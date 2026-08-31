"""Módulo de conectores de bases de datos y streaming robusto con drenaje de stderr."""

import asyncio
import contextlib
import logging
import os
import signal
import tempfile
from collections import deque
from collections.abc import AsyncGenerator
from pathlib import Path

log = logging.getLogger(__name__)

STDERR_RING_BUFFER_MAX_CHUNKS = 16
STDERR_CHUNK_SIZE = 4096  # 16 * 4KB = 64 KB max
DEFAULT_STARTUP_TIMEOUT = 30.0
DEFAULT_INACTIVITY_TIMEOUT = 60.0


class DatabaseConnectorError(Exception):
    """Error fatal en la ejecución o streaming del conector de base de datos."""


class StreamingTimeoutError(DatabaseConnectorError):
    """Expiración de timeout por inactividad o arranque en el stream de datos."""


async def drain_stderr_nonblocking(
    stream: asyncio.StreamReader, ring_buffer: deque[bytes]
) -> None:
    """Drena continuamente stderr para prevenir el bloqueo del buffer de tubería del SO."""
    try:
        while True:
            chunk = await stream.read(STDERR_CHUNK_SIZE)
            if not chunk:
                break
            ring_buffer.append(chunk)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        log.debug("error_drenando_stderr", extra={"error": str(exc)})


def build_postgres_dump_command(
    db_name: str,
    host: str = "localhost",
    port: int = 5432,
    user: str = "postgres",
    password: str | None = None,
    custom_flags: list[str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Construye el comando pg_dump con variables de entorno seguras."""
    env = {
        "PGHOST": host,
        "PGPORT": str(port),
        "PGUSER": user,
    }
    if password:
        env["PGPASSWORD"] = password

    cmd = [
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--dbname",
        db_name,
    ]
    if custom_flags:
        cmd.extend(custom_flags)

    return cmd, env


def build_mysql_dump_command(
    db_name: str,
    host: str = "localhost",
    port: int = 3306,
    user: str = "root",
    password: str | None = None,
    custom_flags: list[str] | None = None,
) -> tuple[list[str], dict[str, str], Path | None]:
    """Construye el comando mysqldump utilizando defaults-extra-file seguro para credenciales."""
    cnf_path: Path | None = None
    cmd = [
        "mysqldump",
        "--single-transaction",
        "--quick",
        "--skip-lock-tables",
        "--routines",
        "--triggers",
        "--events",
    ]

    if password is not None:
        fd, temp_file = tempfile.mkstemp(prefix="boveda_my_", suffix=".cnf")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(
                f"[client]\nhost={host}\nport={port}\nuser={user}\npassword={password}\n"
            )
        cnf_path = Path(temp_file)
        try:
            cnf_path.chmod(0o600)
        except OSError:
            pass
        cmd.insert(1, f"--defaults-extra-file={cnf_path}")
    else:
        cmd.extend(["-h", host, "-P", str(port), "-u", user])

    if custom_flags:
        cmd.extend(custom_flags)

    cmd.append(db_name)
    return cmd, {}, cnf_path


def build_sqlite_backup_command(db_path: str) -> list[str]:
    """Construye el comando de volcado consistente para SQLite."""
    return ["sqlite3", db_path, ".dump"]


async def stream_subprocess_with_watchdog(
    cmd: list[str],
    env: dict[str, str] | None = None,
    chunk_size: int = 8 * 1024 * 1024,
    startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
    inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
    shutdown_event: asyncio.Event | None = None,
) -> AsyncGenerator[bytes, None]:
    """Ejecuta un subproceso en streaming con drenaje continuo de stderr y control por timeout."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    stderr_buffer: deque[bytes] = deque(maxlen=STDERR_RING_BUFFER_MAX_CHUNKS)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=merged_env,
    )

    if proc.stdout is None or proc.stderr is None:
        raise DatabaseConnectorError("Fallo al inicializar descriptores de tubería")

    drain_task = asyncio.create_task(
        drain_stderr_nonblocking(proc.stderr, stderr_buffer)
    )

    accumulated = bytearray()
    first_chunk_received = False

    try:
        while True:
            if shutdown_event and shutdown_event.is_set():
                break

            current_timeout = (
                startup_timeout if not first_chunk_received else inactivity_timeout
            )

            try:
                read_coro = proc.stdout.read(chunk_size - len(accumulated))
                chunk = await asyncio.wait_for(read_coro, timeout=current_timeout)
            except TimeoutError as exc:
                raise StreamingTimeoutError(
                    f"Timeout de streaming alcanzado ({current_timeout}s) sin recibir datos"
                ) from exc

            if not chunk:
                break

            first_chunk_received = True
            accumulated.extend(chunk)

            if len(accumulated) >= chunk_size:
                yield bytes(accumulated[:chunk_size])
                accumulated = accumulated[chunk_size:]

        if accumulated:
            yield bytes(accumulated)

        await proc.wait()

        if proc.returncode != 0 and not (shutdown_event and shutdown_event.is_set()):
            raw_err = b"".join(stderr_buffer).decode(errors="replace")
            is_sigpipe = (
                proc.returncode == -signal.SIGPIPE
                if hasattr(signal, "SIGPIPE")
                else proc.returncode in (109, 141)
            )

            if not is_sigpipe:
                raise DatabaseConnectorError(
                    f"Subproceso finalizó con error {proc.returncode}: {raw_err[-1000:]}"
                )

    except Exception:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
        raise

    finally:
        drain_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await drain_task
