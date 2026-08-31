import sys

import pytest

from boveda.connectors import (
    DatabaseConnectorError,
    StreamingTimeoutError,
    build_mysql_dump_command,
    build_postgres_dump_command,
    build_sqlite_backup_command,
    stream_subprocess_with_watchdog,
)


def test_build_postgres_dump_command():
    cmd, env = build_postgres_dump_command(
        db_name="prod_db",
        host="pg.internal",
        port=5433,
        user="backup_user",
        password="secret_password",
        custom_flags=["--exclude-table-data=logs"],
    )
    assert cmd == [
        "pg_dump",
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--dbname",
        "prod_db",
        "--exclude-table-data=logs",
    ]
    assert env["PGHOST"] == "pg.internal"
    assert env["PGPORT"] == "5433"
    assert env["PGUSER"] == "backup_user"
    assert env["PGPASSWORD"] == "secret_password"


def test_build_mysql_dump_command():
    cmd, _env, cnf_path = build_mysql_dump_command(
        db_name="app_db",
        host="mysql.internal",
        port=3307,
        user="my_user",
        password="my_password",
        custom_flags=["--no-data"],
    )
    assert "--single-transaction" in cmd
    assert "--no-data" in cmd
    assert cnf_path is not None
    assert cnf_path.exists()
    with open(cnf_path, encoding="utf-8") as f:
        content = f.read()
    assert "user=my_user" in content
    assert "password=my_password" in content
    assert "host=mysql.internal" in content

    # Cleanup temp cnf
    cnf_path.unlink(missing_ok=True)

    # Without password
    cmd2, _env2, cnf_path2 = build_mysql_dump_command("test_db")
    assert cnf_path2 is None
    assert "-u" in cmd2
    assert "root" in cmd2


def test_build_sqlite_backup_command():
    cmd = build_sqlite_backup_command("/var/data/app.db")
    assert cmd == ["sqlite3", "/var/data/app.db", ".dump"]


@pytest.mark.asyncio
async def test_stream_subprocess_successful():
    python_code = "import sys; sys.stdout.write('X' * (8 * 1024 * 1024 + 100)); sys.stderr.write('Warning 123'); sys.stdout.flush()"
    cmd = [sys.executable, "-c", python_code]

    chunks = []
    async for chunk in stream_subprocess_with_watchdog(cmd, chunk_size=8 * 1024 * 1024):
        chunks.append(chunk)

    assert len(chunks) == 2
    assert len(chunks[0]) == 8 * 1024 * 1024
    assert len(chunks[1]) == 100


@pytest.mark.asyncio
async def test_stream_subprocess_inactivity_timeout():
    # Process sleeps longer than timeout
    python_code = (
        "import time, sys; sys.stdout.write('first'); sys.stdout.flush(); time.sleep(2)"
    )
    cmd = [sys.executable, "-c", python_code]

    with pytest.raises(StreamingTimeoutError, match="Timeout de streaming alcanzado"):
        async for _ in stream_subprocess_with_watchdog(
            cmd, chunk_size=1024, startup_timeout=1.0, inactivity_timeout=0.2
        ):
            pass


@pytest.mark.asyncio
async def test_stream_subprocess_failure_with_stderr_capture():
    python_code = "import sys; sys.stderr.write('FATAL: Table locked'); sys.exit(2)"
    cmd = [sys.executable, "-c", python_code]

    with pytest.raises(DatabaseConnectorError, match="FATAL: Table locked"):
        async for _ in stream_subprocess_with_watchdog(cmd):
            pass
