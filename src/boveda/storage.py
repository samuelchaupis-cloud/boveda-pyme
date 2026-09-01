import asyncio
import hashlib
import logging
import os
import uuid
from collections.abc import Callable
from enum import StrEnum
from pathlib import Path
from typing import Any

import aioboto3
from botocore.exceptions import ClientError, EndpointConnectionError
from sqlalchemy import Engine, text
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    wait_random,
)

from boveda.database import Snapshot

log = logging.getLogger(__name__)


def abort_multipart_upload(s3_client, bucket: str, key: str, upload_id: str):
    """Cancela un upload multipart y libera los chunks de S3."""
    try:
        s3_client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
        log.info(f"multipart_abortado bucket={bucket} key={key} upload_id={upload_id}")
    except ClientError as e:
        log.error(f"abort_multipart_fallido error={e} upload_id={upload_id}")


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1, max=120) + wait_random(0, 5),
    retry=retry_if_exception_type(
        (ClientError, EndpointConnectionError, ConnectionError)
    ),
    reraise=True,
)
def upload_part(
    s3_client, bucket: str, key: str, upload_id: str, part_number: int, body: bytes
) -> dict:
    """Sube un part con reintentos exponenciales + jitter."""
    return s3_client.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=part_number, Body=body
    )


def cleanup_in_progress_snapshots(session, s3_client, bucket: str):
    """Al arrancar, limpia snapshots que quedaron en estado RUNNING."""
    stale = session.query(Snapshot).filter(Snapshot.estado == "RUNNING").all()
    for snap in stale:
        log.warning(f"snapshot_huerfano_detectado snapshot_id={snap.id}")
        if snap.multipart_upload_id:
            # We assume the storage key prefix for multipart is known, e.g. snapshots/{snap.id}/data
            storage_key = f"snapshots/{snap.id}/data"
            abort_multipart_upload(
                s3_client, bucket, storage_key, snap.multipart_upload_id
            )
        snap.estado = "FAILED"
        snap.error_detail = "Proceso interrumpido abruptamente (crash/OOM kill previo)"
    session.commit()


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1, max=10) + wait_random(0, 5),
    reraise=True,
)
async def upload_to_s3(s3_client, payload: bytes, bucket: str, key: str):
    await s3_client.put_object(Bucket=bucket, Key=key, Body=payload)


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1, max=10) + wait_random(0, 5),
    reraise=True,
)
async def delete_objects_s3(bucket: str, keys: list[str]):
    session = aioboto3.Session()
    async with session.client("s3", endpoint_url=os.getenv("S3_ENDPOINT")) as s3:
        for i in range(0, len(keys), 1000):
            batch = keys[i : i + 1000]
            objects = [{"Key": k} for k in batch]
            await s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=2, min=1, max=10) + wait_random(0, 5),
    reraise=True,
)
async def download_from_s3(bucket: str, key: str) -> bytes:
    session = aioboto3.Session()
    async with session.client("s3", endpoint_url=os.getenv("S3_ENDPOINT")) as s3:
        response = await s3.get_object(Bucket=bucket, Key=key)
        return await response["Body"].read()


class OutboxChunkState(StrEnum):
    PENDING = "PENDING"
    DRAINING = "DRAINING"
    PROCESSED = "PROCESSED"
    DEAD_LETTER = "DEAD_LETTER"


def init_outbox_schema(engine: Engine) -> None:
    """Inicializa la tabla e índices de la cola Transactional Outbox."""
    ddl = """
    CREATE TABLE IF NOT EXISTS outbox_chunks (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        storage_key TEXT NOT NULL,
        payload_encrypted_path TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'DRAINING', 'PROCESSED', 'DEAD_LETTER')),
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')),
        updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')),
        processed_at TEXT,
        next_retry_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc'))
    );

    CREATE INDEX IF NOT EXISTS idx_outbox_chunks_state_retry 
    ON outbox_chunks(state, next_retry_at);

    CREATE INDEX IF NOT EXISTS idx_outbox_chunks_tenant 
    ON outbox_chunks(tenant_id);
    """
    with engine.connect() as conn:
        conn.execute(text("BEGIN IMMEDIATE"))
        for stmt in ddl.strip().split(";"):
            if stmt.strip():
                conn.execute(text(stmt.strip()))
        conn.commit()


def _write_staged_file(staged_path: Path, payload: bytes) -> None:
    """Escribe síncronamente el payload cifrado con permisos 0600 y fsync."""
    fd = os.open(staged_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    try:
        with open(fd, "wb", closefd=True) as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if staged_path.exists():
            staged_path.unlink(missing_ok=True)
        raise


def _read_staged_file(staged_path: Path) -> bytes:
    """Lee síncronamente el archivo de staging."""
    with open(staged_path, "rb") as f:
        return f.read()


class TransactionalOutbox:
    """Gestor de persistencia temporal Store-and-Forward desacoplado en staging y SQLite."""

    def __init__(self, staging_dir: Path | str, engine: Engine) -> None:
        self.staging_dir = Path(staging_dir)
        self.engine = engine
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        init_outbox_schema(self.engine)

    async def enqueue_chunk(
        self, tenant_id: str, storage_key: str, payload: bytes
    ) -> str:
        """Persiste el payload en disco local con 0600 y registra atómicamente en outbox_chunks."""
        chunk_id = str(uuid.uuid4())
        safe_name = (
            f"{chunk_id}_{hashlib.sha256(storage_key.encode()).hexdigest()[:16]}.enc"
        )
        staged_path = self.staging_dir / safe_name

        # Escribir payload cifrado a disco en hilo separado (no bloqueante para el event loop)
        await asyncio.to_thread(_write_staged_file, staged_path, payload)

        # Registrar en la tabla outbox con BEGIN IMMEDIATE
        try:
            with self.engine.connect() as conn:
                conn.execute(text("BEGIN IMMEDIATE"))
                conn.execute(
                    text("""
                        INSERT INTO outbox_chunks (
                            id, tenant_id, storage_key, payload_encrypted_path, state, attempts, next_retry_at
                        ) VALUES (
                            :id, :tenant_id, :storage_key, :path, 'PENDING', 0, strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                        )
                    """),
                    {
                        "id": chunk_id,
                        "tenant_id": tenant_id,
                        "storage_key": storage_key,
                        "path": str(staged_path.resolve()),
                    },
                )
                conn.commit()
        except Exception:
            if staged_path.exists():
                staged_path.unlink(missing_ok=True)
            raise

        return chunk_id


async def drain_outbox_queue(
    engine: Engine,
    uploader_func: Callable[..., Any],
    max_items: int = 10,
) -> int:
    """Drena chunks pendientes del Outbox con reclamación pesimista y backoff exponencial."""
    with engine.connect() as conn:
        conn.execute(text("BEGIN IMMEDIATE"))
        rows = conn.execute(
            text("""
                SELECT id, tenant_id, storage_key, payload_encrypted_path, attempts
                FROM outbox_chunks
                WHERE state = 'PENDING' AND next_retry_at <= strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                ORDER BY created_at ASC
                LIMIT :limit
            """),
            {"limit": max_items},
        ).fetchall()

        if not rows:
            conn.rollback()
            return 0

        ids = [r[0] for r in rows]
        params = {f"id_{i}": ids[i] for i in range(len(ids))}
        in_clause = ", ".join(f":id_{i}" for i in range(len(ids)))
        conn.execute(
            text(f"""
                UPDATE outbox_chunks 
                SET state = 'DRAINING', updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                WHERE id IN ({in_clause})
            """),
            params,
        )
        conn.commit()

    processed_count = 0
    for chunk_id, tenant_id, storage_key, path_str, attempts in rows:
        staged_path = Path(path_str)
        try:
            if not staged_path.exists():
                raise FileNotFoundError(f"Archivo de staging no encontrado: {path_str}")

            payload = await asyncio.to_thread(_read_staged_file, staged_path)

            await uploader_func(tenant_id, storage_key, payload)

            # Éxito: eliminar archivo y marcar PROCESSED
            if staged_path.exists():
                staged_path.unlink(missing_ok=True)

            with engine.connect() as conn:
                conn.execute(text("BEGIN IMMEDIATE"))
                conn.execute(
                    text("""
                        UPDATE outbox_chunks 
                        SET state = 'PROCESSED', processed_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc'), updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                        WHERE id = :id
                    """),
                    {"id": chunk_id},
                )
                conn.commit()
            processed_count += 1
        except Exception as exc:
            new_attempts = attempts + 1
            new_state = (
                OutboxChunkState.DEAD_LETTER
                if new_attempts >= 10
                else OutboxChunkState.PENDING
            )
            backoff_sec = min(3600, 2**new_attempts)

            with engine.connect() as conn:
                conn.execute(text("BEGIN IMMEDIATE"))
                conn.execute(
                    text("""
                        UPDATE outbox_chunks 
                        SET state = :state, attempts = :attempts, last_error = :err,
                            next_retry_at = datetime('now', :backoff),
                            updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                        WHERE id = :id
                    """),
                    {
                        "state": new_state,
                        "attempts": new_attempts,
                        "err": str(exc),
                        "backoff": f"+{backoff_sec} seconds",
                        "id": chunk_id,
                    },
                )
                conn.commit()

    return processed_count
