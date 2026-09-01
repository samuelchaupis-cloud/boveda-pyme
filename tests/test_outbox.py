import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from boveda.storage import (
    OutboxChunkState,
    TransactionalOutbox,
    drain_outbox_queue,
    init_outbox_schema,
)


@pytest.fixture
def outbox_db(tmp_path):
    db_file = tmp_path / "test_outbox.db"
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)

    engine = create_engine(f"sqlite:///{db_file}")
    init_outbox_schema(engine)
    session_factory = sessionmaker(bind=engine)
    return engine, session_factory, staging_dir


@pytest.mark.asyncio
async def test_outbox_enqueue_and_drain_success(outbox_db):
    engine, _session_factory, staging_dir = outbox_db

    outbox = TransactionalOutbox(staging_dir=staging_dir, engine=engine)

    tenant_id = "tenant_test_1"
    storage_key = "chunks/chunk_001.bin"
    payload = b"ENC_PAYLOAD_BYTES_001"

    # 1. Encolar chunk en Outbox
    chunk_id = await outbox.enqueue_chunk(tenant_id, storage_key, payload)
    assert chunk_id is not None

    # Verificar que el archivo se guardó en staging
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT payload_encrypted_path, state, attempts FROM outbox_chunks WHERE id = :id"
            ),
            {"id": chunk_id},
        ).fetchone()
        assert row is not None
        staged_path_str = row[0]
        assert row[1] == OutboxChunkState.PENDING
        assert row[2] == 0
        assert os.path.exists(staged_path_str)

        content = await asyncio.to_thread(lambda: Path(staged_path_str).read_bytes())
        assert content == payload

    # 2. Drenar con uploader exitoso
    mock_uploader = AsyncMock(return_value="s3-ok")
    processed_count = await drain_outbox_queue(engine, mock_uploader)

    assert processed_count == 1
    mock_uploader.assert_called_once_with(tenant_id, storage_key, payload)

    # Verificar que el archivo en staging fue borrado y estado es PROCESSED
    assert not os.path.exists(staged_path_str)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT state, processed_at FROM outbox_chunks WHERE id = :id"),
            {"id": chunk_id},
        ).fetchone()
        assert row[0] == OutboxChunkState.PROCESSED
        assert row[1] is not None


@pytest.mark.asyncio
async def test_outbox_drain_failure_and_dead_letter(outbox_db):
    engine, _session_factory, staging_dir = outbox_db
    outbox = TransactionalOutbox(staging_dir=staging_dir, engine=engine)

    tenant_id = "tenant_test_2"
    storage_key = "chunks/chunk_002.bin"
    payload = b"ENC_PAYLOAD_FAIL"

    chunk_id = await outbox.enqueue_chunk(tenant_id, storage_key, payload)

    # 1. Simular fallo en uploader
    mock_uploader = AsyncMock(side_effect=ConnectionError("Persistent Cloud Error"))
    processed = await drain_outbox_queue(engine, mock_uploader)
    assert processed == 0

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT state, attempts, last_error FROM outbox_chunks WHERE id = :id"
            ),
            {"id": chunk_id},
        ).fetchone()
        assert row[0] == OutboxChunkState.PENDING
        assert row[1] == 1
        assert "Persistent Cloud Error" in row[2]

        # Forzar 9 intentos previos y next_retry_at en el pasado para reintentar de inmediato
        conn.execute(
            text(
                "UPDATE outbox_chunks SET attempts = 9, next_retry_at = datetime('now', '-1 minute') WHERE id = :id"
            ),
            {"id": chunk_id},
        )
        conn.commit()

    # Drenar de nuevo (décimo intento) -> debe pasar a DEAD_LETTER
    await drain_outbox_queue(engine, mock_uploader)

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT state, attempts FROM outbox_chunks WHERE id = :id"),
            {"id": chunk_id},
        ).fetchone()
        assert row[0] == OutboxChunkState.DEAD_LETTER
        assert row[1] == 10
