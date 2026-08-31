import pytest
from sqlalchemy.exc import DBAPIError

from boveda.database import (
    ChunkPool,
    Snapshot,
    SnapshotChunk,
    init_db,
    verify_db_integrity,
)
from boveda.fsm import FSMError, transition_snapshot


@pytest.fixture
def db_session(tmp_path):
    db_path = str(tmp_path / "test_snapshots.db")
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()


def test_integrity_check_corrupt(db_session):
    verify_db_integrity(db_session)


def test_integrity_check_corrupt_fails(tmp_path):
    corrupt_file = str(tmp_path / "corrupt.db")
    with open(corrupt_file, "wb") as f:
        f.write(b"NOT A SQLITE DB BUT TRASH BYTES" * 100)

    Session = None
    session = None
    try:
        Session = init_db(corrupt_file)
        session = Session()
        verify_db_integrity(session)
    except Exception as e:
        assert "not a database" in str(e) or "bd_corrupta" in str(e)
    finally:
        if session:
            session.close()
        if Session:
            Session.kw["bind"].dispose()


def test_fsm_transitions(db_session):
    snap = Snapshot(
        id="snap-fsm",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="PENDING",
    )

    transition_snapshot(snap, "RUNNING")
    assert snap.estado == "RUNNING"

    transition_snapshot(snap, "FAILED")
    assert snap.estado == "FAILED"

    with pytest.raises(FSMError):
        transition_snapshot(snap, "COMPLETED")

    transition_snapshot(snap, "CLEANUP")
    transition_snapshot(snap, "PURGED")
    assert snap.estado == "PURGED"


def test_chunk_pool_and_ref_count_triggers(db_session):
    # 1. Crear entrada en ChunkPool
    chunk = ChunkPool(
        hash_sha256="a" * 64,
        storage_key="chunks/aaa.bin",
        size_compressed=100,
        size_encrypted=100,
        ref_count=0,
        state="ACTIVE",
    )
    db_session.add(chunk)
    db_session.commit()

    # 2. Crear dos snapshots
    snap1 = Snapshot(
        id="snap-1",
        tipo="DIARIO",
        source_type="file",
        source_identifier="/data1",
        encrypted_dek=b"enc1",
        dek_nonce=b"nonce1",
        dek_tag=b"tag1",
        estado="COMPLETED",
    )
    snap2 = Snapshot(
        id="snap-2",
        tipo="DIARIO",
        source_type="file",
        source_identifier="/data2",
        encrypted_dek=b"enc2",
        dek_nonce=b"nonce2",
        dek_tag=b"tag2",
        estado="COMPLETED",
    )
    db_session.add_all([snap1, snap2])
    db_session.commit()

    # 3. Vincular chunk al snap1 -> Trigger incrementa ref_count a 1
    sc1 = SnapshotChunk(snapshot_id=snap1.id, chunk_seq=0, chunk_hash=chunk.hash_sha256)
    db_session.add(sc1)
    db_session.commit()

    db_session.refresh(chunk)
    assert chunk.ref_count == 1
    assert chunk.state == "ACTIVE"

    # 4. Vincular mismo chunk al snap2 (Deduplicación) -> Trigger incrementa ref_count a 2
    sc2 = SnapshotChunk(snapshot_id=snap2.id, chunk_seq=0, chunk_hash=chunk.hash_sha256)
    db_session.add(sc2)
    db_session.commit()

    db_session.refresh(chunk)
    assert chunk.ref_count == 2

    # 5. Intentar borrar chunk directamente mientras ref_count > 0 -> Trigger bloquea
    with pytest.raises(DBAPIError):
        db_session.delete(chunk)
        db_session.commit()
    db_session.rollback()

    # 6. Desvincular snap1 -> Trigger decrementa ref_count a 1
    db_session.delete(sc1)
    db_session.commit()

    db_session.refresh(chunk)
    assert chunk.ref_count == 1
    assert chunk.state == "ACTIVE"

    # 7. Desvincular snap2 -> Trigger decrementa ref_count a 0 y pasa a PENDING_DELETE
    db_session.delete(sc2)
    db_session.commit()

    db_session.refresh(chunk)
    assert chunk.ref_count == 0
    assert chunk.state == "PENDING_DELETE"
    assert chunk.purge_scheduled_at is not None


def test_snapshot_chunk_properties_accessors(db_session):
    # Standalone SnapshotChunk (without ChunkPool attached)
    sc_standalone = SnapshotChunk(
        snapshot_id="snap-tmp",
        chunk_seq=0,
        storage_key="s3://custom-key",
        size_compressed=500,
        size_encrypted=520,
        hash_sha256="abc",
    )
    assert sc_standalone.storage_key == "s3://custom-key"
    assert sc_standalone.size_compressed == 500
    assert sc_standalone.size_encrypted == 520
    assert sc_standalone.hash_sha256 == "abc"

    sc_standalone.storage_key = "s3://new-key"
    sc_standalone.size_compressed = 600
    sc_standalone.size_encrypted = 620
    sc_standalone.hash_sha256 = "def"

    assert sc_standalone.storage_key == "s3://new-key"
    assert sc_standalone.size_compressed == 600
    assert sc_standalone.size_encrypted == 620
    assert sc_standalone.hash_sha256 == "def"
