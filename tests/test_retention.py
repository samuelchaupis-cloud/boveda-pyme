from datetime import UTC, datetime, timedelta

import pytest

from boveda.database import ChunkPool, Snapshot, SnapshotChunk, init_db
from boveda.retention import (
    classify_snapshots,
    execute_two_phase_purge,
    purge_expired_snapshots,
)


@pytest.fixture
def db_session(tmp_path):
    db_path = str(tmp_path / "test_retention.db")
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()


def test_gfs_classification():
    now = datetime(2023, 12, 31, 12, 0, 0, tzinfo=UTC)
    snapshots = []

    # Generar 1 snapshot por día durante los últimos 40 días
    for i in range(40):
        ts = now - timedelta(days=i)
        snapshots.append(Snapshot(id=f"snap-{i}", timestamp=ts, estado="COMPLETED"))

    expired = classify_snapshots(snapshots, now)

    # Invariante GFS: 7 diarios + 4 semanales + 1 mensual previo = 12 preservados; 40 - 12 = 28 expirados
    assert len(expired) == 28
    assert len(snapshots) - len(expired) == 12

    # Comprobar que los 7 más recientes nunca están expirados

    expired_ids = {s.id for s in expired}
    for i in range(7):
        assert f"snap-{i}" not in expired_ids


def test_purge_order_s3_single_snapshot(db_session):
    chunk = ChunkPool(
        hash_sha256="c" * 64,
        storage_key="chunks/single.bin",
        size_compressed=10,
        size_encrypted=20,
        ref_count=0,
        state="ACTIVE",
    )
    db_session.add(chunk)
    db_session.commit()

    snap = Snapshot(
        id="snap-purge",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="EXPIRED",
    )
    db_session.add(snap)
    db_session.commit()

    sc = SnapshotChunk(
        snapshot_id=snap.id,
        chunk_seq=0,
        chunk_hash=chunk.hash_sha256,
    )
    db_session.add(sc)
    db_session.commit()

    s3_store = {"chunks/single.bin": b"data"}

    def del_cb(keys):
        for key in keys:
            s3_store.pop(key, None)

    purge_expired_snapshots(db_session, del_cb)

    assert len(s3_store) == 0
    assert db_session.query(Snapshot).count() == 0
    assert db_session.query(SnapshotChunk).count() == 0
    assert db_session.query(ChunkPool).count() == 0


def test_shared_chunk_retention_and_no_dangling_pointer(db_session):
    """Verifica que purgar un snapshot NO elimine de S3 chunks compartidos con snapshots activos."""
    shared_chunk = ChunkPool(
        hash_sha256="s" * 64,
        storage_key="chunks/shared.bin",
        size_compressed=10,
        size_encrypted=20,
        ref_count=0,
        state="ACTIVE",
    )
    db_session.add(shared_chunk)
    db_session.commit()

    # Snapshot 1 (Expirado) y Snapshot 2 (Activo / Completed)
    snap1 = Snapshot(
        id="snap-expired-1",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="EXPIRED",
    )
    snap2 = Snapshot(
        id="snap-active-2",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="COMPLETED",
    )
    db_session.add_all([snap1, snap2])
    db_session.commit()

    sc1 = SnapshotChunk(
        snapshot_id=snap1.id, chunk_seq=0, chunk_hash=shared_chunk.hash_sha256
    )
    sc2 = SnapshotChunk(
        snapshot_id=snap2.id, chunk_seq=0, chunk_hash=shared_chunk.hash_sha256
    )
    db_session.add_all([sc1, sc2])
    db_session.commit()

    db_session.refresh(shared_chunk)
    assert shared_chunk.ref_count == 2

    s3_store = {"chunks/shared.bin": b"valuable_shared_data"}

    def del_cb(keys):
        for key in keys:
            s3_store.pop(key, None)

    # Purgar el snapshot expirado
    purge_expired_snapshots(db_session, del_cb)

    # El chunk de S3 NO debe haberse borrado
    assert "chunks/shared.bin" in s3_store
    db_session.refresh(shared_chunk)
    assert shared_chunk.ref_count == 1
    assert shared_chunk.state == "ACTIVE"
    assert db_session.get(Snapshot, "snap-expired-1") is None
    assert db_session.get(Snapshot, "snap-active-2") is not None

    # Ahora expirar el segundo snapshot y purgar
    snap2 = db_session.get(Snapshot, "snap-active-2")
    snap2.estado = "EXPIRED"
    db_session.commit()

    purge_expired_snapshots(db_session, del_cb)

    # Ahora sí debe haberse borrado de S3 y SQLite
    assert "chunks/shared.bin" not in s3_store
    assert db_session.query(ChunkPool).count() == 0


def test_two_phase_purge_s3_error_reversion(db_session):
    chunk = ChunkPool(
        hash_sha256="e" * 64,
        storage_key="chunks/err.bin",
        size_compressed=10,
        size_encrypted=20,
        ref_count=0,
        state="PENDING_DELETE",
    )
    db_session.add(chunk)
    db_session.commit()

    def fail_cb(keys):
        raise ConnectionError("Network down to S3")

    purged = execute_two_phase_purge(db_session, fail_cb)
    assert purged == 0

    db_session.refresh(chunk)
    assert chunk.state == "PENDING_DELETE"

    # Al reintentar con éxito, debe purgar el chunk pendiente
    assert execute_two_phase_purge(db_session, lambda k: None) == 1

    # Ya no quedan huérfanos
    assert execute_two_phase_purge(db_session, lambda k: None) == 0
