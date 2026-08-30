import os
from datetime import UTC, datetime, timedelta

import pytest

from boveda.database import Bloque, Snapshot, init_db
from boveda.retention import (
    classify_snapshots,
    purge_expired_snapshots,
)


@pytest.fixture
def db_session():
    db_path = "test_retention.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()
    if os.path.exists(db_path):
        os.remove(db_path)


def test_gfs_classification():
    now = datetime(2023, 12, 31, 12, 0, 0, tzinfo=UTC)
    snapshots = []

    # Generar 1 snapshot por día durante los últimos 40 días
    for i in range(40):
        ts = now - timedelta(days=i)
        snapshots.append(Snapshot(id=f"snap-{i}", timestamp=ts, estado="COMPLETED"))

    expired = classify_snapshots(snapshots, now)

    # 7 daily (0-6)
    # 4 weekly -> Last of week (isocalendar logic)
    # Monthly -> First of month
    # We should have some expired snapshots
    assert len(expired) > 0
    assert len(expired) < 40

    # Comprobar que los más recientes nunca están expirados
    expired_ids = {s.id for s in expired}
    for i in range(7):
        assert f"snap-{i}" not in expired_ids


def test_purge_order_s3_first(db_session):
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
    bloque = Bloque(
        snapshot_id="snap-purge",
        chunk_seq=0,
        hash_sha256="abc",
        size_compressed=10,
        size_encrypted=20,
        storage_key="key-1",
    )
    db_session.add(bloque)
    db_session.commit()

    s3_store = {"key-1": b"data"}

    def del_cb(keys):
        for key in keys:
            s3_store.pop(key, None)

    purge_expired_snapshots(db_session, del_cb)

    # Verificamos
    assert len(s3_store) == 0
    assert db_session.query(Snapshot).count() == 0
    assert db_session.query(Bloque).count() == 0


def test_purge_failure_rollback(db_session):
    snap = Snapshot(
        id="snap-fail",
        tipo="DIARIO",
        source_type="test",
        source_identifier="test",
        encrypted_dek=b"",
        dek_nonce=b"",
        dek_tag=b"",
        estado="EXPIRED",
    )
    db_session.add(snap)
    bloque = Bloque(
        snapshot_id="snap-fail",
        chunk_seq=0,
        hash_sha256="abc",
        size_compressed=10,
        size_encrypted=20,
        storage_key="key-fail",
    )
    db_session.add(bloque)
    db_session.commit()

    s3_store = {"key-fail": b"data"}

    def del_cb(keys):
        # We pretend to delete but we actually fail to delete it
        raise ValueError("S3 deletion failed")

    purge_expired_snapshots(db_session, del_cb)

    # Debe hacer rollback de SQLite y marcar como PURGE_FAILED
    assert len(s3_store) == 1
    snap_db = db_session.query(Snapshot).get("snap-fail")
    assert snap_db.estado == "PURGE_FAILED"
    assert "S3 deletion failed" in snap_db.error_detail
    assert db_session.query(Bloque).count() == 1
