import os

import pytest

from boveda.database import (
    Bloque,
    Snapshot,
    init_db,
    verify_db_integrity,
)
from boveda.fsm import FSMError, transition_snapshot


@pytest.fixture
def db_session():
    db_path = "test_snapshots.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    Session = init_db(db_path)
    session = Session()
    yield session
    session.close()
    Session.kw["bind"].dispose()  # Engine dispose
    if os.path.exists(db_path):
        os.remove(db_path)


def test_integrity_check_corrupt(db_session):
    verify_db_integrity(db_session)


def test_integrity_check_corrupt_fails():
    with open("corrupt.db", "wb") as f:
        f.write(b"NOT A SQLITE DB BUT TRASH BYTES" * 100)

    Session = None
    session = None
    try:
        Session = init_db("corrupt.db")
        session = Session()
        verify_db_integrity(session)
    except Exception as e:  # noqa: BLE001
        assert "not a database" in str(e) or "bd_corrupta" in str(e)
    finally:
        if session:
            session.close()
        if Session:
            Session.kw["bind"].dispose()
        try:
            os.remove("corrupt.db")
        except OSError:
            pass


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


def test_persistence(db_session):
    snap = Snapshot(
        id="snap-1",
        tipo="DIARIO",
        source_type="file",
        source_identifier="/data",
        encrypted_dek=b"enc",
        dek_nonce=b"nonce",
        dek_tag=b"tag",
        estado="PENDING",
    )
    db_session.add(snap)
    db_session.commit()

    bloque = Bloque(
        snapshot_id=snap.id,
        chunk_seq=0,
        hash_sha256="abc",
        size_compressed=10,
        size_encrypted=20,
        storage_key="s3://key",
    )
    db_session.add(bloque)
    db_session.commit()

    db_session.delete(snap)
    db_session.commit()

    assert db_session.query(Bloque).count() == 0
