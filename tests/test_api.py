from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from boveda.api import app
from boveda.database import Snapshot, init_db


@pytest.fixture
def client_with_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_api.db")
    Session = init_db(db_path)

    monkeypatch.setattr("boveda.api.Session", Session)

    with Session() as session:
        from boveda.database import ChunkPool, SnapshotChunk

        cp = ChunkPool(
            hash_sha256="hash123",
            storage_key="k1",
            size_compressed=100,
            size_encrypted=100,
            ref_count=0,
            state="ACTIVE",
        )
        session.add(cp)
        session.commit()

        s1 = Snapshot(
            id="snap-api-1",
            estado="COMPLETED",
            tipo="DIARIO",
            source_type="cmd",
            source_identifier="db-prod",
            encrypted_dek=b"enc",
            dek_nonce=b"nonce",
            dek_tag=b"tag",
            timestamp=datetime.now(UTC),
        )
        session.add(s1)
        session.commit()

        b1 = SnapshotChunk(
            snapshot_id="snap-api-1",
            chunk_seq=0,
            chunk_hash="hash123",
        )
        session.add(b1)
        session.commit()

    return TestClient(app)


def test_api_endpoints(client_with_db):
    response = client_with_db.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Bóveda PyME API en línea"}

    response = client_with_db.get("/api/snapshots")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == "snap-api-1"
    assert data[0]["estado"] == "COMPLETED"

    response = client_with_db.get("/api/stats")
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_snapshots_completed"] == 1
    assert stats["total_deduplicated_blocks"] == 1
