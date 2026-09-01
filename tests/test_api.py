import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from boveda.api import SERVER_PRIVATE_KEY, app
from boveda.auth import TokenClaims, UserRole, create_access_token
from boveda.database import (
    ChunkPool,
    Snapshot,
    SnapshotChunk,
    get_tenant_session_factory,
)


@pytest.fixture
def client_and_auth(tmp_path, monkeypatch):
    base_dir = str(tmp_path / "tenants")

    def mock_get_tenant_factory(tenant_id: str, base_dir_arg: str = base_dir):
        return get_tenant_session_factory(tenant_id, base_dir=base_dir)

    monkeypatch.setattr(
        "boveda.api.get_tenant_session_factory", mock_get_tenant_factory
    )

    # Inicializar datos para tenant_pyme_1
    factory = mock_get_tenant_factory("tenant_pyme_1")
    with factory() as session:
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

    now = int(time.time())
    claims_admin = TokenClaims(
        sub="usr_admin",
        tenant_id="tenant_pyme_1",
        role=UserRole.TENANT_ADMIN,
        exp=now + 3600,
        iat=now,
        jti="jti_admin",
    )
    token_admin = create_access_token(claims_admin, SERVER_PRIVATE_KEY)

    return TestClient(app), token_admin


def test_api_endpoints(client_and_auth):
    client, token = client_and_auth

    # 1. Endpoint público raíz
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Bóveda PyME API en línea"}

    # 2. /api/snapshots sin auth -> 401
    resp_unauth = client.get("/api/snapshots")
    assert resp_unauth.status_code == 401

    # 3. /api/snapshots con auth -> 200
    response = client.get(
        "/api/snapshots", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == "snap-api-1"
    assert data[0]["estado"] == "COMPLETED"

    # 4. /api/stats con auth -> 200
    response = client.get("/api/stats", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    stats = response.json()
    assert stats["total_snapshots_completed"] == 1
    assert stats["total_deduplicated_blocks"] == 1
    assert stats["tenant_id"] == "tenant_pyme_1"


def test_prometheus_metrics_endpoint(client_and_auth):
    client, token = client_and_auth
    response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    text_content = response.text
    assert "boveda_process_resident_memory_bytes" in text_content
    assert (
        'boveda_snapshots_total{status="completed",tenant="tenant_pyme_1"} 1'
        in text_content
    )
    assert 'boveda_chunks_unique_total{tenant="tenant_pyme_1"} 1' in text_content
    assert 'boveda_deduplication_ratio{tenant="tenant_pyme_1"} 1.00' in text_content
    assert 'boveda_circuit_breaker_state{cloud="s3"} 0' in text_content
    assert "boveda_fastcdc_enabled 1" in text_content


def test_auth_and_rbac_endpoints(client_and_auth):
    client, _ = client_and_auth
    import time

    from boveda.api import SERVER_PRIVATE_KEY
    from boveda.auth import TokenClaims, UserRole, create_access_token

    # 1. /auth/ws-ticket sin credenciales -> 401
    resp_unauth = client.post("/auth/ws-ticket")
    assert resp_unauth.status_code == 401

    # 2. Generar tokens con roles
    now = int(time.time())
    claims_admin = TokenClaims(
        sub="usr_admin",
        tenant_id="tenant_pyme_1",
        role=UserRole.TENANT_ADMIN,
        exp=now + 3600,
        iat=now,
        jti="jti_admin",
    )
    token_admin = create_access_token(claims_admin, SERVER_PRIVATE_KEY)

    claims_auditor = TokenClaims(
        sub="usr_auditor",
        tenant_id="tenant_pyme_1",
        role=UserRole.AUDITOR,
        exp=now + 3600,
        iat=now,
        jti="jti_auditor",
    )
    token_auditor = create_access_token(claims_auditor, SERVER_PRIVATE_KEY)

    # 3. Solicitar ticket de WebSocket/SSE con token de admin
    resp_ticket = client.post(
        "/auth/ws-ticket", headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert resp_ticket.status_code == 200
    ticket = resp_ticket.json()["ticket"]
    assert len(ticket) > 20

    # 4. Consumir SSE con ticket válido
    resp_sse = client.get(f"/api/events/sse?ticket={ticket}")
    assert resp_sse.status_code == 200
    assert "text/event-stream" in resp_sse.headers["content-type"]
    assert "connected" in resp_sse.text

    # 5. Reusar ticket consumido -> debe fallar con 401
    resp_sse_reuse = client.get(f"/api/events/sse?ticket={ticket}")
    assert resp_sse_reuse.status_code == 401

    # 6. Probar RBAC en /api/backup:
    # Auditor -> 403 Forbidden
    resp_backup_denied = client.post(
        "/api/backup", headers={"Authorization": f"Bearer {token_auditor}"}
    )
    assert resp_backup_denied.status_code == 403

    # Admin -> 200 OK
    resp_backup_ok = client.post(
        "/api/backup", headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert resp_backup_ok.status_code == 200
    assert resp_backup_ok.json()["status"] == "initiated"
