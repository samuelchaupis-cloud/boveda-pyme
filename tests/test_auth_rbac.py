import time

import pytest

from boveda.auth import (
    InvalidTicketError,
    TicketStore,
    TokenAuthError,
    TokenClaims,
    UserRole,
    create_access_token,
    generate_ed25519_keypair,
    verify_access_token,
)


def test_ed25519_jwt_create_and_verify():
    priv_key, pub_key = generate_ed25519_keypair()

    now = int(time.time())
    claims = TokenClaims(
        sub="usr_12345",
        tenant_id="tenant_alpha",
        role=UserRole.TENANT_ADMIN,
        exp=now + 3600,
        iat=now,
        jti="jti_unique_001",
    )

    token = create_access_token(claims, priv_key)
    assert isinstance(token, str)
    assert token.count(".") == 2

    # Verificar token con clave pública
    verified_claims = verify_access_token(token, pub_key)
    assert verified_claims.sub == "usr_12345"
    assert verified_claims.tenant_id == "tenant_alpha"
    assert verified_claims.role == UserRole.TENANT_ADMIN


def test_ed25519_jwt_tampered_signature_fails():
    priv_key, pub_key = generate_ed25519_keypair()
    _other_priv, other_pub = generate_ed25519_keypair()

    now = int(time.time())
    claims = TokenClaims(
        sub="usr_12345",
        tenant_id="tenant_alpha",
        role=UserRole.OPERATOR,
        exp=now + 3600,
        iat=now,
        jti="jti_002",
    )

    token = create_access_token(claims, priv_key)

    # 1. Fallo al verificar con otra clave pública
    with pytest.raises(TokenAuthError, match="Firma de token inválida"):
        verify_access_token(token, other_pub)

    # 2. Fallo si el payload fue alterado
    parts = token.split(".")
    # Mutar 1 byte del payload base64url
    tampered_payload = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

    with pytest.raises(TokenAuthError):
        verify_access_token(tampered_token, pub_key)


def test_ed25519_jwt_expired_token_fails():
    priv_key, pub_key = generate_ed25519_keypair()

    now = int(time.time())
    claims = TokenClaims(
        sub="usr_expired",
        tenant_id="tenant_alpha",
        role=UserRole.AUDITOR,
        exp=now - 10,  # Expirado hace 10 segundos
        iat=now - 60,
        jti="jti_003",
    )

    token = create_access_token(claims, priv_key)

    with pytest.raises(TokenAuthError, match="Token expirado"):
        verify_access_token(token, pub_key)


def test_ephemeral_ticket_store_lifecycle():
    store = TicketStore()

    claims = TokenClaims(
        sub="usr_stream",
        tenant_id="tenant_beta",
        role=UserRole.OPERATOR,
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        jti="jti_004",
    )

    ticket = store.create_ticket(claims, ttl_seconds=1.0)
    assert isinstance(ticket, str)

    # Canje exitoso de un solo uso
    consumed = store.consume_ticket(ticket)
    assert consumed.sub == "usr_stream"
    assert consumed.tenant_id == "tenant_beta"

    # Segundo intento debe fallar (consumo atómico destructivo)
    with pytest.raises(InvalidTicketError, match="Ticket inexistente o ya consumido"):
        store.consume_ticket(ticket)


def test_ephemeral_ticket_store_expiration():
    store = TicketStore()
    claims = TokenClaims(
        sub="usr_stream_exp",
        tenant_id="tenant_beta",
        role=UserRole.AUDITOR,
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        jti="jti_005",
    )

    ticket = store.create_ticket(claims, ttl_seconds=0.05)
    time.sleep(0.08)

    with pytest.raises(InvalidTicketError, match="Ticket expirado"):
        store.consume_ticket(ticket)
