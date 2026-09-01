"""Módulo de autenticación asimétrica Ed25519 JWT, RBAC multi-tenant y tickets efímeros."""

import base64
import json
import secrets
import threading
import time
from collections import OrderedDict
from enum import StrEnum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import Field

from boveda.schemas import StrictBaseModel


class UserRole(StrEnum):
    TENANT_ADMIN = "TenantAdmin"
    OPERATOR = "Operator"
    AUDITOR = "Auditor"


class TokenAuthError(Exception):
    """Excepción lanzada ante errores de autenticación o verificación de tokens JWT."""


class InvalidTicketError(Exception):
    """Excepción lanzada cuando un ticket efímero es inválido, ha expirado o ya fue consumido."""


class TokenClaims(StrictBaseModel):
    """Claims canónicos de autenticación multi-inquilino en tokens JWT."""

    iss: str = Field(default="boveda-pyme:auth")
    sub: str
    aud: str = Field(default="boveda-pyme:api")
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{3,36}$")
    role: UserRole
    exp: int
    iat: int
    jti: str


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data_str: str) -> bytes:
    padding = 4 - (len(data_str) % 4)
    if padding != 4:
        data_str += "=" * padding
    return base64.urlsafe_b64decode(data_str.encode("ascii"))


def generate_ed25519_keypair() -> tuple[
    ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey
]:
    """Genera un par de claves asimétricas Ed25519 conforme a RFC 8032."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def create_access_token(
    claims: TokenClaims, private_key: ed25519.Ed25519PrivateKey
) -> str:
    """Crea y firma un token JWT asimétrico Ed25519 (EdDSA)."""
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(claims.model_dump(), separators=(",", ":")).encode(
        "utf-8"
    )

    header_b64 = _b64url_encode(header_json)
    payload_b64 = _b64url_encode(payload_json)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    signature = private_key.sign(signing_input)
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_access_token(
    token: str, public_key: ed25519.Ed25519PublicKey
) -> TokenClaims:
    """Verifica la firma asimétrica Ed25519 y la vigencia temporal del token JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenAuthError("Formato de token JWT malformado.")

    header_b64, payload_b64, signature_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    try:
        header_bytes = _b64url_decode(header_b64)
        signature = _b64url_decode(signature_b64)
        payload_bytes = _b64url_decode(payload_b64)
    except Exception as exc:
        raise TokenAuthError("Error al decodificar base64url del token.") from exc

    # 1. Validar encabezado RFC 7519
    try:
        header_dict = json.loads(header_bytes.decode("utf-8"))
        if header_dict.get("alg") != "EdDSA" or header_dict.get("typ") != "JWT":
            raise TokenAuthError("Encabezado JWT inválido o algoritmo no permitido.")
    except Exception as exc:
        if isinstance(exc, TokenAuthError):
            raise
        raise TokenAuthError("Encabezado de token malformado.") from exc

    # 2. Verificar firma criptográfica Ed25519
    try:
        public_key.verify(signature, signing_input)
    except InvalidSignature as exc:
        raise TokenAuthError("Firma de token inválida.") from exc

    # 3. Deserializar claims a Pydantic v2
    try:
        claims = TokenClaims.model_validate_json(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise TokenAuthError("Claims de token inválidos.") from exc

    # 4. Validar expiración y emisor/audiencia
    now = int(time.time())
    if claims.exp < now:
        raise TokenAuthError("Token expirado.")
    if claims.iss != "boveda-pyme:auth":
        raise TokenAuthError(f"Emisor no confiable: {claims.iss}")
    if claims.aud != "boveda-pyme:api":
        raise TokenAuthError(f"Audiencia inválida: {claims.aud}")

    return claims


class TicketStore:
    """Almacén en memoria de tickets efímeros de un solo uso con capacidad acotada y desalojo FIFO."""

    def __init__(self, max_capacity: int = 1000) -> None:
        self.max_capacity = max_capacity
        self._tickets: OrderedDict[str, tuple[TokenClaims, float]] = OrderedDict()
        self._lock = threading.Lock()

    def create_ticket(self, claims: TokenClaims, ttl_seconds: float = 30.0) -> str:
        """Genera un ticket criptográfico efímero de alta entropía (256 bits)."""
        ticket_id = secrets.token_urlsafe(32)
        expires_at = time.monotonic() + ttl_seconds

        with self._lock:
            now = time.monotonic()
            # 1. Purga O(K) rápida de tickets expirados al frente de la cola
            while self._tickets:
                _first_key, (_, exp) = next(iter(self._tickets.items()))
                if exp < now:
                    self._tickets.popitem(last=False)
                else:
                    break

            # 2. Desalojo estricto FIFO si se alcanza la capacidad máxima
            if len(self._tickets) >= self.max_capacity:
                self._tickets.popitem(last=False)

            self._tickets[ticket_id] = (claims, expires_at)

        return ticket_id

    def consume_ticket(self, ticket_id: str) -> TokenClaims:
        """Canjea y elimina atómicamente un ticket efímero de un solo uso."""
        with self._lock:
            entry = self._tickets.pop(ticket_id, None)

        if entry is None:
            raise InvalidTicketError("Ticket inexistente o ya consumido.")

        claims, expires_at = entry
        if time.monotonic() > expires_at:
            raise InvalidTicketError("Ticket expirado.")

        return claims
