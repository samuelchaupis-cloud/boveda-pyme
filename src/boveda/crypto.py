import base64
import hashlib
import hmac
import os
import struct

import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
MASTER_KEY_LENGTH = 32


def generate_master_salt() -> str:
    salt = os.urandom(32)
    return base64.b64encode(salt).decode("utf-8")


def derive_kek(passphrase: str, master_salt_b64: str) -> bytes:
    salt = base64.b64decode(master_salt_b64)
    raw_hash = argon2.low_level.hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=MASTER_KEY_LENGTH,
        type=argon2.low_level.Type.ID,
    )
    return raw_hash


def derive_tenant_kek(
    kek: bytes, tenant_id: str, tenant_salt: bytes | None = None
) -> bytes:
    """Deriva una KEK criptográficamente aislada por inquilino usando HKDF-SHA256."""
    info = f"boveda-tenant:{tenant_id}".encode()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=tenant_salt,
        info=info,
    ).derive(kek)


def derive_dedup_keys(
    kek: bytes,
    tenant_id: str | None = None,
    tenant_salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Deriva K_dedup y K_id usando HKDF-SHA256, aplicando aislamiento por inquilino si se especifica."""
    source_key = derive_tenant_kek(kek, tenant_id, tenant_salt) if tenant_id else kek

    k_dedup = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"boveda-dedup-v2-key",
    ).derive(source_key)

    k_id = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"boveda-dedup-v2-id",
    ).derive(source_key)

    return k_dedup, k_id


def compute_content_id(k_id: bytes, data: bytes) -> str:
    """Calcula el identificador criptográfico de almacenamiento (storage_key hash) usando HMAC-SHA256."""
    return hmac.new(k_id, data, hashlib.sha256).hexdigest()


def derive_chunk_key(k_dedup: bytes, data: bytes) -> bytes:
    """Calcula la clave efímera de bloque (Content-Derived DEK) usando HMAC-SHA256."""
    return hmac.new(k_dedup, data, hashlib.sha256).digest()


def compute_synthetic_nonce(chunk_key: bytes, aad: bytes, data: bytes) -> bytes:
    """Calcula el Synthetic Nonce de 96 bits (12 bytes) para SIV determinista seguro."""
    h = hmac.new(chunk_key, aad + data, hashlib.sha256).digest()
    return h[:12]


def generate_dek_for_snapshot(
    kek: bytes, snapshot_id: str
) -> tuple[bytes, bytes, bytes, bytes]:
    """Genera DEK y lo envuelve con KEK.
    Retorna (dek_raw, encrypted_dek, dek_nonce, dek_tag)
    """
    dek_raw = os.urandom(32)
    dek_nonce = os.urandom(12)
    aesgcm = AESGCM(kek)

    # AAD includes snapshot.id
    aad = snapshot_id.encode("utf-8")
    ciphertext = aesgcm.encrypt(dek_nonce, dek_raw, aad)

    # AESGCM appends the 16-byte tag to the ciphertext
    encrypted_dek = ciphertext[:-16]
    dek_tag = ciphertext[-16:]

    return dek_raw, encrypted_dek, dek_nonce, dek_tag


def unwrap_dek(
    kek: bytes, encrypted_dek: bytes, dek_nonce: bytes, dek_tag: bytes, snapshot_id: str
) -> bytes:
    aesgcm = AESGCM(kek)
    aad = snapshot_id.encode("utf-8")
    ciphertext = encrypted_dek + dek_tag
    dek_raw = aesgcm.decrypt(dek_nonce, ciphertext, aad)
    return dek_raw


class NonceGenerator:
    """Generador de nonces counter-based con prefijo de sesión único."""

    def __init__(self):
        self._prefix = os.urandom(4)
        self._counter = 0

    def next(self) -> bytes:
        if self._counter >= 2**64:
            raise OverflowError("Nonce counter agotado; imposible en la práctica")
        nonce = self._prefix + struct.pack(">Q", self._counter)
        self._counter += 1
        return nonce


def create_chunk_header(chunk_seq: int, nonce: bytes, ciphertext_len: int) -> bytes:
    """
    Formato v1 (26 bytes):
    0-4: magic (4 bytes) "BVPM"
    4-6: version (uint16) 1
    6-10: chunk_seq (uint32)
    10-22: nonce (12 bytes)
    22-26: ciphertext_len (uint32)
    """
    magic = b"BVPM"
    version = 1
    return struct.pack(">4sHI12sI", magic, version, chunk_seq, nonce, ciphertext_len)


def parse_chunk_header(header: bytes) -> tuple[int, bytes, int]:
    """Parse header and return (chunk_seq, nonce, ciphertext_len)"""
    if len(header) != 26:
        raise ValueError("Invalid header length")
    magic, version, chunk_seq, nonce, ciphertext_len = struct.unpack(
        ">4sHI12sI", header
    )
    if magic != b"BVPM":
        raise ValueError("Invalid magic bytes")
    if version != 1:
        raise ValueError("Unsupported version")
    return chunk_seq, nonce, ciphertext_len


def create_chunk_header_v2(
    chunk_seq: int, nonce: bytes, raw_len: int, ciphertext_len: int
) -> bytes:
    """
    Formato v2 (30 bytes):
    0-4: magic (4 bytes) "BVPM"
    4-6: version (uint16) 2
    6-10: chunk_seq (uint32)
    10-14: raw_len (uint32)
    14-18: ciphertext_len (uint32)
    18-30: nonce (12 bytes)
    """
    magic = b"BVPM"
    version = 2
    return struct.pack(
        ">4sHIII12s", magic, version, chunk_seq, raw_len, ciphertext_len, nonce
    )


def create_aad(header: bytes, snapshot_id: str) -> bytes:
    """
    Construye el AAD usando todo el header binario de 26 bytes
    más el snapshot_id (aislamiento temporal).
    """
    return header + snapshot_id.encode("utf-8")


def create_invariant_aad(header: bytes) -> bytes:
    """
    Construye el AAD invariante a partir de la cabecera del bloque,
    desacoplado del snapshot_id para permitir deduplicación cross-snapshot.
    """
    return header


def create_tenant_aad(header: bytes, tenant_id: str) -> bytes:
    """
    Construye el AAD asociando el header binario con el identificador del inquilino,
    previniendo ataques de sustitución cruzada entre inquilinos.
    """
    return header + tenant_id.encode("utf-8")
