import base64
import os
import struct

import argon2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def generate_dek_for_snapshot(
    kek: bytes, snapshot_id: str
) -> tuple[bytes, bytes, bytes, bytes]:
    """Genera DEK y lo envuelve con KEK.
    Retorna (dek_raw, encrypted_dek, dek_nonce, dek_tag)
    """
    dek_raw = os.urandom(32)
    dek_nonce = os.urandom(12)
    aesgcm = AESGCM(kek)

    # Requirement: AAD must include snapshot.id
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
    Formato:
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


def create_aad(chunk_seq: int, snapshot_id: str) -> bytes:
    """magic ‖ version ‖ chunk_seq ‖ snapshot_id"""
    magic = b"BVPM"
    version = 1
    # 4 bytes magic, 2 bytes version, 4 bytes chunk_seq + snapshot_id
    base = struct.pack(">4sHI", magic, version, chunk_seq)
    return base + snapshot_id.encode("utf-8")
