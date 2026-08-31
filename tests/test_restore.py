import hashlib
import io
import os

import pytest
import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.crypto import (
    NonceGenerator,
    create_aad,
    create_chunk_header,
    generate_dek_for_snapshot,
)
from boveda.database import Bloque, Snapshot
from boveda.restore import IntegrityError, restore_snapshot


def build_valid_snapshot_and_chunks():
    kek = os.urandom(32)
    snap = Snapshot(id="snap-test", estado="COMPLETED")
    dek_raw, enc_dek, dek_nonce, dek_tag = generate_dek_for_snapshot(kek, snap.id)
    snap.encrypted_dek = enc_dek
    snap.dek_nonce = dek_nonce
    snap.dek_tag = dek_tag

    # Generate 1 chunk of fake data
    aesgcm = AESGCM(dek_raw)
    nonce = NonceGenerator().next()
    cctx = zstd.ZstdCompressor(level=1)

    plaintext = b"Some data"
    compressed = cctx.compress(plaintext)
    ciphertext_len = len(compressed) + 16
    header = create_chunk_header(0, nonce, ciphertext_len)
    aad = create_aad(header, snap.id)
    ciphertext = aesgcm.encrypt(nonce, compressed, aad)

    raw_payload = header + ciphertext

    bloque = Bloque(
        snapshot_id=snap.id,
        chunk_seq=0,
        storage_key="test-key",
        hash_sha256=hashlib.sha256(raw_payload).hexdigest(),
    )

    return snap, kek, [bloque], {"test-key": raw_payload}, plaintext


def test_restore_success():
    snap, kek, bloques, store, plaintext = build_valid_snapshot_and_chunks()
    out = io.BytesIO()

    restore_snapshot(snap, kek, bloques, out, lambda k: store[k])
    assert out.getvalue() == plaintext


def test_restore_hash_mismatch():
    snap, kek, bloques, store, _plaintext = build_valid_snapshot_and_chunks()
    out = io.BytesIO()

    store["test-key"] = (
        store["test-key"][:-1] + b"x"
    )  # corrupt last byte (part of GCM tag)

    with pytest.raises(IntegrityError, match="SHA-256 mismatch"):
        restore_snapshot(snap, kek, bloques, out, lambda k: store[k])

    assert out.getvalue() == b""


def test_restore_gcm_mismatch():
    snap, kek, bloques, store, _plaintext = build_valid_snapshot_and_chunks()
    out = io.BytesIO()

    # We corrupt the GCM tag, but we MUST recompute the SHA256 so it passes the hash check
    corrupted_payload = store["test-key"][:-1] + b"x"
    store["test-key"] = corrupted_payload
    bloques[0].hash_sha256 = hashlib.sha256(corrupted_payload).hexdigest()

    with pytest.raises(IntegrityError, match="Fallo de autenticación GCM"):
        restore_snapshot(snap, kek, bloques, out, lambda k: store[k])

    assert out.getvalue() == b""


def test_restore_not_completed():
    from boveda.restore import RestoreError

    snap = Snapshot(id="snap-inc", estado="RUNNING")
    with pytest.raises(RestoreError, match="Snapshot no está COMPLETED"):
        restore_snapshot(snap, b"0" * 32, [], io.BytesIO(), lambda k: b"")


def test_restore_dek_corruption():
    snap, kek, bloques, store, _plaintext = build_valid_snapshot_and_chunks()
    snap.encrypted_dek = b"invalid_dek_bytes_xyz"
    with pytest.raises(IntegrityError, match="Error al descifrar DEK"):
        restore_snapshot(snap, kek, bloques, io.BytesIO(), lambda k: store[k])


def test_restore_sequence_mismatch():
    snap, kek, bloques, store, _plaintext = build_valid_snapshot_and_chunks()
    bloques[0].chunk_seq = 999  # Mismatch with header chunk_seq 0
    with pytest.raises(IntegrityError, match="Mismatch de secuencia"):
        restore_snapshot(snap, kek, bloques, io.BytesIO(), lambda k: store[k])
