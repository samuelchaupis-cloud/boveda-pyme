import os

import pytest
from cryptography.exceptions import InvalidTag

from boveda.crypto import (
    MASTER_KEY_LENGTH,
    NonceGenerator,
    create_aad,
    create_chunk_header,
    derive_kek,
    generate_dek_for_snapshot,
    generate_master_salt,
    parse_chunk_header,
    unwrap_dek,
)


def test_key_hierarchy():
    passphrase = "my_super_secret_passphrase"
    snapshot_id = "snap-12345"

    # 1. Generar salt y KEK
    salt_b64 = generate_master_salt()
    kek = derive_kek(passphrase, salt_b64)
    assert len(kek) == MASTER_KEY_LENGTH

    # 2. KEK distinto para salt distinto o passphrase distinta
    kek2 = derive_kek("wrong_passphrase", salt_b64)
    assert kek != kek2

    # 3. Generar DEK envuelto
    dek_raw, enc_dek, nonce, tag = generate_dek_for_snapshot(kek, snapshot_id)
    assert len(dek_raw) == 32
    assert len(nonce) == 12
    assert len(tag) == 16

    # 4. Desenvuelto correcto
    unwrapped = unwrap_dek(kek, enc_dek, nonce, tag, snapshot_id)
    assert unwrapped == dek_raw

    # 5. Aislamiento / AAD inválido
    with pytest.raises(InvalidTag):
        unwrap_dek(kek, enc_dek, nonce, tag, "snap-wrong")

    with pytest.raises(InvalidTag):
        unwrap_dek(kek2, enc_dek, nonce, tag, snapshot_id)


def test_nonce_uniqueness():
    gen = NonceGenerator()
    nonces = set()
    for _ in range(10000):
        n = gen.next()
        assert len(n) == 12
        nonces.add(n)

    assert len(nonces) == 10000


def test_chunk_format_parse():
    seq = 42
    nonce = os.urandom(12)
    cipher_len = 1024

    header = create_chunk_header(seq, nonce, cipher_len)
    assert len(header) == 26

    p_seq, p_nonce, p_len = parse_chunk_header(header)
    assert p_seq == seq
    assert p_nonce == nonce
    assert p_len == cipher_len

    # Modificar magic
    bad_header = b"BADM" + header[4:]
    with pytest.raises(ValueError, match="Invalid magic"):
        parse_chunk_header(bad_header)

    # Modificar version
    bad_version = header[:4] + b"\x00\x02" + header[6:]
    with pytest.raises(ValueError, match="Unsupported version"):
        parse_chunk_header(bad_version)


def test_aad_generation():
    seq = 5
    snap = "snap-test"
    nonce = os.urandom(12)
    header = create_chunk_header(seq, nonce, 1024)
    aad = create_aad(header, snap)
    assert aad.startswith(header)
    assert aad.endswith(b"snap-test")
