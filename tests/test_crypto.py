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


def test_dek_mutation():
    passphrase = "my_super_secret_passphrase"
    snapshot_id = "snap-mutation-123"

    salt_b64 = generate_master_salt()
    kek = derive_kek(passphrase, salt_b64)

    _dek_raw, enc_dek, nonce, tag = generate_dek_for_snapshot(kek, snapshot_id)

    # 1. Mutar ciphertext (enc_dek)
    mutated_enc = bytearray(enc_dek)
    mutated_enc[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        unwrap_dek(kek, bytes(mutated_enc), nonce, tag, snapshot_id)

    # 2. Mutar tag
    mutated_tag = bytearray(tag)
    mutated_tag[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        unwrap_dek(kek, enc_dek, nonce, bytes(mutated_tag), snapshot_id)

    # 3. Mutar nonce
    mutated_nonce = bytearray(nonce)
    mutated_nonce[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        unwrap_dek(kek, enc_dek, bytes(mutated_nonce), tag, snapshot_id)


def test_dedup_keys_and_synthetic_iv():
    from boveda.crypto import (
        compute_content_id,
        compute_synthetic_nonce,
        create_chunk_header_v2,
        create_invariant_aad,
        derive_chunk_key,
        derive_dedup_keys,
    )

    kek = b"0" * 32
    k_dedup, k_id = derive_dedup_keys(kek)
    assert len(k_dedup) == 32
    assert len(k_id) == 32
    assert k_dedup != k_id

    # Test content ID (deterministic)
    data1 = b"some data to chunk"
    data2 = b"some data to chunk"
    data3 = b"different data"

    id1 = compute_content_id(k_id, data1)
    id2 = compute_content_id(k_id, data2)
    id3 = compute_content_id(k_id, data3)

    assert len(id1) == 64
    assert id1 == id2
    assert id1 != id3

    # Test chunk key (deterministic)
    ckey1 = derive_chunk_key(k_dedup, data1)
    ckey2 = derive_chunk_key(k_dedup, data2)
    assert len(ckey1) == 32
    assert ckey1 == ckey2

    # Test synthetic nonce
    header = create_chunk_header_v2(
        chunk_seq=0, nonce=b"0" * 12, raw_len=100, ciphertext_len=120
    )
    assert len(header) == 30
    aad = create_invariant_aad(header)
    assert aad == header

    s_nonce1 = compute_synthetic_nonce(ckey1, aad, data1)
    s_nonce2 = compute_synthetic_nonce(ckey2, aad, data2)
    assert len(s_nonce1) == 12
    assert s_nonce1 == s_nonce2
