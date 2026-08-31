import hashlib
import json

from boveda.manifest import (
    compute_merkle_root,
    create_canonical_manifest_json,
    generate_ed25519_keypair,
    sign_manifest_ed25519,
    verify_manifest_signature,
)


def test_compute_merkle_root():
    # Empty list
    assert compute_merkle_root([]) == hashlib.sha256(b"").hexdigest()

    # Single chunk known RFC 6962 domain separation vector
    h_zero = "00" * 32
    expected_leaf_hash = hashlib.sha256(b"\x00" + b"\x00" * 32).hexdigest()
    assert compute_merkle_root([h_zero]) == expected_leaf_hash

    # Single chunk
    h1 = "1" * 64
    root1 = compute_merkle_root([h1])
    assert len(root1) == 64

    # Even chunks (2 chunks)
    h2 = "2" * 64
    root2 = compute_merkle_root([h1, h2])
    assert len(root2) == 64
    assert root2 != root1

    # Odd chunks (3 chunks - test last node duplication)
    h3 = "3" * 64
    root3 = compute_merkle_root([h1, h2, h3])
    assert len(root3) == 64
    assert root3 != root2


def test_canonical_manifest_determinism():
    chunks = ["a" * 64, "b" * 64]
    m1 = create_canonical_manifest_json(
        snapshot_id="snap-123",
        timestamp_iso="2026-08-31T12:00:00Z",
        tipo="DIARIO",
        source="db-prod",
        chunk_hashes=chunks,
        total_size_bytes=1024,
    )
    m2 = create_canonical_manifest_json(
        snapshot_id="snap-123",
        timestamp_iso="2026-08-31T12:00:00Z",
        tipo="DIARIO",
        source="db-prod",
        chunk_hashes=chunks,
        total_size_bytes=1024,
    )
    assert m1 == m2
    parsed = json.loads(m1.decode("utf-8"))
    assert parsed["snapshot_id"] == "snap-123"
    assert parsed["total_chunks"] == 2


def test_ed25519_sign_and_verify():
    priv_b64, pub_b64 = generate_ed25519_keypair()
    manifest_bytes = b'{"test":"manifest_data"}'

    signature_b64 = sign_manifest_ed25519(manifest_bytes, priv_b64)
    assert len(signature_b64) > 0

    # Verification success
    assert verify_manifest_signature(manifest_bytes, signature_b64, pub_b64) is True

    # Mutated manifest
    assert (
        verify_manifest_signature(b'{"test":"tampered"}', signature_b64, pub_b64)
        is False
    )

    # Wrong public key
    _priv2, pub2_b64 = generate_ed25519_keypair()
    assert verify_manifest_signature(manifest_bytes, signature_b64, pub2_b64) is False

    # Invalid signature bytes
    assert verify_manifest_signature(manifest_bytes, "invalid_sig", pub_b64) is False
