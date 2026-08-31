"""Módulo de sellado legal, árboles de Merkle RFC 6962 y firmas Ed25519."""

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def compute_merkle_root(chunk_hashes: list[str]) -> str:
    """Calcula el Merkle Root de los bloques con separación de dominio RFC 6962.

    0x00 para hojas, 0x01 para nodos internos.
    """
    if not chunk_hashes:
        return hashlib.sha256(b"").hexdigest()

    # 1. Hojas con prefijo 0x00
    current_level: list[bytes] = [
        hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in chunk_hashes
    ]

    # 2. Nodos internos con prefijo 0x01
    while len(current_level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # Si el nivel tiene cantidad impar, se duplica el último nodo
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256(b"\x01" + left + right).digest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0].hex()


def create_canonical_manifest_json(
    snapshot_id: str,
    timestamp_iso: str,
    tipo: str,
    source: str,
    chunk_hashes: list[str],
    total_size_bytes: int,
    parent_snapshot_id: str | None = None,
    parent_manifest_hash: str | None = None,
) -> bytes:
    """Genera el JSON canónico (RFC 8785) determinista con claves ordenadas."""
    merkle_root = compute_merkle_root(chunk_hashes)

    manifest_dict: dict[str, Any] = {
        "chunk_hashes": chunk_hashes,
        "merkle_root": merkle_root,
        "parent_manifest_hash": parent_manifest_hash,
        "parent_snapshot_id": parent_snapshot_id,
        "snapshot_id": snapshot_id,
        "source": source,
        "timestamp": timestamp_iso,
        "total_chunks": len(chunk_hashes),
        "total_size_bytes": total_size_bytes,
        "type": tipo,
        "version": "1.0",
    }

    # Serialización canónica determinista: claves ordenadas, sin espacios extra
    canonical_json_str = json.dumps(
        manifest_dict, sort_keys=True, separators=(",", ":")
    )
    return canonical_json_str.encode("utf-8")


def generate_ed25519_keypair() -> tuple[str, str]:
    """Genera un nuevo par de claves Ed25519 codificadas en Base64."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    from cryptography.hazmat.primitives import serialization

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return (
        base64.b64encode(priv_bytes).decode("utf-8"),
        base64.b64encode(pub_bytes).decode("utf-8"),
    )


def sign_manifest_ed25519(canonical_manifest_bytes: bytes, private_key_b64: str) -> str:
    """Firma digitalmente el manifiesto canónico usando Ed25519."""
    raw_priv = base64.b64decode(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
    signature = private_key.sign(canonical_manifest_bytes)
    return base64.b64encode(signature).decode("utf-8")


def verify_manifest_signature(
    canonical_manifest_bytes: bytes, signature_b64: str, public_key_b64: str
) -> bool:
    """Verifica de forma Zero-Knowledge la firma Ed25519 del manifiesto canónico."""
    try:
        raw_pub = base64.b64decode(public_key_b64)
        raw_sig = base64.b64decode(signature_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_pub)
        public_key.verify(raw_sig, canonical_manifest_bytes)
        return True
    except (InvalidSignature, ValueError):
        return False
