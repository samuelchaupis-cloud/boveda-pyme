import hashlib
from typing import IO

import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.crypto import create_aad, parse_chunk_header, unwrap_dek
from boveda.database import Bloque, Snapshot


class IntegrityError(Exception):
    pass


class RestoreError(Exception):
    pass


def restore_snapshot(
    snapshot: Snapshot,
    kek: bytes,
    bloques: list[Bloque],
    output: IO[bytes],
    download_callback,
):
    """
    Restaura un snapshot verificando bloque a bloque.
    """
    if snapshot.estado != "COMPLETED":
        raise RestoreError("Snapshot no está COMPLETED")

    try:
        dek = unwrap_dek(
            kek,
            snapshot.encrypted_dek,
            snapshot.dek_nonce,
            snapshot.dek_tag,
            snapshot.id,
        )
    except InvalidTag:
        raise IntegrityError(
            "Error al descifrar DEK: tag inválido o snapshot adulterado"
        )

    aesgcm = AESGCM(dek)
    dctx = zstd.ZstdDecompressor().stream_writer(output)

    # bloques must be sorted by chunk_seq
    for bloque in sorted(bloques, key=lambda b: b.chunk_seq):
        raw = download_callback(bloque.storage_key)

        if hashlib.sha256(raw).hexdigest() != bloque.hash_sha256:
            raise IntegrityError(f"SHA-256 mismatch en chunk {bloque.chunk_seq}")

        header = raw[:26]
        try:
            c_seq, nonce, _ = parse_chunk_header(header)
        except ValueError as e:
            raise IntegrityError(
                f"Error parseando header de chunk {bloque.chunk_seq}: {e}"
            )

        if c_seq != bloque.chunk_seq:
            raise IntegrityError(
                f"Mismatch de secuencia: {c_seq} != {bloque.chunk_seq}"
            )

        ciphertext = raw[26:]
        aad = create_aad(c_seq, snapshot.id)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise IntegrityError(
                f"Fallo de autenticación GCM en chunk {bloque.chunk_seq}"
            )

        dctx.write(plaintext)

    dctx.flush()
