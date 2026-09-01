import hashlib
from collections.abc import Callable, Iterable
from typing import IO

import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.crypto import create_aad, parse_chunk_header, unwrap_dek
from boveda.database import Bloque, Snapshot, SnapshotState


class IntegrityError(Exception):
    pass


class RestoreError(Exception):
    pass


def restore_snapshot(
    snapshot: Snapshot,
    kek: bytes,
    bloques: Iterable[Bloque],
    output: IO[bytes],
    download_callback: Callable[[str], bytes],
) -> None:
    """
    Restaura un snapshot verificando bloque a bloque en streaming acotado.
    """
    if snapshot.estado != SnapshotState.COMPLETED:
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

    # Si se pasa una lista no ordenada, ordenar; si es un generador/iterable streamed, consumir en orden
    bloque_iter = (
        sorted(bloques, key=lambda b: b.chunk_seq)
        if isinstance(bloques, list)
        else bloques
    )

    dctx = zstd.ZstdDecompressor().stream_writer(output, closefd=False)
    for bloque in bloque_iter:
        raw = download_callback(bloque.storage_key)

        if len(raw) < 26:
            raise IntegrityError(
                f"Chunk {bloque.chunk_seq} truncado (tamaño {len(raw)} < 26 bytes)"
            )

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
        aad = create_aad(header, snapshot.id)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise IntegrityError(
                f"Fallo de autenticación GCM en chunk {bloque.chunk_seq}"
            )

        dctx.write(plaintext)

    dctx.flush()

