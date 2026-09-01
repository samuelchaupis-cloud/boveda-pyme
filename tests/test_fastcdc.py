import hashlib
import os

from boveda.fastcdc import (
    AVG_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    FastCDCStreamer,
    find_fastcdc_boundary,
)


def test_fastcdc_constants():
    assert MIN_CHUNK_SIZE == 1 * 1024 * 1024
    assert AVG_CHUNK_SIZE == 2 * 1024 * 1024
    assert MAX_CHUNK_SIZE == 4 * 1024 * 1024
    assert MIN_CHUNK_SIZE < AVG_CHUNK_SIZE < MAX_CHUNK_SIZE


def test_fastcdc_boundary_short_buffer():
    # Buffer menor a MIN_CHUNK_SIZE no debe cortar prematuramente si no es EOF
    short_data = b"A" * (512 * 1024)
    boundary = find_fastcdc_boundary(
        memoryview(short_data), 0, len(short_data), is_eof=False
    )
    assert boundary == 0

    # Si es EOF, debe cortar en el tamaño disponible
    boundary_eof = find_fastcdc_boundary(
        memoryview(short_data), 0, len(short_data), is_eof=True
    )
    assert boundary_eof == len(short_data)


def test_fastcdc_boundary_max_cap():
    # Buffer mayor a MAX_CHUNK_SIZE sin coincidencia de máscara debe cortar en MAX_CHUNK_SIZE
    large_data = b"\x00" * (MAX_CHUNK_SIZE + 1024)
    boundary = find_fastcdc_boundary(
        memoryview(large_data), 0, len(large_data), is_eof=False
    )
    assert boundary <= MAX_CHUNK_SIZE
    assert boundary >= MIN_CHUNK_SIZE


def test_fastcdc_deterministic_chunking():
    # Mismo stream debe generar exactamente los mismos chunks y hashes
    data = os.urandom(8 * 1024 * 1024)  # 8MB

    streamer1 = FastCDCStreamer()
    chunks1 = list(streamer1.feed(data, is_eof=True))

    streamer2 = FastCDCStreamer()
    chunks2 = list(streamer2.feed(data, is_eof=True))

    assert len(chunks1) == len(chunks2)
    assert sum(len(c) for c in chunks1) == len(data)

    for c1, c2 in zip(chunks1, chunks2, strict=True):
        assert len(c1) == len(c2)
        assert hashlib.sha256(c1).digest() == hashlib.sha256(c2).digest()
        # Verificar cotas de tamaño
        assert len(c1) <= MAX_CHUNK_SIZE


def test_fastcdc_content_defined_shift_resilience():
    # Propiedad fundamental de CDC: Si insertamos datos al inicio de un stream con entropía,
    # los chunks subsecuentes deben resincronizarse (Deduplication across shifts)
    import random

    rng = random.Random(42)
    # 12MB de datos pseudo-aleatorios deterministas
    base_data = rng.randbytes(12 * 1024 * 1024)

    streamer_base = FastCDCStreamer()
    chunks_base = list(streamer_base.feed(base_data, is_eof=True))

    # Insertar 256 bytes al inicio
    shifted_data = (
        b"PREFIX_256_BYTES_INJECTED_AT_THE_START_" + (b"\xaa" * 217) + base_data
    )
    streamer_shifted = FastCDCStreamer()
    chunks_shifted = list(streamer_shifted.feed(shifted_data, is_eof=True))

    # Al menos uno de los chunks intermedios o finales debe coincidir en hash tras la resincronización
    hashes_base = {hashlib.sha256(c).hexdigest() for c in chunks_base}
    hashes_shifted = {hashlib.sha256(c).hexdigest() for c in chunks_shifted}

    common_chunks = hashes_base.intersection(hashes_shifted)
    assert len(common_chunks) >= 1, (
        "FastCDC no logró resincronizar chunks tras desplazamiento"
    )
