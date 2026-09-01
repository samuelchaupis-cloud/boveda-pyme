"""Algoritmo de Content-Defined Chunking (FastCDC) optimizado para streaming continuo."""

import hashlib
from collections.abc import Iterator


# Generación determinista del vector GEAR_TABLE de 256 constantes uint64
def _generate_gear_table() -> tuple[int, ...]:
    table: list[int] = []
    for i in range(256):
        h = hashlib.sha256(f"boveda-fastcdc-gear-seed-v1-{i}".encode()).digest()
        val = int.from_bytes(h[:8], byteorder="big", signed=False)
        table.append(val)
    return tuple(table)


GEAR_TABLE: tuple[int, ...] = _generate_gear_table()

MIN_CHUNK_SIZE: int = 1 * 1024 * 1024  # 1 MiB
AVG_CHUNK_SIZE: int = 2 * 1024 * 1024  # 2 MiB
MAX_CHUNK_SIZE: int = 4 * 1024 * 1024  # 4 MiB


# Máscaras de dos niveles para Normalized Chunking
MASK_STRICT: int = (
    0x003FFFFF  # 22 bits a cero (en región temprana: 1MB <= offset < 2MB)
)
MASK_LAX: int = 0x000FFFFF  # 20 bits a cero (en región tardía: 2MB <= offset < 4MB)


def find_fastcdc_boundary_rolling(
    buf: memoryview,
    start_offset: int,
    max_offset: int,
    fingerprint: int = 0,
    is_eof: bool = False,
) -> tuple[int, int, int]:
    """Calcula el límite del bloque manteniendo el fingerprint rodante para escaneo O(N)."""
    buf_len = len(buf)
    if buf_len < MIN_CHUNK_SIZE:
        return (buf_len if is_eof else 0, fingerprint, 0)

    scan_limit = min(buf_len, max_offset, MAX_CHUNK_SIZE)
    start_scan = max(MIN_CHUNK_SIZE, start_offset)
    gear = GEAR_TABLE
    m_strict = MASK_STRICT
    m_lax = MASK_LAX
    avg_size = AVG_CHUNK_SIZE

    for i in range(start_scan, scan_limit):
        b = buf[i]
        fingerprint = ((fingerprint << 1) + gear[b]) & 0xFFFFFFFFFFFFFFFF

        if i < avg_size:
            if (fingerprint & m_strict) == 0:
                return (i + 1, fingerprint, i + 1)
        elif (fingerprint & m_lax) == 0:
            return (i + 1, fingerprint, i + 1)

    # Si se alcanzó el límite máximo de chunk permitido
    if scan_limit >= MAX_CHUNK_SIZE:
        return (MAX_CHUNK_SIZE, fingerprint, MAX_CHUNK_SIZE)

    # Si es EOF y quedan datos entre MIN_CHUNK_SIZE y MAX_CHUNK_SIZE
    if is_eof and buf_len > 0:
        return (buf_len, fingerprint, buf_len)

    return (0, fingerprint, scan_limit)


def find_fastcdc_boundary(
    buf: memoryview,
    start_offset: int,
    max_offset: int,
    is_eof: bool = False,
) -> int:
    """Calcula el límite del bloque usando Gear Hashing y Normalized Chunking."""
    b, _, _ = find_fastcdc_boundary_rolling(buf, start_offset, max_offset, 0, is_eof)
    return b


class FastCDCStreamer:
    """Motor de particionado FastCDC en streaming continuo con memoria acotada y escaneo lineal O(N)."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self._scanned_offset = 0
        self._fingerprint = 0

    def feed(self, data: bytes, is_eof: bool = False) -> Iterator[bytes]:
        """Alimenta el búfer con nuevos datos y emite chunks según los límites de FastCDC."""
        if data:
            self._buffer.extend(data)

        while True:
            if not self._buffer:
                break

            view = memoryview(self._buffer)
            try:
                boundary, self._fingerprint, new_scanned = (
                    find_fastcdc_boundary_rolling(
                        view,
                        self._scanned_offset,
                        len(self._buffer),
                        self._fingerprint,
                        is_eof=is_eof,
                    )
                )
            finally:
                view.release()

            if boundary == 0:
                self._scanned_offset = new_scanned
                break

            # Extraer chunk y resetear punteros para el siguiente bloque
            chunk = bytes(self._buffer[:boundary])
            del self._buffer[:boundary]
            self._scanned_offset = 0
            self._fingerprint = 0
            yield chunk

            if not is_eof and len(self._buffer) < MIN_CHUNK_SIZE:
                break
