import asyncio
import os

import pytest
import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.crypto import create_aad, parse_chunk_header
from boveda.engine import (
    SubprocessError,
    read_source,
    streaming_pipeline,
)


@pytest.mark.asyncio
async def test_subprocess_exit_code():
    queue = asyncio.Queue()
    shutdown_event = asyncio.Event()
    # Ejecutamos un comando que falla, ej. ls un archivo inexistente o bash -c 'exit 1'
    # Como es windows, usaremos pwsh -Command "exit 1"
    cmd = ["pwsh", "-Command", "Write-Error 'Fallo intencional'; exit 1"]

    with pytest.raises(SubprocessError, match="terminó con error 1"):
        await read_source(cmd, queue, shutdown_event)


@pytest.mark.asyncio
async def test_backpressure_queue():
    queue = asyncio.Queue(maxsize=1)
    shutdown_event = asyncio.Event()

    cmd = [
        "python",
        "-c",
        "import sys, time; sys.stdout.buffer.write(b'Chunk '*1000); sys.stdout.flush(); time.sleep(1); sys.stdout.buffer.write(b'Chunk2 '*1000); sys.stdout.flush()",
    ]

    task = asyncio.create_task(read_source(cmd, queue, shutdown_event))

    await asyncio.sleep(2.0)
    assert queue.full()

    # Vaciamos la cola
    while not queue.empty():
        await queue.get()

    await asyncio.sleep(0.5)

    # Forzamos terminación
    shutdown_event.set()

    # Vaciamos otra vez
    while not queue.empty():
        await queue.get()

    # Esperamos a que la tarea termine
    await task


@pytest.mark.asyncio
async def test_pipeline_roundtrip():
    dek = os.urandom(32)
    snapshot_id = "test-snap-roundtrip"
    shutdown_event = asyncio.Event()

    test_data = (
        b"Hello, this is a test string that will be compressed and encrypted." * 100
    )

    uploads = {}

    async def mock_upload(seq: int, payload: bytes, h: str):
        uploads[seq] = payload

    cmd = [
        "python",
        "-c",
        "import sys; sys.stdout.buffer.write(b'Hello, this is a test string that will be compressed and encrypted.' * 100)",
    ]

    await streaming_pipeline(cmd, snapshot_id, dek, mock_upload, shutdown_event)

    assert len(uploads) >= 1

    assembled_raw = b""
    aesgcm = AESGCM(dek)
    dctx = zstd.ZstdDecompressor()

    for seq in sorted(uploads.keys()):
        payload = uploads[seq]
        header = payload[:26]
        c_seq, nonce, _c_len = parse_chunk_header(header)
        assert c_seq == seq

        ciphertext = payload[26:]
        aad = create_aad(header, snapshot_id)

        compressed = aesgcm.decrypt(nonce, ciphertext, aad)
        raw = dctx.decompress(compressed)
        assembled_raw += raw

    assert assembled_raw == test_data


@pytest.mark.asyncio
async def test_pipeline_mutation_failures():
    dek = os.urandom(32)
    snapshot_id = "test-snap-mutation"
    shutdown_event = asyncio.Event()

    uploads = {}

    async def mock_upload(seq: int, payload: bytes, h: str):
        uploads[seq] = payload

    cmd = [
        "python",
        "-c",
        "import sys; sys.stdout.buffer.write(b'Secret'*100)",
    ]

    await streaming_pipeline(cmd, snapshot_id, dek, mock_upload, shutdown_event)

    assert len(uploads) >= 1

    payload = uploads[0]
    header = payload[:26]
    ciphertext = payload[26:]

    _c_seq, nonce, _c_len = parse_chunk_header(header)
    aesgcm = AESGCM(dek)

    # 1. Mutar Ciphertext (corromper 1 byte de datos encriptados / tag)
    mutated_ciphertext = bytearray(ciphertext)
    mutated_ciphertext[0] ^= 0xFF
    aad = create_aad(header, snapshot_id)

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, bytes(mutated_ciphertext), aad)

    # 2. Mutar tag (últimos 16 bytes de ciphertext en AESGCM)
    mutated_tag = bytearray(ciphertext)
    mutated_tag[-1] ^= 0xFF

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, bytes(mutated_tag), aad)

    # 3. Mutar header (afecta al AAD)
    mutated_header = bytearray(header)
    mutated_header[-1] ^= 0xFF
    mutated_aad = create_aad(bytes(mutated_header), snapshot_id)

    with pytest.raises(InvalidTag):
        aesgcm.decrypt(nonce, ciphertext, mutated_aad)


@pytest.mark.asyncio
async def test_streaming_edge_cases_and_boundaries():
    dek = os.urandom(32)
    snapshot_id = "snap-boundaries-test"

    # 1. Caso 0 bytes (stream vacío)
    uploads_empty = []

    async def mock_upload_empty(seq, payload, h):
        uploads_empty.append((seq, payload, h))

    cmd_empty = ["python", "-c", "import sys; sys.stdout.buffer.write(b'')"]
    shutdown_empty = asyncio.Event()
    await streaming_pipeline(
        cmd_empty, snapshot_id, dek, mock_upload_empty, shutdown_empty
    )
    assert len(uploads_empty) == 0

    # 2. Caso 1 byte
    uploads_1b = []

    async def mock_upload_1b(seq, payload, h):
        uploads_1b.append((seq, payload, h))

    cmd_1b = ["python", "-c", "import sys; sys.stdout.buffer.write(b'Z')"]
    shutdown_1b = asyncio.Event()
    await streaming_pipeline(cmd_1b, snapshot_id, dek, mock_upload_1b, shutdown_1b)
    assert len(uploads_1b) == 1
    assert uploads_1b[0][0] == 0  # seq 0

    # 3. Caso 4MB exactos (1 chunk exacto)
    uploads_4mb = []

    async def mock_upload_4mb(seq, payload, h):
        uploads_4mb.append((seq, payload, h))

    cmd_4mb = [
        "python",
        "-c",
        "import sys; sys.stdout.buffer.write(b'B' * (4 * 1024 * 1024))",
    ]
    shutdown_4mb = asyncio.Event()
    await streaming_pipeline(cmd_4mb, snapshot_id, dek, mock_upload_4mb, shutdown_4mb)
    assert len(uploads_4mb) == 1
    assert uploads_4mb[0][0] == 0

    # 4. Caso 4MB + 1 byte (2 chunks por alcanzar MAX_CHUNK_SIZE)
    uploads_4mb_plus = []

    async def mock_upload_4mb_plus(seq, payload, h):
        uploads_4mb_plus.append((seq, payload, h))

    cmd_4mb_plus = [
        "python",
        "-c",
        "import sys; sys.stdout.buffer.write(b'B' * (4 * 1024 * 1024) + b'X')",
    ]
    shutdown_4mb_plus = asyncio.Event()
    await streaming_pipeline(
        cmd_4mb_plus, snapshot_id, dek, mock_upload_4mb_plus, shutdown_4mb_plus
    )
    assert len(uploads_4mb_plus) == 2
    assert uploads_4mb_plus[0][0] == 0
    assert uploads_4mb_plus[1][0] == 1
