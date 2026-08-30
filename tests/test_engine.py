import asyncio
import os

import pytest
import zstandard as zstd
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

    with pytest.raises(SubprocessError, match="terminó con código 1"):
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
        aad = create_aad(seq, snapshot_id)

        compressed = aesgcm.decrypt(nonce, ciphertext, aad)
        raw = dctx.decompress(compressed)
        assembled_raw += raw

    assert assembled_raw == test_data
