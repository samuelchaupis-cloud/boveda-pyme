import asyncio
import hashlib
from collections.abc import Awaitable, Callable

import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.constants import (
    CHUNK_SIZE_BYTES,
    MAX_CONCURRENT_UPLOADS,
    PIPELINE_QUEUE_MAXSIZE,
    ZSTD_COMPRESSION_LEVEL,
)
from boveda.crypto import NonceGenerator, create_aad, create_chunk_header


class SubprocessError(Exception):
    pass


async def read_source(
    cmd: list[str], queue: asyncio.Queue, shutdown_event: asyncio.Event
):
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    if proc.stdout is None or proc.stderr is None:
        raise SubprocessError("Pipes not initialized")

    while True:
        chunk = await proc.stdout.read(CHUNK_SIZE_BYTES)
        if not chunk:
            break

        if shutdown_event.is_set():
            proc.terminate()
            break

        put_task = asyncio.create_task(queue.put(chunk))
        wait_task = asyncio.create_task(shutdown_event.wait())

        done, pending = await asyncio.wait(
            [put_task, wait_task], return_when=asyncio.FIRST_COMPLETED
        )

        for p in pending:
            p.cancel()

        if wait_task in done:
            proc.terminate()
            break

    await proc.wait()
    if proc.returncode != 0 and not shutdown_event.is_set():
        stderr_output = (await proc.stderr.read()).decode(errors="replace")
        raise SubprocessError(
            f"{cmd[0]} terminó con código {proc.returncode}: {stderr_output[:500]}"
        )

    await queue.put(None)  # Sentinel


async def compress_encrypt_upload(
    queue: asyncio.Queue,
    upload_semaphore: asyncio.Semaphore,
    snapshot_id: str,
    dek: bytes,
    upload_callback: Callable[[int, bytes, str], Awaitable[None]],
    shutdown_event: asyncio.Event,
):
    cctx = zstd.ZstdCompressor(level=ZSTD_COMPRESSION_LEVEL)
    aesgcm = AESGCM(dek)
    nonce_gen = NonceGenerator()
    chunk_seq = 0

    upload_tasks = []

    while True:
        get_task = asyncio.create_task(queue.get())
        wait_task = asyncio.create_task(shutdown_event.wait())

        done, pending = await asyncio.wait(
            [get_task, wait_task], return_when=asyncio.FIRST_COMPLETED
        )

        for p in pending:
            p.cancel()

        if wait_task in done:
            break

        chunk = get_task.result()
        if chunk is None:
            break

        # 1. Compress
        compressed = cctx.compress(chunk)

        # 2. Encrypt
        nonce = nonce_gen.next()
        aad = create_aad(chunk_seq, snapshot_id)
        ciphertext = aesgcm.encrypt(nonce, compressed, aad)

        # 3. Header + Payload
        header = create_chunk_header(chunk_seq, nonce, len(ciphertext))
        final_payload = header + ciphertext

        # 4. Hash SHA-256
        chunk_hash = hashlib.sha256(final_payload).hexdigest()

        # 5. Upload (concurrent via semaphore)
        await upload_semaphore.acquire()

        async def do_upload(seq: int, payload: bytes, h: str):
            try:
                if not shutdown_event.is_set():
                    await upload_callback(seq, payload, h)
            finally:
                upload_semaphore.release()

        task = asyncio.create_task(do_upload(chunk_seq, final_payload, chunk_hash))
        upload_tasks.append(task)

        chunk_seq += 1

    if upload_tasks:
        await asyncio.gather(*upload_tasks, return_exceptions=True)


async def streaming_pipeline(
    source_cmd: list[str],
    snapshot_id: str,
    dek: bytes,
    upload_callback: Callable[[int, bytes, str], Awaitable[None]],
    shutdown_event: asyncio.Event,
):
    queue = asyncio.Queue(maxsize=PIPELINE_QUEUE_MAXSIZE)
    upload_semaphore = asyncio.Semaphore(MAX_CONCURRENT_UPLOADS)

    async with asyncio.TaskGroup() as tg:
        tg.create_task(read_source(source_cmd, queue, shutdown_event))
        tg.create_task(
            compress_encrypt_upload(
                queue,
                upload_semaphore,
                snapshot_id,
                dek,
                upload_callback,
                shutdown_event,
            )
        )
