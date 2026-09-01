import asyncio
import contextlib
import hashlib
import signal
from collections import deque

import zstandard as zstd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from boveda.connectors import drain_stderr_nonblocking
from boveda.constants import (
    MAX_CONCURRENT_UPLOADS,
    PIPELINE_QUEUE_MAXSIZE,
    ZSTD_COMPRESSION_LEVEL,
)
from boveda.crypto import NonceGenerator, create_aad, create_chunk_header
from boveda.fastcdc import FastCDCStreamer


class SubprocessError(Exception):
    pass


async def read_source(
    cmd: list[str],
    queue: asyncio.Queue[bytes | None],
    shutdown_event: asyncio.Event,
):
    """Ejecuta el origen y alimenta la cola usando FastCDC con drenaje continuo de stderr."""
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )

    if proc.stdout is None or proc.stderr is None:
        raise SubprocessError("Pipes not initialized")

    stderr_buffer: deque[bytes] = deque(maxlen=16)
    drain_task = asyncio.create_task(
        drain_stderr_nonblocking(proc.stderr, stderr_buffer)
    )

    fastcdc = FastCDCStreamer()
    io_read_size = 512 * 1024

    try:
        while True:
            raw_bytes = await proc.stdout.read(io_read_size)
            is_eof = len(raw_bytes) == 0

            for chunk in fastcdc.feed(raw_bytes, is_eof=is_eof):
                put_task = asyncio.create_task(queue.put(chunk))
                wait_task = asyncio.create_task(shutdown_event.wait())

                done, pending = await asyncio.wait(
                    [put_task, wait_task], return_when=asyncio.FIRST_COMPLETED
                )

                for p in pending:
                    p.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                if wait_task in done:
                    break

            if is_eof or shutdown_event.is_set():
                break

        if not shutdown_event.is_set():
            try:
                put_sentinel = asyncio.create_task(queue.put(None))
                wait_shutdown = asyncio.create_task(shutdown_event.wait())
                done, pending = await asyncio.wait(
                    [put_sentinel, wait_shutdown],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            except Exception:
                pass

        await proc.wait()

        if proc.returncode != 0 and not shutdown_event.is_set():
            raw_err = b"".join(stderr_buffer).decode(errors="ignore")
            sigpipe_code = -getattr(signal, "SIGPIPE", 13)
            is_sigpipe = proc.returncode == sigpipe_code or proc.returncode in (
                109,
                141,
            )
            if not is_sigpipe:
                raise SubprocessError(
                    f"Proceso terminó con error {proc.returncode}: {raw_err[-500:]}"
                )

    finally:
        drain_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await drain_task
        if proc.returncode is None:
            with contextlib.suppress(Exception):
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3.0)
                except TimeoutError:
                    proc.kill()


async def compress_encrypt_upload(
    queue: asyncio.Queue[bytes | None],
    snapshot_id: str,
    dek: bytes,
    upload_callback,
    shutdown_event: asyncio.Event,
):
    aesgcm = AESGCM(dek)
    nonce_gen = NonceGenerator()
    chunk_seq = 0
    upload_semaphore = asyncio.Semaphore(MAX_CONCURRENT_UPLOADS)
    background_tasks: set[asyncio.Task[None]] = set()
    cctx = zstd.ZstdCompressor(level=ZSTD_COMPRESSION_LEVEL)

    while True:
        get_task = asyncio.create_task(queue.get())
        wait_task = asyncio.create_task(shutdown_event.wait())

        done, pending = await asyncio.wait(
            [get_task, wait_task], return_when=asyncio.FIRST_COMPLETED
        )

        for p in pending:
            p.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        if wait_task in done:
            break

        chunk = get_task.result()
        if chunk is None:
            break

        compressed = cctx.compress(chunk)
        nonce = nonce_gen.next()
        ciphertext_len = len(compressed) + 16
        header = create_chunk_header(chunk_seq, nonce, ciphertext_len)
        aad = create_aad(header, snapshot_id)
        ciphertext = aesgcm.encrypt(nonce, compressed, aad)

        final_payload = header + ciphertext
        chunk_hash = hashlib.sha256(final_payload).hexdigest()

        await upload_semaphore.acquire()

        async def do_upload(seq: int, payload: bytes, h: str):
            try:
                if not shutdown_event.is_set():
                    await upload_callback(seq, payload, h)
            except Exception:
                shutdown_event.set()
                raise
            finally:
                upload_semaphore.release()

        task = asyncio.create_task(do_upload(chunk_seq, final_payload, chunk_hash))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)

        chunk_seq += 1

    if background_tasks:
        results = await asyncio.gather(*background_tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                shutdown_event.set()
                raise r


async def streaming_pipeline(
    cmd: list[str],
    snapshot_id: str,
    dek: bytes,
    upload_callback,
    shutdown_event: asyncio.Event,
):
    queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=PIPELINE_QUEUE_MAXSIZE)

    reader = asyncio.create_task(read_source(cmd, queue, shutdown_event))
    writer = asyncio.create_task(
        compress_encrypt_upload(
            queue, snapshot_id, dek, upload_callback, shutdown_event
        )
    )

    done, _pending = await asyncio.wait(
        [reader, writer], return_when=asyncio.FIRST_EXCEPTION
    )

    if shutdown_event.is_set():
        for t in [reader, writer]:
            t.cancel()
        return

    for t in done:
        t.result()
