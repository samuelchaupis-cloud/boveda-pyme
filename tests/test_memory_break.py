import asyncio
import os
import sys

import psutil
import pytest

from boveda.constants import MAX_MEMORY_BUDGET_MB
from boveda.engine import streaming_pipeline


@pytest.mark.asyncio
async def test_500mb_streaming_memory_budget():
    """
    Test de rotura de memoria:
    Demuestra que procesar un flujo masivo de 500 MB (generado dinámicamente)
    mantiene el consumo de memoria física (RSS) estrictamente acotado bajo los 45 MB.
    """
    process = psutil.Process(os.getpid())
    peak_rss_mb = 0.0

    # Comando generador de 500MB en streaming (sin almacenar archivo en disco)
    # Escribe 500 bloques de 1MB a stdout
    generator_script = (
        "import sys\n"
        "block = b'X' * (1024 * 1024)\n"
        "for _ in range(500):\n"
        "    sys.stdout.buffer.write(block)\n"
        "sys.stdout.buffer.flush()\n"
    )
    cmd = [sys.executable, "-c", generator_script]

    snapshot_id = "snap-stress-500mb"
    dek = os.urandom(32)
    shutdown_event = asyncio.Event()

    total_chunks = 0
    total_bytes_encrypted = 0

    async def mock_upload_callback(chunk_seq: int, payload: bytes, c_hash: str):
        nonlocal peak_rss_mb, total_chunks, total_bytes_encrypted
        total_chunks += 1
        total_bytes_encrypted += len(payload)

        # Monitorear memoria en tiempo real durante la subida
        current_rss_mb = process.memory_info().rss / (1024 * 1024)
        peak_rss_mb = max(peak_rss_mb, current_rss_mb)

        # Pequeña latencia asíncrona para simular I/O a S3
        await asyncio.sleep(0.001)

    initial_rss_mb = process.memory_info().rss / (1024 * 1024)

    # Ejecutar pipeline completo
    await streaming_pipeline(
        cmd, snapshot_id, dek, mock_upload_callback, shutdown_event
    )

    final_rss_mb = process.memory_info().rss / (1024 * 1024)
    peak_rss_mb = max(peak_rss_mb, final_rss_mb)

    # Verificaciones de invariantes de negocio:
    # 500MB particionados con FastCDC (1MB-4MB por chunk)
    assert 120 <= total_chunks <= 500
    assert total_bytes_encrypted > 0

    # Aserción estricta de Cgroups / Memoria SRE:
    # El delta de memoria o el pico total debe respetar la cota presupuestada de 45MB
    rss_growth_mb = peak_rss_mb - initial_rss_mb
    assert rss_growth_mb < MAX_MEMORY_BUDGET_MB, (
        f"El crecimiento de RAM ({rss_growth_mb:.2f} MB) excedió el presupuesto ({MAX_MEMORY_BUDGET_MB} MB)"
    )
