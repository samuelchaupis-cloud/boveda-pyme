"""Suite de pruebas adversariales y de estrés caótico (Chaos Testing)."""

import asyncio

import pytest

from boveda.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)
from boveda.database import (
    ChunkPool,
    ChunkState,
    init_db,
)
from boveda.schemas import RestoreJobRequest, TenantContext


@pytest.mark.asyncio
async def test_chaos_circuit_breaker_high_concurrency_storm():
    """Simula una tormenta de 100 corutinas concurrentes sobre el Circuit Breaker."""
    cb = CircuitBreaker(
        name="s3-storm",
        config=CircuitBreakerConfig(failure_threshold=5, cooldown_seconds=0.1),
    )

    success_count = 0
    failure_count = 0
    circuit_open_count = 0

    async def worker(idx: int):
        nonlocal success_count, failure_count, circuit_open_count
        try:
            if idx % 2 == 0:

                async def flaky_call():
                    if idx < 10:
                        raise ConnectionError("Red inestable")
                    return "ok"

                await cb.call(flaky_call)
                success_count += 1
            else:

                async def slow_call():
                    await asyncio.sleep(0.005)
                    return "ok"

                await cb.call(slow_call)
                success_count += 1
        except CircuitBreakerOpenError:
            circuit_open_count += 1
        except ConnectionError:
            failure_count += 1

    tasks = [worker(i) for i in range(100)]
    await asyncio.gather(*tasks)

    # Invariante: La suma de todos los estados debe ser exactamente 100 sin excepciones colgadas
    assert success_count + failure_count + circuit_open_count == 100
    assert cb.state in (CircuitState.CLOSED, CircuitState.OPEN, CircuitState.HALF_OPEN)


def test_chaos_sqlite_concurrent_write_contention(tmp_path):
    """Prueba 30 transacciones concurrentes con BEGIN IMMEDIATE en SQLite WAL."""
    db_path = str(tmp_path / "chaos_wal.db")
    Session = init_db(db_path)

    import concurrent.futures

    def write_worker(worker_id: int):
        with Session() as session:
            chunk = ChunkPool(
                hash_sha256=f"{worker_id:064x}",
                storage_key=f"chunks/{worker_id}.bin",
                size_compressed=1024,
                size_encrypted=1040,
                ref_count=1,
                state=ChunkState.ACTIVE,
            )
            session.add(chunk)
            session.commit()
            return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(write_worker, i) for i in range(30)]
        results = [f.result() for f in futures]

    assert all(results)
    with Session() as session:
        count = session.query(ChunkPool).count()
        assert count == 30


def test_chaos_schema_path_traversal_fuzzing():
    """Inyecta secuencias de path traversal y caracteres nulos en RestoreJobRequest."""
    malicious_payloads = [
        "../../../../etc/shadow",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
        "/var/data/\x00/exploit",
        "snapshots/../../../root/.ssh/id_rsa",
        "nested/../../../../../../boot.ini",
    ]

    for payload in malicious_payloads:
        with pytest.raises(ValueError):
            RestoreJobRequest(
                tenant=TenantContext(tenant_id="tenant_pyme_safe"),
                snapshot_id="snap-12345",
                destination_file=payload,
            )
