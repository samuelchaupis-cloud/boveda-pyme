import asyncio
from unittest.mock import AsyncMock

import pytest

from boveda.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    MultiCloudStorageRouter,
    StorageDestination,
)


@pytest.mark.asyncio
async def test_circuit_breaker_initial_state_and_success():
    cb = CircuitBreaker(
        name="test-s3", config=CircuitBreakerConfig(failure_threshold=3)
    )
    assert cb.state == CircuitState.CLOSED

    mock_func = AsyncMock(return_value="ok")
    result = await cb.call(mock_func, "arg1")

    assert result == "ok"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_transition_to_open():
    config = CircuitBreakerConfig(
        failure_threshold=3, failure_window_seconds=10.0, cooldown_seconds=2.0
    )
    cb = CircuitBreaker(name="test-s3", config=config)

    mock_fail = AsyncMock(side_effect=ConnectionError("S3 unreachable"))

    # Primeros 2 fallos: sigue CLOSED
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(mock_fail)
        assert cb.state == CircuitState.CLOSED

    # Tercer fallo: transiciona a OPEN
    with pytest.raises(ConnectionError):
        await cb.call(mock_fail)

    assert cb.state == CircuitState.OPEN

    # Las llamadas subsecuentes deben fallar de inmediato (Fail-Fast)
    mock_ok = AsyncMock(return_value="ok")
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call(mock_ok)

    assert mock_ok.call_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_and_recovery():
    config = CircuitBreakerConfig(
        failure_threshold=2, failure_window_seconds=10.0, cooldown_seconds=0.1
    )
    cb = CircuitBreaker(name="test-s3", config=config)

    mock_fail = AsyncMock(side_effect=ConnectionError("Fail"))
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(mock_fail)
    assert cb.state == CircuitState.OPEN

    # Esperar a que expire el cooldown
    await asyncio.sleep(0.15)

    # Ahora la siguiente llamada debe ponerlo en HALF_OPEN
    mock_success = AsyncMock(return_value="recovered")
    result = await cb.call(mock_success)

    assert result == "recovered"
    # Sonda exitosa debe transicionar de vuelta a CLOSED
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_canary_failure():
    config = CircuitBreakerConfig(
        failure_threshold=2, failure_window_seconds=10.0, cooldown_seconds=0.1
    )
    cb = CircuitBreaker(name="test-s3", config=config)

    mock_fail = AsyncMock(side_effect=ConnectionError("Fail"))
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(mock_fail)
    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(0.15)

    # En HALF_OPEN, si la sonda canaria falla, debe volver a OPEN de inmediato
    with pytest.raises(ConnectionError):
        await cb.call(mock_fail)

    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_multi_cloud_router_failover_cascade():
    # Router con S3 (primario) y R2 (secundario)
    s3_cb = CircuitBreaker(
        name="s3",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=1.0),
    )
    r2_cb = CircuitBreaker(
        name="r2",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=1.0),
    )

    s3_mock = AsyncMock(side_effect=ConnectionError("S3 Down"))
    r2_mock = AsyncMock(return_value="uploaded-to-r2")
    outbox_mock = AsyncMock(return_value="staged-in-outbox")

    router = MultiCloudStorageRouter(
        primary_breaker=s3_cb,
        secondary_breaker=r2_cb,
        primary_uploader=s3_mock,
        secondary_uploader=r2_mock,
        outbox_uploader=outbox_mock,
    )

    # S3 falla -> Router conmuta a R2
    dest, res = await router.upload_chunk("tenant1", "key1", b"payload")
    assert dest == StorageDestination.SECONDARY
    assert res == "uploaded-to-r2"
    assert s3_cb.state == CircuitState.OPEN

    # Ahora R2 también falla -> Router conmuta a Transactional Outbox
    r2_mock.side_effect = ConnectionError("R2 Down")
    dest2, res2 = await router.upload_chunk("tenant1", "key2", b"payload")
    assert dest2 == StorageDestination.OUTBOX
    assert res2 == "staged-in-outbox"
    assert r2_cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_success_in_closed_clears_failures():
    cb = CircuitBreaker(
        name="test-s3", config=CircuitBreakerConfig(failure_threshold=3)
    )
    mock_fail = AsyncMock(side_effect=ConnectionError("Fallo 1"))
    mock_ok = AsyncMock(return_value="ok")

    # 2 fallos (no abre el circuito)
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(mock_fail)
    assert cb.failure_count == 2
    assert cb.state == CircuitState.CLOSED

    # 1 éxito -> DEBE resetear el contador de fallos a 0
    res = await cb.call(mock_ok)
    assert res == "ok"
    assert cb.failure_count == 0

    # 2 fallos subsecuentes no deben abrir el circuito si se reseteó
    for _ in range(2):
        with pytest.raises(ConnectionError):
            await cb.call(mock_fail)
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_cancellation_releases_canary():
    cb = CircuitBreaker(
        name="test-s3",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=0.05),
    )
    mock_fail = AsyncMock(side_effect=ConnectionError("Fail"))
    with pytest.raises(ConnectionError):
        await cb.call(mock_fail)
    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(0.08)

    # Simular una corutina lenta que es cancelada externamente (timeout)
    async def slow_canary():
        await asyncio.sleep(1.0)
        return "slow"

    task = asyncio.create_task(cb.call(slow_canary))
    await asyncio.sleep(0.01)  # Asegurar que el task inicia y toma la sonda
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Tras la cancelación, la sonda canaria debe haberse liberado y reabierto el circuito
    assert not cb.canary_in_flight
    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_concurrent_canaries_blocked():
    cb = CircuitBreaker(
        name="test-s3",
        config=CircuitBreakerConfig(failure_threshold=1, cooldown_seconds=0.05),
    )
    mock_fail = AsyncMock(side_effect=ConnectionError("Fail"))
    with pytest.raises(ConnectionError):
        await cb.call(mock_fail)
    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(0.08)

    # Lanzar sonda lenta
    canary_started = asyncio.Event()

    async def blocking_canary():
        canary_started.set()
        await asyncio.sleep(0.2)
        return "canary-done"

    canary_task = asyncio.create_task(cb.call(blocking_canary))
    await canary_started.wait()

    # Segunda llamada concurrente en HALF_OPEN DEBE ser rechazada de inmediato con CircuitBreakerOpenError
    mock_secondary = AsyncMock(return_value="secondary")
    with pytest.raises(CircuitBreakerOpenError):
        await cb.call(mock_secondary)

    await canary_task
    assert cb.state == CircuitState.CLOSED
