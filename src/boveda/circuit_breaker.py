"""Máquina de estados de Circuit Breaker y enrutador Multi-Cloud con failover en cascada."""

import asyncio
import time
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import Field

from boveda.schemas import StrictBaseModel


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class StorageDestination(StrEnum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    OUTBOX = "OUTBOX"


class CircuitBreakerOpenError(Exception):
    """Excepción lanzada cuando el Circuit Breaker está en estado OPEN y rechaza peticiones."""


class CircuitBreakerConfig(StrictBaseModel):
    """Configuración inmutable del Circuit Breaker."""

    failure_threshold: int = Field(default=3, ge=1, le=20)
    failure_window_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    cooldown_seconds: float = Field(default=60.0, gt=0.0, le=600.0)
    half_open_success_threshold: int = Field(default=1, ge=1, le=5)


class CircuitBreaker:
    """FSM asíncrona y atómica para Circuit Breakers con sondeo canario."""

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None) -> None:
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self._state: CircuitState = CircuitState.CLOSED
        self._lock = asyncio.Lock()
        self._failure_timestamps: deque[float] = deque()
        self._opened_at: float = 0.0
        self._consecutive_successes: int = 0
        self._canary_in_flight: bool = False

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return len(self._failure_timestamps)

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Ejecuta una corutina a través del Circuit Breaker con conmutación de estado atómica."""
        async with self._lock:
            now = time.monotonic()

            # Evaluación de transición por Cooldown de OPEN -> HALF_OPEN
            if self._state == CircuitState.OPEN:
                if (now - self._opened_at) >= self.config.cooldown_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._consecutive_successes = 0
                    self._canary_in_flight = False
                else:
                    raise CircuitBreakerOpenError(
                        f"CircuitBreaker '{self.name}' está OPEN. Tiempo restante de cooldown: {self.config.cooldown_seconds - (now - self._opened_at):.1f}s"
                    )

            # En HALF_OPEN, solo 1 sonda canaria concurrente es permitida
            if self._state == CircuitState.HALF_OPEN:
                if self._canary_in_flight:
                    raise CircuitBreakerOpenError(
                        f"CircuitBreaker '{self.name}' está HALF_OPEN con sonda canaria en tránsito."
                    )
                self._canary_in_flight = True

        try:
            # Ejecución fuera del cerrojo para no bloquear otras corutinas en CLOSED
            result = await func(*args, **kwargs)
            await self._record_success()
            return result
        except Exception:
            await self._record_failure()
            raise

    async def _record_success(self) -> None:
        """Registra una ejecución exitosa."""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._canary_in_flight = False
                self._consecutive_successes += 1
                if (
                    self._consecutive_successes
                    >= self.config.half_open_success_threshold
                ):
                    self._state = CircuitState.CLOSED
                    self._failure_timestamps.clear()
                    self._consecutive_successes = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_timestamps.clear()

    async def _record_failure(self) -> None:
        """Registra una falla y evalúa transiciones a OPEN."""
        async with self._lock:
            now = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Si falla la sonda canaria, vuelve a OPEN inmediatamente
                self._canary_in_flight = False
                self._state = CircuitState.OPEN
                self._opened_at = now
                self._consecutive_successes = 0
                return

            if self._state == CircuitState.CLOSED:
                # Purgar timestamps fuera de la ventana rodante
                cutoff = now - self.config.failure_window_seconds
                while self._failure_timestamps and self._failure_timestamps[0] < cutoff:
                    self._failure_timestamps.popleft()

                self._failure_timestamps.append(now)

                if len(self._failure_timestamps) >= self.config.failure_threshold:
                    self._state = CircuitState.OPEN
                    self._opened_at = now


class MultiCloudStorageRouter:
    """Enrutador de almacenamiento con failover en cascada entre nubes y Outbox local."""

    def __init__(
        self,
        primary_breaker: CircuitBreaker,
        secondary_breaker: CircuitBreaker,
        primary_uploader: Callable[..., Any],
        secondary_uploader: Callable[..., Any],
        outbox_uploader: Callable[..., Any],
    ) -> None:
        self.primary_breaker = primary_breaker
        self.secondary_breaker = secondary_breaker
        self.primary_uploader = primary_uploader
        self.secondary_uploader = secondary_uploader
        self.outbox_uploader = outbox_uploader

    async def upload_chunk(
        self,
        tenant_id: str,
        storage_key: str,
        payload: bytes,
        *args: Any,
        **kwargs: Any,
    ) -> tuple[StorageDestination, Any]:
        """Intenta subir al primario; si falla, al secundario; si ambos fallan, al Outbox."""
        # 1. Intentar primario (AWS S3)
        try:
            res = await self.primary_breaker.call(
                self.primary_uploader,
                tenant_id,
                storage_key,
                payload,
                *args,
                **kwargs,
            )
            return (StorageDestination.PRIMARY, res)
        except Exception:
            pass

        # 2. Intentar secundario (Cloudflare R2 / Backblaze B2)
        try:
            res = await self.secondary_breaker.call(
                self.secondary_uploader,
                tenant_id,
                storage_key,
                payload,
                *args,
                **kwargs,
            )
            return (StorageDestination.SECONDARY, res)
        except Exception:
            pass

        # 3. Degradar a Transactional Outbox (Persistencia local en staging)
        res = await self.outbox_uploader(
            tenant_id, storage_key, payload, *args, **kwargs
        )
        return (StorageDestination.OUTBOX, res)
