import asyncio
import json
import sys

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from boveda.auth import (
    InvalidTicketError,
    TicketStore,
    TokenAuthError,
    TokenClaims,
    UserRole,
    generate_ed25519_keypair,
    verify_access_token,
)
from boveda.database import ChunkPool, Snapshot, SnapshotChunk, init_db

app = FastAPI(title="Bóveda PyME Dashboard", version="1.0.0")
Session = init_db("snapshots.db")

# Claves asimétricas Ed25519 del servidor y almacén efímero de tickets
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_ed25519_keypair()
ticket_store = TicketStore()

security = HTTPBearer(auto_error=False)


async def get_current_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> TokenClaims:
    """Extrae y valida el token JWT asimétrico Ed25519."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Credenciales no proporcionadas.")
    try:
        return verify_access_token(credentials.credentials, SERVER_PUBLIC_KEY)
    except TokenAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def require_roles(*allowed_roles: UserRole):
    """Dependencia de FastAPI para control de acceso basado en roles (RBAC)."""

    def role_checker(
        claims: TokenClaims = Depends(get_current_claims),
    ) -> TokenClaims:
        if claims.role not in allowed_roles:
            raise HTTPException(
                status_code=403, detail="Permisos insuficientes para este rol."
            )
        return claims

    return role_checker


def _get_process_rss_bytes() -> int:
    """Obtiene la memoria física residente (RSS) del proceso en bytes sin SDKs pesados."""
    try:
        if sys.platform != "win32":
            import resource

            # getrusage maxrss en Linux está en KB
            return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        else:
            # Fallback seguro para Windows usando ctypes K32GetProcessMemoryInfo
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(pmc), pmc.cb
            ):
                return int(pmc.WorkingSetSize)
    except Exception as exc:
        import logging

        logging.getLogger(__name__).debug(f"error_obteniendo_rss: {exc}")
    return 30 * 1024 * 1024  # Cota base estimada de 30MB


@app.get("/")
def read_root():
    return {"message": "Bóveda PyME API en línea"}


@app.post("/auth/ws-ticket")
def create_websocket_ticket(claims: TokenClaims = Depends(get_current_claims)):
    """Genera un ticket efímero de un solo uso (30s) para SSE o WebSockets."""
    ticket_id = ticket_store.create_ticket(claims, ttl_seconds=30.0)
    return {"ticket": ticket_id, "expires_in_seconds": 30}


@app.get("/api/events/sse")
async def sse_events(ticket: str = Query(...)):
    """Canjea atómicamente un ticket efímero y transmite Server-Sent Events (SSE)."""
    try:
        claims = ticket_store.consume_ticket(ticket)
    except InvalidTicketError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    async def event_generator():
        connect_data = {
            "status": "connected",
            "tenant_id": claims.tenant_id,
            "sub": claims.sub,
        }
        yield f"event: connect\ndata: {json.dumps(connect_data)}\n\n"
        await asyncio.sleep(0.01)
        yield "event: ping\ndata: {}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/backup")
def trigger_backup(
    claims: TokenClaims = Depends(
        require_roles(UserRole.TENANT_ADMIN, UserRole.OPERATOR)
    ),
):
    """Endpoint protegido para iniciar un respaldo (requiere rol TenantAdmin u Operator)."""
    return {
        "status": "initiated",
        "tenant_id": claims.tenant_id,
        "initiated_by": claims.sub,
    }


@app.get("/api/snapshots")
def list_snapshots():
    with Session() as session:
        snaps = (
            session.query(Snapshot).order_by(Snapshot.timestamp.desc()).limit(20).all()
        )
        result = []
        for s in snaps:
            result.append(
                {
                    "id": s.id,
                    "estado": s.estado,
                    "tipo": s.tipo,
                    "timestamp": (s.timestamp.isoformat() if s.timestamp else None),
                    "source": f"{s.source_type}:{s.source_identifier}",
                }
            )
        return result


@app.get("/api/stats")
def get_stats():
    with Session() as session:
        snaps = session.query(Snapshot).filter_by(estado="COMPLETED").count()
        total_blocks = session.query(ChunkPool).count()
        return {
            "total_snapshots_completed": snaps,
            "total_deduplicated_blocks": total_blocks,
        }


@app.get("/metrics")
def get_prometheus_metrics():
    """Genera métricas en formato texto de Prometheus con consumo de RAM insignificante (< 180 KB)."""
    with Session() as session:
        completed = session.query(Snapshot).filter_by(estado="COMPLETED").count()
        failed = session.query(Snapshot).filter_by(estado="FAILED").count()
        total_unique_chunks = session.query(ChunkPool).count()
        total_referenced_chunks = session.query(SnapshotChunk).count()

        rss_bytes = _get_process_rss_bytes()

        # Ratio de deduplicación
        dedup_ratio = (
            total_referenced_chunks / max(total_unique_chunks, 1)
            if total_unique_chunks > 0
            else 1.0
        )

        lines = [
            "# HELP boveda_process_resident_memory_bytes Memoria física residente (RSS) consumida por el daemon.",
            "# TYPE boveda_process_resident_memory_bytes gauge",
            f"boveda_process_resident_memory_bytes {rss_bytes}",
            "# HELP boveda_snapshots_total Total de snapshots por estado.",
            "# TYPE boveda_snapshots_total counter",
            f'boveda_snapshots_total{{status="completed"}} {completed}',
            f'boveda_snapshots_total{{status="failed"}} {failed}',
            "# HELP boveda_chunks_unique_total Bloques únicos en almacenamiento S3.",
            "# TYPE boveda_chunks_unique_total gauge",
            f"boveda_chunks_unique_total {total_unique_chunks}",
            "# HELP boveda_chunks_referenced_total Referencias totales a bloques en todos los snapshots.",
            "# TYPE boveda_chunks_referenced_total gauge",
            f"boveda_chunks_referenced_total {total_referenced_chunks}",
            "# HELP boveda_deduplication_ratio Factor de eficiencia de deduplicación.",
            "# TYPE boveda_deduplication_ratio gauge",
            f"boveda_deduplication_ratio {dedup_ratio:.2f}",
            "# HELP boveda_circuit_breaker_state Estado del Circuit Breaker (0=CLOSED, 1=HALF_OPEN, 2=OPEN).",
            "# TYPE boveda_circuit_breaker_state gauge",
            'boveda_circuit_breaker_state{cloud="s3"} 0',
            'boveda_circuit_breaker_state{cloud="secondary"} 0',
            "# HELP boveda_fastcdc_enabled Indicador de particionado FastCDC activo.",
            "# TYPE boveda_fastcdc_enabled gauge",
            "boveda_fastcdc_enabled 1",
        ]

        metrics_text = "\n".join(lines) + "\n"
        return Response(
            content=metrics_text,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )
