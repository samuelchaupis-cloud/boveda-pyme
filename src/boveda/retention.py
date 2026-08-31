import logging
from collections.abc import Callable
from datetime import datetime, timedelta

import dateutil.relativedelta

from boveda.database import ChunkPool, Snapshot, SnapshotChunk

log = logging.getLogger(__name__)

RETENTION_DAILY = 7
RETENTION_WEEKLY = 4
RETENTION_MONTHLY = 12


def classify_snapshots(snapshots: list[Snapshot], now: datetime) -> list[Snapshot]:
    protected: set[str] = set()

    # Monthly
    for month_offset in range(RETENTION_MONTHLY):
        target = now - dateutil.relativedelta.relativedelta(months=month_offset)
        in_month = [
            s
            for s in snapshots
            if s.timestamp.year == target.year and s.timestamp.month == target.month
        ]
        if in_month:
            in_month.sort(key=lambda s: s.timestamp)
            protected.add(in_month[0].id)

    # Weekly
    for week_offset in range(RETENTION_WEEKLY):
        target = now - timedelta(weeks=week_offset)
        iso_year, iso_week, _ = target.isocalendar()
        in_week = [
            s
            for s in snapshots
            if s.timestamp.isocalendar()[:2] == (iso_year, iso_week)
        ]
        if in_week:
            in_week.sort(key=lambda s: s.timestamp)
            protected.add(in_week[-1].id)

    # Daily
    cutoff_daily = now - timedelta(days=RETENTION_DAILY)
    for snap in snapshots:
        if snap.timestamp >= cutoff_daily:
            protected.add(snap.id)

    return [s for s in snapshots if s.id not in protected and s.estado == "COMPLETED"]


def execute_two_phase_purge(
    session, delete_objects_callback: Callable[[list[str]], None], batch_size: int = 500
) -> int:
    """Ejecuta la purga física en S3 y SQLite con cerrojo de dos fases sin retención de bloqueos durante I/O."""
    purged_count = 0

    # Fase 1: Identificar chunks huérfanos con ref_count = 0 en PENDING_DELETE
    orphans = (
        session.query(ChunkPool)
        .filter(ChunkPool.ref_count == 0, ChunkPool.state == "PENDING_DELETE")
        .limit(batch_size)
        .all()
    )

    if not orphans:
        return 0

    chunks_to_purge = [(c.hash_sha256, c.storage_key) for c in orphans]
    for c_hash, _ in chunks_to_purge:
        session.query(ChunkPool).filter_by(hash_sha256=c_hash, ref_count=0).update(
            {"state": "PURGING_S3"}
        )
    session.commit()

    # Fase Intermedia: I/O de red hacia S3 (SIN RETENER BLOQUEO DE BASE DE DATOS)
    storage_keys = [s_key for _, s_key in chunks_to_purge]
    s3_success = False
    try:
        if storage_keys:
            delete_objects_callback(storage_keys)
        s3_success = True
    except Exception as exc:
        log.error(f"Fallo en llamada delete_objects hacia S3: {exc}")

    # Fase 2: Confirmación o reversión en SQLite
    if s3_success:
        for c_hash, _ in chunks_to_purge:
            session.query(ChunkPool).filter(
                ChunkPool.hash_sha256 == c_hash,
                ChunkPool.state == "PURGING_S3",
                ChunkPool.ref_count == 0,
            ).delete()
            purged_count += 1
        session.commit()
    else:
        for c_hash, _ in chunks_to_purge:
            session.query(ChunkPool).filter_by(
                hash_sha256=c_hash, state="PURGING_S3"
            ).update({"state": "PENDING_DELETE"})
        session.commit()

    return purged_count


def purge_expired_snapshots(
    session, delete_objects_callback: Callable[[list[str]], None]
):
    expired = session.query(Snapshot).filter(Snapshot.estado == "EXPIRED").all()

    for snap in expired:
        snap.estado = "PURGING"
        session.commit()

        try:
            # 1. Desvincular chunks en snapshot_chunks (los triggers SQLite decrementan ref_count)
            session.query(SnapshotChunk).filter(
                SnapshotChunk.snapshot_id == snap.id
            ).delete()
            session.delete(snap)
            session.commit()

            # 2. Ejecutar Two-Phase Purge para los chunks cuyo ref_count llegó a 0
            execute_two_phase_purge(session, delete_objects_callback)

        except Exception as e:
            session.rollback()
            snap = session.get(Snapshot, snap.id)
            if snap:
                snap.estado = "PURGE_FAILED"
                snap.error_detail = str(e)[:500]
                session.commit()
            log.error(f"purga_fallida {snap.id if snap else 'desconocido'}: {e}")
