import logging
from datetime import datetime, timedelta

import dateutil.relativedelta

from boveda.database import Bloque, Snapshot

log = logging.getLogger(__name__)

RETENTION_DAILY = 7
RETENTION_WEEKLY = 4
RETENTION_MONTHLY = 12


def classify_snapshots(snapshots: list[Snapshot], now: datetime) -> list[Snapshot]:
    protected: set[str] = set()

    # Monthly
    for month_offset in range(RETENTION_MONTHLY):
        # We need the target month
        target = now - dateutil.relativedelta.relativedelta(months=month_offset)
        # Find all snapshots in that month/year
        in_month = [
            s
            for s in snapshots
            if s.timestamp.year == target.year and s.timestamp.month == target.month
        ]
        if in_month:
            # First of month
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
            # Last of week
            in_week.sort(key=lambda s: s.timestamp)
            protected.add(in_week[-1].id)

    # Daily
    cutoff_daily = now - timedelta(days=RETENTION_DAILY)
    for snap in snapshots:
        if snap.timestamp >= cutoff_daily:
            protected.add(snap.id)

    return [s for s in snapshots if s.id not in protected and s.estado == "COMPLETED"]


def purge_expired_snapshots(session, delete_objects_callback):
    expired = session.query(Snapshot).filter(Snapshot.estado == "EXPIRED").all()

    for snap in expired:
        snap.estado = "PURGING"
        session.commit()

        try:
            bloques = session.query(Bloque).filter(Bloque.snapshot_id == snap.id).all()

            keys_list = [bloque.storage_key for bloque in bloques]
            if keys_list:
                delete_objects_callback(keys_list)

            session.query(Bloque).filter(Bloque.snapshot_id == snap.id).delete()
            session.delete(snap)
            session.commit()

        except Exception as e:  # noqa: BLE001
            session.rollback()
            # Fetch again since rollback detaches
            snap = session.query(Snapshot).get(snap.id)
            snap.estado = "PURGE_FAILED"
            snap.error_detail = str(e)[:500]
            session.commit()
            log.error(f"purga_fallida {snap.id}: {e}")
