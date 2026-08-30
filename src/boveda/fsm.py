from boveda.database import Snapshot

VALID_TRANSITIONS = {
    "PENDING": {"RUNNING"},
    "RUNNING": {"COMPLETED", "FAILED"},
    "COMPLETED": {"EXPIRED"},
    "EXPIRED": {"PURGING"},
    "PURGING": {"PURGED", "PURGE_FAILED"},
    "PURGE_FAILED": {"PURGING"},
    "FAILED": {"CLEANUP"},
    "CLEANUP": {"PURGED"},
}


class FSMError(Exception):
    pass


def transition_snapshot(snapshot: Snapshot, new_estado: str):
    if new_estado not in VALID_TRANSITIONS.get(snapshot.estado, set()):
        raise FSMError(f"Transición no permitida: {snapshot.estado} -> {new_estado}")
    snapshot.estado = new_estado
