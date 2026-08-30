from fastapi import FastAPI

from boveda.database import Bloque, Snapshot, init_db

app = FastAPI(title="Bóveda PyME Dashboard", version="1.0.0")
Session = init_db("snapshots.db")


@app.get("/")
def read_root():
    return {"message": "Bóveda PyME API en línea"}


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
                    "timestamp": s.timestamp.isoformat() if s.timestamp else None,
                    "source": f"{s.source_type}:{s.source_identifier}",
                }
            )
        return result


@app.get("/api/stats")
def get_stats():
    with Session() as session:
        snaps = session.query(Snapshot).filter_by(estado="COMPLETED").count()
        total_blocks = session.query(Bloque).count()
        return {
            "total_snapshots_completed": snaps,
            "total_deduplicated_blocks": total_blocks,
        }
