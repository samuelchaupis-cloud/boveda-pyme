from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    create_engine,
    event,
    text,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class Snapshot(Base):
    __tablename__ = "snapshots"

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    tipo = Column(String, nullable=False)  # DIARIO, SEMANAL, MENSUAL
    estado = Column(String, nullable=False, default="PENDING")
    source_type = Column(String, nullable=False)
    source_identifier = Column(String, nullable=False)
    total_chunks = Column(Integer)
    uploaded_chunks = Column(Integer, default=0)
    size_bytes_raw = Column(Integer)
    size_bytes_stored = Column(Integer)
    encrypted_dek = Column(LargeBinary, nullable=False)
    dek_nonce = Column(LargeBinary, nullable=False)
    dek_tag = Column(LargeBinary, nullable=False)
    multipart_upload_id = Column(String)
    error_detail = Column(String)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime)

    bloques = relationship(
        "Bloque", back_populates="snapshot", cascade="all, delete-orphan"
    )


class Bloque(Base):
    __tablename__ = "bloques"
    __table_args__ = (UniqueConstraint("snapshot_id", "chunk_seq"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(
        String, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    chunk_seq = Column(Integer, nullable=False)
    hash_sha256 = Column(String, nullable=False)
    size_compressed = Column(Integer, nullable=False)
    size_encrypted = Column(Integer, nullable=False)
    storage_key = Column(String, nullable=False)
    etag = Column(String)

    snapshot = relationship("Snapshot", back_populates="bloques")


class Configuracion(Base):
    __tablename__ = "configuracion"

    clave = Column(String, primary_key=True)
    valor = Column(String, nullable=False)
    es_secreto = Column(Boolean, default=False)


def get_engine(db_path: str):
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"timeout": 15}, pool_pre_ping=True
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragmas(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

    return engine


def verify_db_integrity(session):
    result = session.execute(text("PRAGMA integrity_check")).scalar()
    if result != "ok":
        raise ValueError(f"bd_corrupta: {result}")


def init_db(db_path: str):
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
