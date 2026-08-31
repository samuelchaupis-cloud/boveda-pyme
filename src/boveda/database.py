from datetime import datetime

from sqlalchemy import (
    Boolean,
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
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)


class Base(DeclarativeBase):
    pass


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    tipo: Mapped[str] = mapped_column(
        String, nullable=False
    )  # DIARIO, SEMANAL, MENSUAL
    estado: Mapped[str] = mapped_column(String, nullable=False, default="PENDING")
    source_type: Mapped[str] = mapped_column(String, nullable=False)
    source_identifier: Mapped[str] = mapped_column(String, nullable=False)
    total_chunks: Mapped[int | None] = mapped_column(Integer)
    uploaded_chunks: Mapped[int | None] = mapped_column(Integer, default=0)
    size_bytes_raw: Mapped[int | None] = mapped_column(Integer)
    size_bytes_stored: Mapped[int | None] = mapped_column(Integer)
    encrypted_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    dek_tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    multipart_upload_id: Mapped[str | None] = mapped_column(String)
    error_detail: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    bloques: Mapped[list["Bloque"]] = relationship(
        "Bloque", back_populates="snapshot", cascade="all, delete-orphan"
    )


class Bloque(Base):
    __tablename__ = "bloques"
    __table_args__ = (UniqueConstraint("snapshot_id", "chunk_seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_id: Mapped[str] = mapped_column(
        String, ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    chunk_seq: Mapped[int] = mapped_column(Integer, nullable=False)
    hash_sha256: Mapped[str] = mapped_column(String, nullable=False)
    size_compressed: Mapped[int] = mapped_column(Integer, nullable=False)
    size_encrypted: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(String, nullable=False)
    etag: Mapped[str | None] = mapped_column(String)

    snapshot: Mapped["Snapshot"] = relationship("Snapshot", back_populates="bloques")


class Configuracion(Base):
    __tablename__ = "configuracion"

    clave: Mapped[str] = mapped_column(String, primary_key=True)
    valor: Mapped[str] = mapped_column(String, nullable=False)
    es_secreto: Mapped[bool | None] = mapped_column(Boolean, default=False)


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
