import os
import re
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
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
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
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
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    bloques: Mapped[list["SnapshotChunk"]] = relationship(
        "SnapshotChunk", back_populates="snapshot", cascade="all, delete-orphan"
    )


class ChunkPool(Base):
    __tablename__ = "chunk_pool"

    hash_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    storage_key: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    size_compressed: Mapped[int] = mapped_column(Integer, nullable=False)
    size_encrypted: Mapped[int] = mapped_column(Integer, nullable=False)
    ref_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String, nullable=False, default="ACTIVE")
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    last_referenced_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    purge_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime)

    references: Mapped[list["SnapshotChunk"]] = relationship(
        "SnapshotChunk", back_populates="chunk_entry"
    )


class SnapshotChunk(Base):
    __tablename__ = "snapshot_chunks"

    snapshot_id: Mapped[str] = mapped_column(
        String, ForeignKey("snapshots.id", ondelete="CASCADE"), primary_key=True
    )
    chunk_seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    chunk_hash: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("chunk_pool.hash_sha256", ondelete="RESTRICT"),
        nullable=False,
    )
    etag: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=lambda: datetime.now(UTC)
    )

    snapshot: Mapped["Snapshot"] = relationship("Snapshot", back_populates="bloques")
    chunk_entry: Mapped["ChunkPool"] = relationship(
        "ChunkPool", back_populates="references"
    )

    def __init__(
        self,
        snapshot_id: str | None = None,
        chunk_seq: int | None = None,
        chunk_hash: str | None = None,
        hash_sha256: str | None = None,
        storage_key: str | None = None,
        size_compressed: int | None = None,
        size_encrypted: int | None = None,
        etag: str | None = None,
        created_at: datetime | None = None,
        **kwargs,
    ):
        final_hash = chunk_hash or hash_sha256 or ""
        super().__init__(
            snapshot_id=snapshot_id,
            chunk_seq=chunk_seq,
            chunk_hash=final_hash,
            etag=etag,
            created_at=created_at or datetime.now(UTC),
            **kwargs,
        )
        self._temp_storage_key = storage_key or ""
        self._temp_size_compressed = size_compressed or 0
        self._temp_size_encrypted = size_encrypted or 0

    @property
    def hash_sha256(self) -> str:
        return self.chunk_hash

    @hash_sha256.setter
    def hash_sha256(self, value: str) -> None:
        self.chunk_hash = value

    @property
    def storage_key(self) -> str:
        if self.chunk_entry:
            return self.chunk_entry.storage_key
        return getattr(self, "_temp_storage_key", "")

    @storage_key.setter
    def storage_key(self, value: str) -> None:
        if self.chunk_entry:
            self.chunk_entry.storage_key = value
        self._temp_storage_key = value

    @property
    def size_compressed(self) -> int:
        if self.chunk_entry:
            return self.chunk_entry.size_compressed
        return getattr(self, "_temp_size_compressed", 0)

    @size_compressed.setter
    def size_compressed(self, value: int) -> None:
        if self.chunk_entry:
            self.chunk_entry.size_compressed = value
        self._temp_size_compressed = value

    @property
    def size_encrypted(self) -> int:
        if self.chunk_entry:
            return self.chunk_entry.size_encrypted
        return getattr(self, "_temp_size_encrypted", 0)

    @size_encrypted.setter
    def size_encrypted(self, value: int) -> None:
        if self.chunk_entry:
            self.chunk_entry.size_encrypted = value
        self._temp_size_encrypted = value


# Alias Bloque to SnapshotChunk for backwards compatibility
Bloque = SnapshotChunk


class Configuracion(Base):
    __tablename__ = "configuracion"

    clave: Mapped[str] = mapped_column(String, primary_key=True)
    valor: Mapped[str] = mapped_column(String, nullable=False)
    es_secreto: Mapped[bool | None] = mapped_column(Boolean, default=False)


TRIGGERS_DDL = [
    """
    CREATE TRIGGER IF NOT EXISTS trg_snapshot_chunks_after_insert
    AFTER INSERT ON snapshot_chunks
    FOR EACH ROW
    BEGIN
        UPDATE chunk_pool
        SET 
            ref_count = ref_count + 1,
            state = 'ACTIVE',
            last_referenced_at = strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc'),
            purge_scheduled_at = NULL
        WHERE hash_sha256 = NEW.chunk_hash;
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_snapshot_chunks_after_delete
    AFTER DELETE ON snapshot_chunks
    FOR EACH ROW
    BEGIN
        UPDATE chunk_pool
        SET 
            ref_count = CASE 
                WHEN ref_count > 0 THEN ref_count - 1 
                ELSE 0 
            END,
            state = CASE 
                WHEN ref_count - 1 = 0 THEN 'PENDING_DELETE' 
                ELSE state 
            END,
            purge_scheduled_at = CASE 
                WHEN ref_count - 1 = 0 THEN strftime('%Y-%m-%d %H:%M:%f', 'now', 'utc')
                ELSE purge_scheduled_at 
            END
        WHERE hash_sha256 = OLD.chunk_hash;
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_chunk_pool_prevent_payload_mutation
    BEFORE UPDATE OF hash_sha256, storage_key, size_compressed, size_encrypted ON chunk_pool
    FOR EACH ROW
    BEGIN
        SELECT RAISE(ABORT, 'INVARIANTE_VIOLADA: Los metadatos del chunk son inmutables.');
    END;
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_chunk_pool_prevent_active_delete
    BEFORE DELETE ON chunk_pool
    FOR EACH ROW
    WHEN OLD.ref_count > 0 OR OLD.state = 'ACTIVE'
    BEGIN
        SELECT RAISE(ABORT, 'INVARIANTE_VIOLADA: Prohibido eliminar chunk activo o con ref_count > 0.');
    END;
    """,
]


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
    with engine.connect() as conn:
        for trigger_sql in TRIGGERS_DDL:
            conn.execute(text(trigger_sql))
        conn.commit()
    return sessionmaker(bind=engine)


def get_tenant_db_path(tenant_id: str, base_dir: str = "data/tenants") -> str:
    """Genera la ruta segura al archivo SQLite específico del inquilino (Database-per-Tenant)."""
    sanitized_id = re.sub(r"[^a-zA-Z0-9_-]", "", tenant_id)
    if not sanitized_id:
        raise ValueError("Identificador de inquilino inválido o vacío")
    tenant_dir = os.path.join(base_dir, sanitized_id)
    os.makedirs(tenant_dir, exist_ok=True)
    return os.path.join(tenant_dir, "snapshots.db")


def get_tenant_session_factory(
    tenant_id: str, base_dir: str = "data/tenants"
) -> sessionmaker:
    """Retorna una fábrica de sesiones SQLAlchemy inicializada para el inquilino específico."""
    db_path = get_tenant_db_path(tenant_id, base_dir=base_dir)
    return init_db(db_path)
