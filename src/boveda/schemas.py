"""Esquemas de validación estricta Pydantic v2 para Bóveda PyME Multi-Tenant."""

import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

TENANT_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,36}$")
SAFE_IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_]{1,63}$")


class StrictBaseModel(BaseModel):
    """Modelo base estricto con inmutabilidad y prohibición de coerción o campos extra."""

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


class TenantContext(StrictBaseModel):
    """Contexto de seguridad e identidad de inquilino."""

    tenant_id: Annotated[
        str,
        Field(
            description="Identificador único del inquilino (alfanumérico, 3-36 caracteres).",
            min_length=3,
            max_length=36,
        ),
    ]

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if not TENANT_ID_REGEX.fullmatch(v):
            raise ValueError(
                "INVARIANTE_VIOLADA: tenant_id debe ser alfanumérico estricto ([a-zA-Z0-9_-]{3,36})."
            )
        return v


class PathContainmentValidator:
    """Validador defensivo contra ataques de Path Traversal."""

    @staticmethod
    def ensure_confined_path(target_path: Path, allowed_base_dir: Path) -> Path:
        resolved_base = allowed_base_dir.resolve()
        resolved_target = target_path.resolve()

        try:
            resolved_target.relative_to(resolved_base)
        except ValueError as exc:
            raise ValueError(
                f"INVARIANTE_VIOLADA: Intento de Path Traversal detectado fuera de {resolved_base}."
            ) from exc
        return resolved_target


class BackupJobRequest(StrictBaseModel):
    """Contrato estricto para solicitudes de respaldo multi-inquilino."""

    tenant: TenantContext
    tipo: Literal["DIARIO", "SEMANAL", "MENSUAL"]
    source_type: Literal["postgres", "mysql", "sqlite"]
    source_identifier: Annotated[str, Field(min_length=1, max_length=128)]
    db_name: Annotated[str, Field(min_length=1, max_length=63)]
    host: Annotated[str, Field(default="localhost", min_length=1, max_length=255)]
    port: Annotated[int, Field(ge=1, le=65535)]
    user: Annotated[str, Field(default="postgres", min_length=1, max_length=63)]

    @field_validator("db_name", "user")
    @classmethod
    def validate_safe_identifiers(cls, v: str) -> str:
        if not SAFE_IDENTIFIER_REGEX.fullmatch(v):
            raise ValueError(
                f"INVARIANTE_VIOLADA: Identificador de base de datos no seguro: {v}"
            )
        return v


class RestoreJobRequest(StrictBaseModel):
    """Contrato estricto para solicitudes de restauración."""

    tenant: TenantContext
    snapshot_id: Annotated[str, Field(min_length=3, max_length=64)]
    destination_file: Annotated[str, Field(min_length=1, max_length=512)]
