import pytest
from pydantic import ValidationError

from boveda.schemas import (
    BackupJobRequest,
    PathContainmentValidator,
    RestoreJobRequest,
    TenantContext,
)


def test_tenant_context_valid():
    ctx = TenantContext(tenant_id="pyme_corp_01")
    assert ctx.tenant_id == "pyme_corp_01"


@pytest.mark.parametrize(
    "invalid_id",
    [
        "ab",  # Demasiado corto (<3)
        "a" * 37,  # Demasiado largo (>36)
        "tenant/../../root",  # Path Traversal
        "tenant; DROP TABLE",  # SQL Injection
        "tenant$id",  # Caracter especial
        "tenant space",  # Espacio en blanco
    ],
)
def test_tenant_context_invalid(invalid_id):
    with pytest.raises(ValidationError):
        TenantContext(tenant_id=invalid_id)


def test_backup_job_request_valid():
    req = BackupJobRequest(
        tenant=TenantContext(tenant_id="acme_tenant"),
        tipo="DIARIO",
        source_type="postgres",
        source_identifier="prod_db_instance",
        db_name="crm_production",
        host="db.internal.lan",
        port=5432,
        user="backup_svc",
    )
    assert req.db_name == "crm_production"
    assert req.port == 5432


@pytest.mark.parametrize(
    "bad_db_name",
    [
        "db; DROP TABLE users;",
        "db name with spaces",
        "db/with/slashes",
        "db--injection",
    ],
)
def test_backup_job_request_injection_rejection(bad_db_name):
    with pytest.raises(ValidationError):
        BackupJobRequest(
            tenant=TenantContext(tenant_id="acme_tenant"),
            tipo="DIARIO",
            source_type="postgres",
            source_identifier="prod_db_instance",
            db_name=bad_db_name,
            host="localhost",
            port=5432,
            user="postgres",
        )


def test_path_containment_validator(tmp_path):
    base_dir = tmp_path / "safe_zone"
    base_dir.mkdir()

    safe_file = base_dir / "backups" / "dump.sql"
    safe_file.parent.mkdir()
    safe_file.touch()

    # Camino dentro del directorio permitido
    resolved = PathContainmentValidator.ensure_confined_path(safe_file, base_dir)
    assert resolved == safe_file.resolve()

    # Intento de Path Traversal
    unsafe_file = tmp_path / "system_file.txt"
    unsafe_file.touch()

    with pytest.raises(ValueError, match="Intento de Path Traversal detectado"):
        PathContainmentValidator.ensure_confined_path(unsafe_file, base_dir)


def test_restore_job_request_valid():
    req = RestoreJobRequest(
        tenant=TenantContext(tenant_id="tenant_01"),
        snapshot_id="snap-20260831-abcd",
        destination_file="/tmp/restore.sql",
    )
    assert req.snapshot_id == "snap-20260831-abcd"
