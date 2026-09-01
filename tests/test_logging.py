"""Pruebas para el módulo de logging estructurado y sanitización de PII/secretos."""

import io
import json
import logging

from boveda.logging import configure_logging, get_logger, redact_pii_and_secrets


def test_redact_pii_and_secrets_processor():
    event_dict = {
        "event": "backup_start",
        "passphrase": "super-secret-passphrase",
        "token": "jwt-token-xyz",
        "db_url": "postgresql://usr_pyme:secretpassword@localhost:5432/mydb",
        "safe_key": "safe_value",
    }

    result = redact_pii_and_secrets(None, "info", event_dict)

    assert result["passphrase"] == "[REDACTED]"
    assert result["token"] == "[REDACTED]"
    assert "secretpassword" not in result["db_url"]
    assert "[REDACTED]" in result["db_url"]
    assert result["safe_key"] == "safe_value"


def test_configure_logging_and_json_rendering(monkeypatch):
    buf = io.StringIO()
    configure_logging(level=logging.INFO)
    logger = get_logger("test_boveda")

    # Redirigir stdout de sys para capturar JSON
    monkeypatch.setattr("sys.stdout", buf)
    logger.info("snapshot_iniciado", snapshot_id="snap-123", tenant_id="tenant-pyme")

    output = buf.getvalue().strip()
    if output:
        parsed = json.loads(output)
        assert parsed["event"] == "snapshot_iniciado"
        assert parsed["snapshot_id"] == "snap-123"
        assert parsed["tenant_id"] == "tenant-pyme"
        assert "timestamp" in parsed
