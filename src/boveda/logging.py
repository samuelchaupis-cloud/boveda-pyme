"""Módulo de configuración de logging estructurado JSON (structlog) con sanitización de PII."""

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog

# Patrones para ofuscar información sensible y PII
SENSITIVE_KEYS = {
    "passphrase",
    "password",
    "token",
    "secret",
    "authorization",
    "dek",
    "kek",
    "master_salt",
    "encrypted_dek",
}

CONNECTION_STRING_REGEX = re.compile(r"://([^:]+):([^@]+)@")


def redact_pii_and_secrets(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Procesador de structlog que redacta secretos, tokens y credenciales de URLs."""
    for key, value in list(event_dict.items()):
        if any(s in key.lower() for s in SENSITIVE_KEYS):
            event_dict[key] = "[REDACTED]"
        elif isinstance(value, str) and CONNECTION_STRING_REGEX.search(value):
            event_dict[key] = CONNECTION_STRING_REGEX.sub(r"://\1:[REDACTED]@", value)

    return event_dict


def configure_logging(level: int = logging.INFO) -> None:
    """Configura structlog con procesadores estándar y formateador JSON para producción."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            redact_pii_and_secrets,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Retorna un logger estructurado."""
    return structlog.get_logger(name)
