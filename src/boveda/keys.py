"""Módulo de jerarquía de claves, abstracción KeyProvider y rotación atómica de KEK."""

import base64
import logging
import os
from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from boveda.crypto import (
    derive_kek,
    generate_dek_for_snapshot,
    unwrap_dek,
)
from boveda.database import Snapshot

log = logging.getLogger(__name__)


class KeyProviderError(Exception):
    """Error fatal en la obtención o resolución de claves maestras."""


class KeyProvider(ABC):
    """Protocolo base para proveedores de gestión de claves maestras (KEK)."""

    @abstractmethod
    def get_kek(self) -> bytes:
        """Obtiene o deriva la KEK maestra de 256 bits."""

    @abstractmethod
    def get_provider_identifier(self) -> str:
        """Retorna el identificador legible del proveedor de claves."""


class Argon2idKeyProvider(KeyProvider):
    """Proveedor de clave maestra local derivado con Argon2id."""

    def __init__(self, passphrase: str, master_salt_b64: str):
        self._passphrase = passphrase
        self._master_salt_b64 = master_salt_b64
        self._cached_kek: bytes | None = None

    def get_kek(self) -> bytes:
        if self._cached_kek is None:
            self._cached_kek = derive_kek(self._passphrase, self._master_salt_b64)
        return self._cached_kek

    def get_provider_identifier(self) -> str:
        return "local:argon2id"


class AwsKmsKeyProvider(KeyProvider):
    """Proveedor de clave maestra integrado con AWS KMS Envelope Encryption."""

    def __init__(self, key_id: str, kms_client: Any | None = None):
        self._key_id = key_id
        self._kms_client = kms_client
        self._cached_kek: bytes | None = None

    def get_kek(self) -> bytes:
        if self._cached_kek is None:
            if self._kms_client is not None:
                resp = self._kms_client.generate_data_key(
                    KeyId=self._key_id, KeySpec="AES_256"
                )
                self._cached_kek = resp["Plaintext"]
            else:
                env_key = os.environ.get("BOVEDA_KMS_MOCK_KEY")
                if env_key:
                    self._cached_kek = base64.b64decode(env_key)
                else:
                    raise KeyProviderError(
                        f"AWS KMS no configurado ni autenticado para key_id: {self._key_id}"
                    )
        return self._cached_kek

    def get_provider_identifier(self) -> str:
        return f"aws:kms:{self._key_id}"


class VaultTransitKeyProvider(KeyProvider):
    """Proveedor de clave maestra integrado con HashiCorp Vault Transit Engine."""

    def __init__(self, key_name: str, vault_client: Any | None = None):
        self._key_name = key_name
        self._vault_client = vault_client
        self._cached_kek: bytes | None = None

    def get_kek(self) -> bytes:
        if self._cached_kek is None:
            if self._vault_client is not None:
                # Invocación real a Vault transit
                resp = self._vault_client.secrets.transit.generate_data_key(
                    name=self._key_name, key_type="plaintext"
                )
                self._cached_kek = base64.b64decode(resp["data"]["plaintext"])
            else:
                env_key = os.environ.get("BOVEDA_VAULT_MOCK_KEY")
                if env_key:
                    self._cached_kek = base64.b64decode(env_key)
                else:
                    raise KeyProviderError(
                        f"HashiCorp Vault no configurado ni autenticado para key_name: {self._key_name}"
                    )
        return self._cached_kek

    def get_provider_identifier(self) -> str:
        return f"vault:transit:{self._key_name}"


def rotate_kek_in_database(
    session: Session,
    old_kek: bytes,
    new_kek: bytes,
    new_salt_b64: str | None = None,
) -> int:
    """Re-envuelve atómicamente todas las DEKs de snapshots en SQLite con la nueva KEK.

    Se ejecuta bajo BEGIN IMMEDIATE con 0 bytes de transferencia a S3.
    """
    rotated_count = 0

    session.execute(text("BEGIN IMMEDIATE"))
    snapshots = (
        session.query(Snapshot)
        .filter(Snapshot.estado.in_(["COMPLETED", "EXPIRED"]))
        .all()
    )

    for snap in snapshots:
        # 1. Desencriptar DEK con la vieja KEK
        raw_dek = unwrap_dek(
            old_kek,
            snap.encrypted_dek,
            snap.dek_nonce,
            snap.dek_tag,
            snap.id,
        )

        # 2. Re-encriptar DEK con la nueva KEK
        _dek_raw, _new_enc_dek, new_nonce, _new_tag = generate_dek_for_snapshot(
            new_kek, snap.id
        )

        # Envolvemos el raw_dek original (no creamos nueva clave de datos para no invalidar chunks)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(new_kek)
        new_ciphertext = aesgcm.encrypt(new_nonce, raw_dek, snap.id.encode("utf-8"))

        snap.encrypted_dek = new_ciphertext[:-16]
        snap.dek_nonce = new_nonce
        snap.dek_tag = new_ciphertext[-16:]
        rotated_count += 1

    if new_salt_b64:
        from boveda.database import Configuracion

        salt_entry = session.query(Configuracion).filter_by(clave="master_salt").first()
        if salt_entry:
            salt_entry.valor = new_salt_b64

    session.commit()
    log.info("rotacion_kek_completada", extra={"snapshots_rotados": rotated_count})
    return rotated_count
