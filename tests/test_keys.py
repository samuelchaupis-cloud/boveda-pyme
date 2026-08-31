from unittest.mock import MagicMock

import pytest

from boveda.crypto import (
    derive_kek,
    generate_dek_for_snapshot,
    generate_master_salt,
    unwrap_dek,
)
from boveda.database import Snapshot, init_db
from boveda.keys import (
    Argon2idKeyProvider,
    AwsKmsKeyProvider,
    VaultTransitKeyProvider,
    rotate_kek_in_database,
)


def test_argon2id_key_provider():
    salt_b64 = generate_master_salt()
    provider = Argon2idKeyProvider("passphrase123", salt_b64)
    kek = provider.get_kek()
    assert len(kek) == 32
    assert provider.get_kek() == kek  # Caching
    assert provider.get_provider_identifier() == "local:argon2id"


def test_aws_kms_key_provider(monkeypatch):
    mock_kms = MagicMock()
    mock_kms.generate_data_key.return_value = {"Plaintext": b"1" * 32}

    provider = AwsKmsKeyProvider("arn:aws:kms:key/123", mock_kms)
    kek = provider.get_kek()
    assert kek == b"1" * 32
    assert provider.get_provider_identifier() == "aws:kms:arn:aws:kms:key/123"

    # Environment mock key
    import base64

    monkeypatch.setenv(
        "BOVEDA_KMS_MOCK_KEY", base64.b64encode(b"2" * 32).decode("utf-8")
    )
    provider_env = AwsKmsKeyProvider("key-env")
    assert provider_env.get_kek() == b"2" * 32

    # Error without client or env
    monkeypatch.delenv("BOVEDA_KMS_MOCK_KEY")
    from boveda.keys import KeyProviderError

    provider_err = AwsKmsKeyProvider("key-xyz")
    with pytest.raises(KeyProviderError, match="AWS KMS no configurado"):
        provider_err.get_kek()


def test_vault_transit_key_provider(monkeypatch):
    mock_vault = MagicMock()
    import base64

    b64_32 = base64.b64encode(b"v" * 32).decode("utf-8")
    mock_vault.secrets.transit.generate_data_key.return_value = {
        "data": {"plaintext": b64_32}
    }

    provider = VaultTransitKeyProvider("boveda-master-key", mock_vault)
    kek = provider.get_kek()
    assert len(kek) == 32
    assert provider.get_provider_identifier() == "vault:transit:boveda-master-key"

    # Error without client or env
    from boveda.keys import KeyProviderError

    monkeypatch.delenv("BOVEDA_VAULT_MOCK_KEY", raising=False)
    provider_err = VaultTransitKeyProvider("vault-unconfigured")
    with pytest.raises(KeyProviderError, match="HashiCorp Vault no configurado"):
        provider_err.get_kek()


def test_rotate_kek_in_database(tmp_path):
    db_path = str(tmp_path / "test_rotate.db")
    Session = init_db(db_path)
    session = Session()

    salt_old = generate_master_salt()
    old_kek = derive_kek("old_passphrase", salt_old)

    # Crear 3 snapshots cifrados con old_kek
    raw_deks = {}
    for i in range(3):
        snap_id = f"snap-{i}"
        raw_dek, enc_dek, nonce, tag = generate_dek_for_snapshot(old_kek, snap_id)
        raw_deks[snap_id] = raw_dek

        s = Snapshot(
            id=snap_id,
            tipo="DIARIO",
            source_type="file",
            source_identifier="/data",
            encrypted_dek=enc_dek,
            dek_nonce=nonce,
            dek_tag=tag,
            estado="COMPLETED",
        )
        session.add(s)
    session.commit()

    salt_new = generate_master_salt()
    new_kek = derive_kek("new_passphrase", salt_new)

    rotated_count = rotate_kek_in_database(session, old_kek, new_kek, salt_new)
    assert rotated_count == 3

    # Verificar que los 3 snapshots se puedan desencriptar con new_kek y recuperen el DEK original
    for snap_id, original_raw_dek in raw_deks.items():
        snap = session.get(Snapshot, snap_id)
        assert snap is not None

        recovered_dek = unwrap_dek(
            new_kek,
            snap.encrypted_dek,
            snap.dek_nonce,
            snap.dek_tag,
            snap.id,
        )
        assert recovered_dek == original_raw_dek

    session.close()
    Session.kw["bind"].dispose()
