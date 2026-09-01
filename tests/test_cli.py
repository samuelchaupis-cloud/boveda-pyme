import sys
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from boveda.cli import main
from boveda.database import (
    Configuracion,
    Snapshot,
    SnapshotChunk,
    init_db,
)


def test_cli_init_and_list(tmp_path):
    db_path = str(tmp_path / "cli_test.db")
    runner = CliRunner()

    result = runner.invoke(main, ["init", "--db", db_path])
    assert result.exit_code == 0
    assert "Inicialización completa" in result.output

    result_second = runner.invoke(main, ["init", "--db", db_path])
    assert result_second.exit_code == 0
    assert "ya se encuentra inicializada" in result_second.output

    result_list = runner.invoke(main, ["list", "--db", db_path])
    assert result_list.exit_code == 0
    assert "No se encontraron snapshots" in result_list.output


def test_cli_restore_errors(tmp_path):
    db_path = str(tmp_path / "cli_test.db")
    runner = CliRunner()

    # Missing DB init
    out_file = str(tmp_path / "restored.bin")
    result = runner.invoke(
        main, ["restore", "non-existent", "--out", out_file, "--db", db_path]
    )
    assert "no existe o no está COMPLETED" in result.output


def test_cli_backup_missing_env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "cli_test.db")
    runner = CliRunner()
    runner.invoke(main, ["init", "--db", db_path])

    monkeypatch.delenv("BOVEDA_PASSPHRASE", raising=False)
    monkeypatch.delenv("S3_BUCKET", raising=False)

    result = runner.invoke(
        main, ["backup", "--db", db_path, "--source", "test-src", "--cmd", "echo test"]
    )
    assert "Se requieren las variables de entorno" in result.output


def test_cli_backup_and_restore_workflow(tmp_path, monkeypatch):
    db_path = str(tmp_path / "cli_test.db")
    runner = CliRunner()
    runner.invoke(main, ["init", "--db", db_path])

    monkeypatch.setenv("BOVEDA_PASSPHRASE", "test-passphrase-12345")
    monkeypatch.setenv("S3_BUCKET", "test-bucket")

    s3_storage = {}

    with patch("aioboto3.Session") as mock_aioboto:
        mock_client = AsyncMock()

        async def mock_upload(Bucket, Key, Body):
            s3_storage[Key] = Body

        mock_client.put_object.side_effect = mock_upload
        mock_client.head_object.side_effect = lambda Bucket, Key: {
            "ContentLength": len(s3_storage.get(Key, b""))
        }
        mock_client.delete_objects = AsyncMock()

        mock_aioboto.return_value.client.return_value.__aenter__.return_value = (
            mock_client
        )

        # Backup 1
        cmd = f"{sys.executable} -c \"import sys; sys.stdout.write('test_data_stream\\n')\""
        result = runner.invoke(
            main, ["backup", "--db", db_path, "--source", "test-src", "--cmd", cmd]
        )
        assert result.exit_code == 0
        assert "Backup completado" in result.output

        # Backup 2 (Deduplication test on same stream)
        result_dedup = runner.invoke(
            main, ["backup", "--db", db_path, "--source", "test-src", "--cmd", cmd]
        )
        assert result_dedup.exit_code == 0

    Session = init_db(db_path)
    with Session() as session:
        snaps = session.query(Snapshot).filter_by(estado="COMPLETED").all()
        assert len(snaps) == 2
        snapshot_id = snaps[0].id

    result_list = runner.invoke(main, ["list", "--db", db_path])
    assert snapshot_id in result_list.output

    # Verify tests
    res_verify_no_flag = runner.invoke(main, ["verify", snapshot_id, "--db", db_path])
    assert "Debes especificar --quick o --full" in res_verify_no_flag.output

    # Quick verify
    with patch("aioboto3.Session") as mock_aioboto:
        mock_client = AsyncMock()
        with Session() as session:
            b = session.query(SnapshotChunk).filter_by(snapshot_id=snapshot_id).first()
            actual_len = len(s3_storage[b.storage_key]) if b else 100
        mock_client.head_object = AsyncMock(return_value={"ContentLength": actual_len})
        mock_aioboto.return_value.client.return_value.__aenter__.return_value = (
            mock_client
        )

        res_quick = runner.invoke(
            main, ["verify", snapshot_id, "--quick", "--db", db_path]
        )
        assert res_quick.exit_code == 0

    # Full verify
    with patch("aioboto3.Session") as mock_aioboto:
        mock_client = AsyncMock()
        with Session() as session:
            b = session.query(SnapshotChunk).filter_by(snapshot_id=snapshot_id).first()
            mock_body = AsyncMock()
            mock_body.read.return_value = s3_storage[b.storage_key] if b else b""

        mock_client.get_object = AsyncMock(return_value={"Body": mock_body})
        mock_aioboto.return_value.client.return_value.__aenter__.return_value = (
            mock_client
        )

        res_full = runner.invoke(
            main,
            ["verify", snapshot_id, "--full", "--db", db_path],
            input="test-passphrase-12345\n",
        )
        assert res_full.exit_code == 0


def test_cli_daemon_invocation():
    runner = CliRunner()
    with patch("subprocess.run") as mock_sub:
        result = runner.invoke(main, ["daemon"])
        assert result.exit_code == 0
        assert mock_sub.called


def test_cli_rotate_kek(tmp_path):
    db_path = str(tmp_path / "cli_rotate.db")
    runner = CliRunner()
    init_res = runner.invoke(main, ["init", "--db", db_path])
    assert init_res.exit_code == 0

    # Poblar 2 snapshots reales cifrados con old_pass
    Session = init_db(db_path)
    with Session() as session:
        from boveda.crypto import (
            derive_kek,
            generate_dek_for_snapshot,
            unwrap_dek,
        )

        salt_conf = session.query(Configuracion).filter_by(clave="master_salt").first()
        assert salt_conf is not None
        old_salt_val = str(salt_conf.valor)
        old_kek = derive_kek("old_pass", old_salt_val)

        dek_raw1, enc1, nonce1, tag1 = generate_dek_for_snapshot(old_kek, "snap-rot-1")
        dek_raw2, enc2, nonce2, tag2 = generate_dek_for_snapshot(old_kek, "snap-rot-2")

        s1 = Snapshot(
            id="snap-rot-1",
            estado="COMPLETED",
            tipo="DIARIO",
            source_type="cmd",
            source_identifier="db1",
            encrypted_dek=enc1,
            dek_nonce=nonce1,
            dek_tag=tag1,
            timestamp=datetime.now(UTC),
        )
        s2 = Snapshot(
            id="snap-rot-2",
            estado="COMPLETED",
            tipo="SEMANAL",
            source_type="cmd",
            source_identifier="db2",
            encrypted_dek=enc2,
            dek_nonce=nonce2,
            dek_tag=tag2,
            timestamp=datetime.now(UTC),
        )
        session.add_all([s1, s2])
        session.commit()

    # Ejecutar comando rotate-kek
    result = runner.invoke(
        main,
        ["rotate-kek", "--db", db_path],
        input="old_pass\nnew_pass\n",
    )
    assert result.exit_code == 0
    assert "Rotación de KEK completada con éxito" in result.output
    assert "Snapshots re-envueltos: 2" in result.output

    # Validar que los DEKs se pueden descifrar con new_pass y coinciden exactamente con dek_raw
    with Session() as session:
        salt_new = session.query(Configuracion).filter_by(clave="master_salt").first()
        assert salt_new is not None
        assert salt_new.valor != old_salt_val  # Salt debe haber rotado
        new_kek = derive_kek("new_pass", salt_new.valor)

        snap1_after = session.get(Snapshot, "snap-rot-1")
        assert snap1_after is not None
        unwrapped1 = unwrap_dek(
            new_kek,
            snap1_after.encrypted_dek,
            snap1_after.dek_nonce,
            snap1_after.dek_tag,
            "snap-rot-1",
        )
        assert unwrapped1 == dek_raw1

        snap2_after = session.get(Snapshot, "snap-rot-2")
        assert snap2_after is not None
        unwrapped2 = unwrap_dek(
            new_kek,
            snap2_after.encrypted_dek,
            snap2_after.dek_nonce,
            snap2_after.dek_tag,
            "snap-rot-2",
        )
        assert unwrapped2 == dek_raw2
