import hashlib
import sys
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from boveda.cli import main
from boveda.database import Bloque, Snapshot, init_db


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
        cmd = f'{sys.executable} -c print("test_data_stream")'
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
        mock_client.head_object = AsyncMock(return_value={"ContentLength": 26 + 100})
        mock_aioboto.return_value.client.return_value.__aenter__.return_value = (
            mock_client
        )

        with Session() as session:
            b = session.query(Bloque).filter_by(snapshot_id=snapshot_id).first()
            b.size_encrypted = 100
            session.commit()

        res_quick = runner.invoke(
            main, ["verify", snapshot_id, "--quick", "--db", db_path]
        )
        assert res_quick.exit_code == 0

    # Full verify
    with patch("aioboto3.Session") as mock_aioboto:
        mock_client = AsyncMock()
        with Session() as session:
            b = session.query(Bloque).filter_by(snapshot_id=snapshot_id).first()
            mock_body = AsyncMock()
            mock_body.read.return_value = b"sample_payload"
            b.hash_sha256 = hashlib.sha256(b"sample_payload").hexdigest()
            session.commit()

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
