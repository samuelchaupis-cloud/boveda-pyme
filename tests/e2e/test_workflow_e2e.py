import os
import shutil
import tempfile

import pytest
from click.testing import CliRunner

from boveda.cli import main

# Configuración del entorno de prueba
E2E_DB = "e2e_snapshots.db"


@pytest.fixture(scope="module", autouse=True)
def setup_e2e_env():
    # Establecer variables para MinIO local (docker-compose)
    os.environ["AWS_ACCESS_KEY_ID"] = "boveda_test"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "boveda_secret_123"
    os.environ["S3_ENDPOINT"] = "http://127.0.0.1:9000"
    os.environ["S3_BUCKET"] = "boveda-backups"
    os.environ["BOVEDA_PASSPHRASE"] = "E2E_Super_Secret"

    if os.path.exists(E2E_DB):
        os.remove(E2E_DB)

    yield

    # Cleanup DB and downloaded artifacts
    if os.path.exists(E2E_DB):
        try:
            os.remove(E2E_DB)
        except OSError:
            pass
    if os.path.exists(E2E_DB + "-shm"):
        try:
            os.remove(E2E_DB + "-shm")
        except OSError:
            pass
    if os.path.exists(E2E_DB + "-wal"):
        try:
            os.remove(E2E_DB + "-wal")
        except OSError:
            pass


def test_full_workflow_e2e():
    """
    Este test levanta un origen de datos temporal, inicializa el sistema, realiza un backup (que
    se procesa de forma asíncrona usando aioboto3 contra MinIO) y luego realiza un restore
    para confirmar integridad.
    Nota: Requiere que docker-compose up -d minio se esté ejecutando localmente.
    Si MinIO no responde en 127.0.0.1:9000, este test fallará (lo cual es esperado en E2E).
    """
    import urllib.request

    try:
        urllib.request.urlopen("http://127.0.0.1:9000/minio/health/live", timeout=2)
    except Exception:  # noqa: BLE001
        pytest.skip("MinIO no está corriendo localmente en el puerto 9000. Saltar E2E.")

    runner = CliRunner()

    # 1. Crear origen de datos de prueba
    temp_dir = tempfile.mkdtemp()
    test_file_path = os.path.join(temp_dir, "data.txt")
    with open(test_file_path, "wb") as f:
        f.write(os.urandom(10 * 1024 * 1024))  # 10 MB payload (causará 2 chunks)

    try:
        # 2. Inicializar BD
        result = runner.invoke(main, ["init", "--db", E2E_DB])
        assert result.exit_code == 0
        assert "Inicializaci" in result.output

        # 3. Realizar Backup (simulate stdout via python -c printing the file)
        # Omitimos el shell nativo si estamos en Python y mejor inyectamos un script python helper
        helper_py = os.path.join(temp_dir, "dump.py")
        with open(helper_py, "w") as f:
            f.write(
                f"import sys\nwith open(r'{test_file_path}', 'rb') as fin:\n    sys.stdout.buffer.write(fin.read())"
            )

        cmd_str = f"python {helper_py}"

        result_backup = runner.invoke(
            main,
            [
                "backup",
                "--db",
                E2E_DB,
                "--tipo",
                "DIARIO",
                "--source",
                "e2e-test",
                "--cmd",
                cmd_str,
            ],
        )

        assert result_backup.exit_code == 0
        assert "Backup completado" in result_backup.output

        # Extraer snapshot_id de la salida
        lines = result_backup.output.split("\n")
        snapshot_id = None
        for line in lines:
            if "Snapshot:" in line:
                snapshot_id = line.split("Snapshot:")[1].strip()
                break

        assert snapshot_id is not None

        # 4. Listar
        result_list = runner.invoke(main, ["list", "--db", E2E_DB])
        assert snapshot_id in result_list.output

        # 5. Restore
        restored_file_path = os.path.join(temp_dir, "restored.txt")
        result_restore = runner.invoke(
            main,
            ["restore", snapshot_id, "--out", restored_file_path, "--db", E2E_DB],
            input="E2E_Super_Secret\n",
        )

        assert result_restore.exit_code == 0
        assert "restaurado exitosamente" in result_restore.output

        # 6. Validar Hashes exactos
        import hashlib

        def file_hash(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()

        assert file_hash(test_file_path) == file_hash(restored_file_path)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
