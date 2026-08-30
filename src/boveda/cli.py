import asyncio
import logging
import os
import uuid
from datetime import UTC, datetime

import click

from boveda.crypto import derive_kek, generate_dek_for_snapshot, generate_master_salt
from boveda.database import Bloque, Configuracion, Snapshot, init_db
from boveda.engine import streaming_pipeline
from boveda.restore import restore_snapshot
from boveda.retention import purge_expired_snapshots

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


@click.group()
def main():
    """Bóveda PyME CLI"""


@main.command()
@click.option("--db", default="snapshots.db", help="Ruta a la base de datos SQLite")
def init(db):
    """Inicializa el catálogo y genera el master_salt"""
    Session = init_db(db)
    session = Session()
    try:
        # Check if already initialized
        salt_conf = session.query(Configuracion).filter_by(clave="master_salt").first()
        if salt_conf:
            click.echo(f"La base de datos {db} ya se encuentra inicializada.")
            return

        salt_b64 = generate_master_salt()
        new_salt = Configuracion(clave="master_salt", valor=salt_b64, es_secreto=False)
        session.add(new_salt)

        argon2_params = '{"t": 3, "m": 65536, "p": 4}'
        params_conf = Configuracion(
            clave="argon2_params", valor=argon2_params, es_secreto=False
        )
        session.add(params_conf)

        session.commit()
        click.echo(f"Inicialización completa en {db}.")

    except Exception as e:  # noqa: BLE001
        session.rollback()
        click.echo(f"Error durante la inicialización: {e}", err=True)
    finally:
        session.close()


@main.command(name="list")
@click.option("--db", default="snapshots.db", help="Ruta a la base de datos SQLite")
def list_snapshots(db):
    """Lista los snapshots disponibles en estado COMPLETED."""
    Session = init_db(db)
    session = Session()
    try:
        snapshots = (
            session.query(Snapshot)
            .filter(Snapshot.estado == "COMPLETED")
            .order_by(Snapshot.timestamp.desc())
            .all()
        )
        if not snapshots:
            click.echo("No se encontraron snapshots completados.")
            return

        click.echo(f"{'ID':<38} {'Timestamp':<21} {'Tipo':<12} {'Source'}")
        click.echo("-" * 90)
        for s in snapshots:
            ts = s.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.timestamp else "N/A"
            source = f"{s.source_type}:{s.source_identifier}"
            click.echo(f"{s.id:<38} {ts:<21} {s.tipo:<12} {source}")
    finally:
        session.close()


@main.command()
@click.argument("snapshot_id")
@click.option(
    "--out",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="Ruta al archivo destino",
)
@click.option("--db", default="snapshots.db", help="Ruta a la base de datos SQLite")
def restore(snapshot_id, out, db):
    """Restaura un snapshot."""
    Session = init_db(db)
    session = Session()
    try:
        snapshot = session.query(Snapshot).filter_by(id=snapshot_id).first()
        if not snapshot or snapshot.estado != "COMPLETED":
            click.echo(
                f"Error: Snapshot {snapshot_id} no existe o no está COMPLETED.",
                err=True,
            )
            return

        salt_conf = session.query(Configuracion).filter_by(clave="master_salt").first()
        if not salt_conf:
            click.echo(
                "Error: master_salt no encontrado en la base de datos.", err=True
            )
            return

        passphrase = click.prompt("Passphrase", hide_input=True)
        kek = derive_kek(passphrase, salt_conf.valor)

        bloques = (
            session.query(Bloque)
            .filter_by(snapshot_id=snapshot_id)
            .order_by(Bloque.chunk_seq)
            .all()
        )

        def download_callback(storage_key):
            from boveda.storage import download_from_s3

            bucket = os.environ.get("S3_BUCKET")
            return asyncio.run(download_from_s3(bucket, storage_key))

        with open(out, "wb") as f_out:
            restore_snapshot(snapshot, kek, bloques, f_out, download_callback)

        click.echo(f"Snapshot {snapshot_id} restaurado exitosamente en {out}")

    except Exception as e:  # noqa: BLE001
        click.echo(f"Error durante la restauración: {e}", err=True)
    finally:
        session.close()


@main.command()
@click.option("--db", default="snapshots.db", help="Ruta a la base de datos SQLite")
@click.option(
    "--tipo", default="DIARIO", help="Tipo de backup: DIARIO, SEMANAL, MENSUAL"
)
@click.option("--source", required=True, help="Identificador del origen (ej. db-prod)")
@click.option("--cmd", required=True, help="Comando a ejecutar y capturar stdout")
def backup(db, tipo, source, cmd):
    """Realiza un backup de un origen, capturando de stdin/pipe el flujo de datos."""
    from boveda.alerts import send_webhook_alert

    passphrase = os.environ.get("BOVEDA_PASSPHRASE")
    bucket = os.environ.get("S3_BUCKET")

    if not passphrase or not bucket:
        click.echo(
            "Error: Se requieren las variables de entorno BOVEDA_PASSPHRASE y S3_BUCKET.",
            err=True,
        )
        return

    Session = init_db(db)
    session = Session()

    try:
        salt_conf = session.query(Configuracion).filter_by(clave="master_salt").first()
        if not salt_conf:
            click.echo(
                "Error: master_salt no encontrado en la BD. Ejecuta 'init' primero.",
                err=True,
            )
            return

        kek = derive_kek(passphrase, salt_conf.valor)

        snapshot_id = str(uuid.uuid4())
        dek_raw, encrypted_dek, dek_nonce, dek_tag = generate_dek_for_snapshot(
            kek, snapshot_id
        )

        snapshot = Snapshot(
            id=snapshot_id,
            estado="IN_PROGRESS",
            tipo=tipo,
            source_type="cmd",
            source_identifier=source,
            encrypted_dek=encrypted_dek,
            dek_nonce=dek_nonce,
            dek_tag=dek_tag,
            timestamp=datetime.now(UTC),
        )
        session.add(snapshot)
        session.commit()

        async def run_pipeline():
            shutdown_event = asyncio.Event()

            async def upload_callback(seq: int, payload: bytes, c_hash: str):
                def _db_ops():
                    local_session = Session()
                    with local_session:
                        existente = (
                            local_session.query(Bloque)
                            .filter_by(hash_sha256=c_hash)
                            .first()
                        )
                        return existente.storage_key if existente else None

                storage_key = await asyncio.to_thread(_db_ops)

                if not storage_key:
                    storage_key = f"{snapshot_id}/chunk_{seq}_{c_hash[:8]}.bin"
                    from boveda.storage import upload_to_s3

                    await upload_to_s3(payload, bucket, storage_key)

                def _save_chunk():
                    local_session = Session()
                    with local_session:
                        b = Bloque(
                            snapshot_id=snapshot_id,
                            chunk_seq=seq,
                            hash_sha256=c_hash,
                            size_compressed=len(payload) - 26,
                            size_encrypted=len(payload) - 26,
                            storage_key=storage_key,
                        )
                        local_session.add(b)
                        local_session.commit()

                await asyncio.to_thread(_save_chunk)

            await streaming_pipeline(
                cmd.split(), snapshot_id, dek_raw, upload_callback, shutdown_event
            )

        try:
            asyncio.run(run_pipeline())
            snapshot.estado = "COMPLETED"
            snapshot.completed_at = datetime.now(UTC)
            session.commit()
            click.echo(f"Backup completado. Snapshot: {snapshot_id}")

            from boveda.alerts import send_webhook_alert

            asyncio.run(send_webhook_alert(snapshot_id, "COMPLETED"))
        except Exception as e:  # noqa: BLE001
            session.rollback()
            snapshot = session.query(Snapshot).get(snapshot_id)
            snapshot.estado = "FAILED"
            snapshot.error_detail = str(e)[:500]
            session.commit()
            click.echo(f"Error en streaming: {e}", err=True)
            from boveda.alerts import send_webhook_alert

            asyncio.run(
                send_webhook_alert(snapshot_id, "FAILED", error_detail=str(e)[:500])
            )

        # FSM retención
        def delete_cb(keys_list):
            from boveda.storage import delete_objects_s3

            asyncio.run(delete_objects_s3(bucket, keys_list))

        purge_expired_snapshots(session, delete_cb)

    except Exception as e:  # noqa: BLE001
        click.echo(f"Error general durante el backup: {e}", err=True)
        if "snapshot" in locals() and snapshot:
            snapshot.estado = "FAILED"
            snapshot.error_detail = str(e)[:500]
            session.commit()
            from boveda.alerts import send_webhook_alert

            asyncio.run(
                send_webhook_alert(snapshot_id, "FAILED", error_detail=str(e)[:500])
            )
    finally:
        session.close()


@main.command()
def daemon():
    """Inicia el ciclo del daemon"""
    click.echo("Iniciando daemon de Bóveda PyME...")
    # Lógica del daemon irá aquí


if __name__ == "__main__":
    main()
