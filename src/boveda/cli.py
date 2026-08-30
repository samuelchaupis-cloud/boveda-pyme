import logging
import os

import click

from boveda.crypto import derive_kek, generate_master_salt
from boveda.database import Bloque, Configuracion, Snapshot, init_db
from boveda.restore import restore_snapshot

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
@click.option("--out", required=True, type=click.Path(dir_okay=False, writable=True), help="Ruta al archivo destino")
@click.option("--db", default="snapshots.db", help="Ruta a la base de datos SQLite")
def restore(snapshot_id, out, db):
    """Restaura un snapshot."""
    Session = init_db(db)
    session = Session()
    try:
        snapshot = session.query(Snapshot).filter_by(id=snapshot_id).first()
        if not snapshot or snapshot.estado != "COMPLETED":
            click.echo(f"Error: Snapshot {snapshot_id} no existe o no está COMPLETED.", err=True)
            return

        salt_conf = session.query(Configuracion).filter_by(clave="master_salt").first()
        if not salt_conf:
            click.echo("Error: master_salt no encontrado en la base de datos.", err=True)
            return

        passphrase = click.prompt("Passphrase", hide_input=True)
        kek = derive_kek(passphrase, salt_conf.valor)

        bloques = session.query(Bloque).filter_by(snapshot_id=snapshot_id).order_by(Bloque.chunk_seq).all()

        def download_callback(storage_key):
            local_path = os.path.join("snapshots", snapshot_id, storage_key)
            if not os.path.exists(local_path):
                raise FileNotFoundError(f"Archivo no encontrado en disco local: {local_path}")
            with open(local_path, "rb") as bf:
                return bf.read()

        with open(out, "wb") as f_out:
            restore_snapshot(snapshot, kek, bloques, f_out, download_callback)

        click.echo(f"Snapshot {snapshot_id} restaurado exitosamente en {out}")

    except Exception as e:  # noqa: BLE001
        click.echo(f"Error durante la restauración: {e}", err=True)
    finally:
        session.close()


@main.command()
def daemon():
    """Inicia el ciclo del daemon"""
    click.echo("Iniciando daemon de Bóveda PyME...")
    # Lógica del daemon irá aquí


if __name__ == "__main__":
    main()
