import logging

import click

from boveda.crypto import generate_master_salt
from boveda.database import Configuracion, init_db

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


@main.command()
def daemon():
    """Inicia el ciclo del daemon"""
    click.echo("Iniciando daemon de Bóveda PyME...")
    # Lógica del daemon irá aquí


if __name__ == "__main__":
    main()
