# Bóveda PyME

Daemon Linux de respaldo cifrado para PyMEs. La Rev. 2 prioriza la recuperación verificable, el aislamiento criptográfico por snapshot y una operación segura ante fallos de red, proceso o almacenamiento.

## Seguridad zero-knowledge

Los datos se comprimen y cifran en el host antes de que cualquier byte salga hacia S3, B2 o un endpoint compatible. El proveedor de almacenamiento no recibe datos en claro ni la passphrase.

- La passphrase deriva un **KEK de 256 bits** con Argon2id (`t=3`, `m=65536`, `p=4`) y un `master_salt` público de 32 bytes.
- Cada snapshot recibe un **DEK aleatorio de 32 bytes**. El DEK se cifra con el KEK mediante AES-256-GCM; el KEK nunca cifra datos de usuario directamente.
- Cada chunk usa un nonce determinista de **96 bits**: prefijo de sesión aleatorio de 4 bytes más contador big-endian de 8 bytes. No puede repetirse bajo el mismo DEK.
- El header binario versionado autentica `magic`, versión, secuencia de chunk y `snapshot_id` como AAD. Junto con el tag GCM y el manifiesto SHA-256, esto rechaza alteraciones, sustituciones y reproducciones de chunks fuera de su snapshot o secuencia válidos.

La protección se completa con un catálogo SQLite en modo WAL, estados explícitos de snapshot y un orden de purga que confirma la eliminación remota antes de borrar los metadatos locales.

## Arquitectura operativa

El pipeline es `origen → zstd → AES-256-GCM → SHA-256 → multipart upload`. No crea archivos temporales: aplica backpressure con una cola acotada de 2 elementos y chunks de 8 MiB. La Rev. 2 establece un presupuesto verificable de aproximadamente 42 MiB y un techo absoluto de **45 MiB** para el pipeline.

Ante SIGTERM o SIGINT, el chunk en tránsito se completa, el upload multipart se aborta, el snapshot se marca como `FAILED` y la transacción SQLite se confirma. Al arrancar, el daemon también recupera snapshots que quedaron en `RUNNING`.

## Onboarding de desarrollo con uv

Requisito: tener `uv` disponible. No uses `pip`, `venv` ni gestores de dependencias alternativos para este proyecto.

```bash
# 1. Obtener Python 3.12 administrado por uv (si aún no está disponible)
uv python install 3.12

# 2. Sincronizar el entorno virtual y todas las dependencias del lockfile
uv sync

# 3. Ejecutar la migración del catálogo
uv run alembic upgrade head

# 4. Consultar la interfaz disponible e inicializar la bóveda
uv run boveda --help
uv run boveda init

# 5. Ejecutar las verificaciones locales
./.agents/pre_commit_gate.sh
```

Para una instalación reproducible o de despliegue, usa `uv sync --frozen`; así se respeta exactamente el lockfile versionado.

## Referencia CLI

La Rev. 2 define estos comandos de operación. `uv run` garantiza que siempre se use el entorno sincronizado por `uv`.

| Comando | Uso |
| --- | --- |
| `uv run boveda init` | Genera el `master_salt`, inicializa el catálogo y prepara la configuración de la bóveda. |
| `uv run boveda daemon` | Inicia el ciclo del daemon: verifica integridad y esquema, ejecuta backups y realiza limpieza de snapshots interrumpidos. |
| `uv run boveda --help` | Muestra los subcomandos expuestos por la versión instalada. |
| `uv run alembic upgrade head` | Lleva el esquema SQLite a la revisión de Alembic requerida antes de arrancar el daemon. |

## Despliegue con systemd

1. Despliega el proyecto en `/opt/boveda` y prepara el entorno con `uv sync --frozen`.
2. Crea el usuario y los directorios de servicio: `boveda`, `/var/lib/boveda` y `/var/log/boveda`.
3. Guarda las variables de entorno y credenciales necesarias en `/etc/boveda/env`, con permisos restrictivos para el usuario de servicio.
4. Instala la unidad siguiente en `/etc/systemd/system/boveda.service`. El `TimeoutStopSec=90` reserva tiempo para finalizar el chunk en curso y ejecutar `AbortMultipartUpload`.
5. Ejecuta `sudo systemctl daemon-reload`, `sudo systemctl enable --now boveda` y revisa los eventos con `journalctl -u boveda -f`.

```ini
[Unit]
Description=Bóveda PyME - Daemon de Respaldo Cifrado
Documentation=https://github.com/tu-org/boveda-pyme
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=boveda
Group=boveda
EnvironmentFile=/etc/boveda/env
ExecStart=/opt/boveda/venv/bin/boveda daemon
Restart=on-failure
RestartSec=60
TimeoutStopSec=90

# Hardening
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ReadWritePaths=/var/lib/boveda /var/log/boveda
CapabilityBoundingSet=
SystemCallFilter=@system-service

StandardOutput=journal
StandardError=journal
SyslogIdentifier=boveda

[Install]
WantedBy=multi-user.target
```

El ejecutable de `ExecStart` debe apuntar al entorno que el despliegue haya creado con `uv` (por ejemplo, `/opt/boveda/venv/bin/boveda` en la disposición de la Rev. 2). No ejecutes el daemon con privilegios de `root`.

Para ejecutar backups programados, instala además un timer que dispare a las 02:00, persista ejecuciones omitidas y distribuya la carga:

```ini
[Unit]
Description=Timer de Bóveda PyME - Disparo de Respaldos Programados

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
```

Guárdalo como `/etc/systemd/system/boveda.timer` y actívalo con `sudo systemctl enable --now boveda.timer`.
