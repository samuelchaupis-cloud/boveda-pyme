#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: Este script debe ejecutarse con privilegios de root (sudo)." >&2
    exit 1
fi

echo "Iniciando instalación de Bóveda PyME..."

# 1. Crear grupo y usuario de sistema
if ! getent group boveda >/dev/null 2>&1; then
    groupadd -r boveda
    echo "Grupo de sistema 'boveda' creado."
fi

if ! id "boveda" >/dev/null 2>&1; then
    useradd -r -g boveda -d /var/lib/boveda -s /usr/sbin/nologin -M boveda
    echo "Usuario de sistema 'boveda' creado."
fi

# 2. Creación segura de directorios del sistema
mkdir -p /var/lib/boveda/cache
mkdir -p /var/log/boveda
mkdir -p /etc/boveda

chown -R boveda:boveda /var/lib/boveda /var/log/boveda
chmod 700 /var/lib/boveda
chmod 750 /var/log/boveda

chown root:boveda /etc/boveda
chmod 750 /etc/boveda

# 3. Archivo de entorno de credenciales seguro
if [ ! -f /etc/boveda/boveda.env ]; then
    cat << 'EOF' > /etc/boveda/boveda.env
# Variables de Configuración de Bóveda PyME
BOVEDA_PASSPHRASE=definir-passphrase-aqui
S3_BUCKET=mi-bucket-boveda
S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
EOF
    chown root:boveda /etc/boveda/boveda.env
    chmod 600 /etc/boveda/boveda.env
    echo "Plantilla /etc/boveda/boveda.env creada con permisos 0600."
fi

# 4. Instalación no destructiva del binario
if [ -f "dist/boveda" ]; then
    install -m 755 -D dist/boveda /usr/local/bin/boveda
    echo "Binario instalado en /usr/local/bin/boveda."
elif command -v boveda >/dev/null 2>&1; then
    echo "Binario boveda ya disponible en PATH ($(command -v boveda))."
else
    echo "Advertencia: dist/boveda no encontrado. Se asume instalación vía pip/uv."
fi

# 5. Instalación de unidades systemd endurecidas
if [ -d "/etc/systemd/system" ]; then
    if [ -f "deploy/boveda.service" ]; then
        install -m 644 -D deploy/boveda.service /etc/systemd/system/boveda.service
    elif [ -f "scripts/boveda.service" ]; then
        install -m 644 -D scripts/boveda.service /etc/systemd/system/boveda.service
    fi
    
    if pidof systemd >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
        systemctl daemon-reload
        systemctl enable boveda.service || true
        echo "Servicio systemd configurado exitosamente."
    fi
fi

echo "Instalación completada exitosamente."

