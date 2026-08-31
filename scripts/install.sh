#!/usr/bin/env bash
set -e

echo "Instalando Bóveda PyME..."

# Crear usuario y grupo de sistema
if ! id "boveda" &>/dev/null; then
    useradd -r -s /bin/false boveda
    echo "Usuario 'boveda' creado."
fi

# Crear directorios
mkdir -p /var/lib/boveda/cache
mkdir -p /etc/boveda
chown -R boveda:boveda /var/lib/boveda
chmod 700 /var/lib/boveda

# Mover binario (Asumiendo que pyinstaller lo dejó en dist/boveda)
if [ -f "dist/boveda" ]; then
    mv dist/boveda /usr/local/bin/boveda
    chmod +x /usr/local/bin/boveda
else
    echo "Advertencia: Binario dist/boveda no encontrado. Se asume instalación vía pip/uv."
fi

# Instalar systemd
if [ -f "scripts/boveda.service" ]; then
    cp scripts/boveda.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable boveda.service
    echo "Servicios systemd instalados y habilitados."
else
    echo "Advertencia: Archivo scripts/boveda.service no encontrado."
fi

echo "Instalación completada exitosamente."
