# Bóveda PyME

Bóveda PyME es un demonio Linux de respaldo enfocado en la resiliencia y el cifrado offline-first. Diseñado estrictamente para servidores con recursos limitados (PYMEs), garantiza transferencias masivas (streaming a S3) sin que la memoria RAM exceda los 45MB.

## Características Principales

*   **Streaming Estricto:** Control de flujos de 8MB. Cero riesgos de "Out of Memory" (OOM).
*   **Criptografía AAD:** Cifrado militar (AES-256-GCM) en origen. Zstandard para compresión ultrarrápida.
*   **Tolerancia a Red Hóstil:** Auto-recuperación de conexiones caídas o saturadas mediante Exponential Backoff.
*   **Deduplicación Hash:** Reutilización de fragmentos para ahorrar tiempo y costo de S3.
*   **Zero-Hallucination Testing:** Probado sobre MinIO real e infraestructura de aserciones.

## Requisitos

*   Python >= 3.12 (o usar el binario independiente).
*   Cuenta S3 compatible (AWS, Backblaze B2, MinIO local).

## Instalación

Mediante UV (Modo Desarrollo):
```bash
uv sync
```

Instalación como Demonio (Systemd):
```bash
sudo ./scripts/install.sh
sudo systemctl enable boveda.service
sudo systemctl start boveda.service
```

## Uso Básico

### 1. Iniciar un Respaldo
Puedes canalizar flujos grandes (ej. bases de datos) directamente al CLI:
```bash
pg_dump -U postgres mi_db | boveda backup --db prod.db --source db-prod
```

### 2. Listar y Restaurar
```bash
# Ver backups completados
boveda list --db prod.db

# Restaurar al disco
boveda restore snap-1234 --db prod.db --out /tmp/restore.sql
```

### 3. Verificar Integridad S3
Busca signos de "bit-rot" comprobando que S3 tenga exactamente la estructura registrada localmente:
```bash
boveda verify --db prod.db --full
```

### 4. Monitoreo
Si se levanta `boveda daemon`, dispondrás de una API REST (FastAPI) local en el puerto `8000`.

## Documentación Relacionada

*   [CONSTRAINTS.md](CONSTRAINTS.md) — Límites y restricciones operativas que moldean este proyecto.
*   [ARCHITECTURE.md](ARCHITECTURE.md) — Diagramas y arquitectura del sistema.

