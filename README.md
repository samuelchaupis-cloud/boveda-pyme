# Bóveda PyME (v0.2.0)

Bóveda PyME es un demonio Linux de respaldo enfocado en la resiliencia y el cifrado offline-first. Diseñado estrictamente para servidores con recursos limitados (PYMEs), garantiza transferencias masivas (streaming a S3) sin que la memoria RAM exceda los 45MB.

## Características Principales

*   **Streaming Acotado O(1):** Control de flujos de 8MB con memoria RAM residente estrictamente $\le 45\,\text{MB}$.
*   **Catálogo `chunk_pool` y Triggers SQLite:** Deduplicación global en origen con conteo de referencias (`ref_count`) y purga en dos fases (*Two-Phase Soft-Delete / Sweep*) libre de punteros colgantes (*dangling pointers*).
*   **Criptografía Convergente SIV & HKDF:** Cifrado determinista seguro basado en contenido con Synthetic IV y AAD invariante desacoplado.
*   **Conectores de Bases de Datos:** Streaming directo para PostgreSQL (`pg_dump -Fc`), MySQL (`mysqldump`) y SQLite con drenaje no-bloqueante de `stderr` y watchdogs de inactividad.
*   **Abstracción KeyProvider & Rotación Atómica:** Soporte para Argon2id, AWS KMS y HashiCorp Vault con comando `boveda rotate-kek` de re-envoltorio de DEKs (0 bytes a S3).
*   **Sellado Legal & Merkle Trees:** Cálculo de raíces de Merkle RFC 6962 y firmas Ed25519 con verificación Zero-Knowledge.
*   **Métricas Prometheus `/metrics`:** Telemetría nativa de cero huella (< 180 KB RAM) para monitoreo de memoria, snapshots y ratios de deduplicación.

## Requisitos

*   Python >= 3.12 (o binario standalone compilado con PyInstaller).
*   Cuenta de almacenamiento compatible con S3 (AWS S3, Backblaze B2, MinIO, Cloudflare R2).

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
Puedes canalizar flujos de datos directamente hacia el CLI:
```bash
pg_dump -U postgres mi_db | boveda backup --db prod.db --source db-prod
```

### 2. Rotación de Claves Maestras (KEK)
Re-encripta todas las claves de snapshot atómicamente en SQLite sin transferir datos a la nube:
```bash
boveda rotate-kek --db prod.db
```

### 3. Listar y Restaurar
```bash
# Listar snapshots completados
boveda list --db prod.db

# Restaurar hacia archivo destino
boveda restore snap-1234 --db prod.db --out /tmp/restore.sql
```

### 4. Verificación de Integridad y Bit-Rot
```bash
boveda verify --db prod.db --full
```

### 5. Telemetría y Dashboard Web
Inicia el daemon con API REST y endpoint OpenMetrics:
```bash
boveda daemon
# Dashboard: http://127.0.0.1:8080/
# Métricas Prometheus: http://127.0.0.1:8080/metrics
```

## Documentación Técnica

*   [CONSTRAINTS.md](CONSTRAINTS.md) — Límites y restricciones operativas del sistema.
*   [ARCHITECTURE.md](ARCHITECTURE.md) — Diagramas y especificación de arquitectura v0.2.0.


