# Project Plan: Boveda-PyME (Streaming Validation & Systemd Packaging)

## Goal
Validate Zstandard/AES-GCM streaming design within <45MB RAM constraints and configure python-packaging for systemd deployment.

## Next Step
Validate Zstandard/AES-GCM streaming limit manually and configure packaging.

## Phases

### Phase 1: Validar diseño de streaming Zstandard/AES-GCM
- **Status:** in_progress
- **Objective:** Confirm that the existing streaming architecture uses bounded buffers and memory < 45MB.

### Phase 2: Configurar python-packaging y Systemd
- **Status:** pending
- **Objective:** Establish the packaging configuration (`pyproject.toml`) and deployment scripts (systemd) for frictionless release.

### Phase 3: Aserciones en Flujo de Bytes (TDD)
- **Status:** pending
- **Objective:** Implement mutation assertions verifying the exact bytes read and written in `engine.py`.

### Phase 4: Documentación de Arquitectura y README
- **Status:** pending
- **Objective:** Generate `ARCHITECTURE.md` tracking fault-tolerance schemes and a `README.md` for user onboarding.
