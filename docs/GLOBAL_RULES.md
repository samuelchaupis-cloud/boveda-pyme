# 🛡️ PROTOCOLO SUPREMO DE CALIDAD, ARQUITECTURA Y CONTROL DE VERSIONES
## 1. Idioma, Redacción de Commits e Higiene del Repositorio
- Todos los mensajes de commit, descripciones de PR y documentación interna DEBEN redactarse 100% en ESPAÑOL técnico formal.

## 2. The Iron Law of Verification (Ejecución vs. Alucinación)
- Zero-Hallucination Execution Gate: El éxito SOLO se demuestra ejecutando herramientas reales (run_command) y leyendo su salida cruda.
- uv run ruff check . y uv run ruff format --check . ➔ Cero errores.
- uv run mypy src/ ➔ Cero errores de tipado.
- uv run bandit -r src/ -ll -ii ➔ Cero vulnerabilidades.
- uv run pytest tests/ -v --cov=src --cov-fail-under=85 ➔ 100% de tests en verde con cobertura >= 85%.

## 3. Cláusulas Anti-Evasión (No-Suppress Law & Assert Quality Gate)
- Prohibido usar # type: ignore, # noqa, # nosec o comodines como Any/object para saltarse los gates de calidad.
- La cobertura del 85% es inválida si los tests no tienen aserciones reales (Mutation Assertions). Toda persistencia en tests debe usar SQLite en modo :memory:. Mocks solo se permiten en fronteras puras de I/O de red externas.

## 4. Adversarial Red Team, Multi-Lens Auditing & TDD Synthesis
- Pydantic v2 estricto. Prohibido usar float en lógica financiera; uso de Decimal escalado.
- Concurrencia y Bloqueos: BEGIN IMMEDIATE en SQLite para prevenir deadlocks.
- Aislamiento de Fallos: Timeouts obligatorios, backoff exponencial con jitter (tenacity).
- Ciclo de Vida y Memoria: Colas acotadas y semáforos para garantizar RAM < 45MB en streaming masivo.
- Observabilidad: Logging JSON (structlog) con ofuscación de PII.
