# Constraints

> Externally-imposed boundaries that shape what this project can build and how. This file is distinct from `openspec/config.yaml` (chosen stack and patterns), `AGENTS.md` (agent behavior), and `ARCHITECTURE.md` (current system structure): it records *why* certain choices in those documents are non-negotiable, when an external forcing function exists.
>
> Maintained by the `constraints-extractor` skill. Hand-edits to any entry are preserved on the next run. Each entry's `CONSTR-<CATEGORY>-<NNN>` ID is its stable identifier: it is assigned once and never changes on retitle, and any cross-reference to this entry (from `AGENTS.md`, from another entry's Enforced-by, from anywhere) should point to the ID, never to the title text.
>
> Confidence is one of two states: `CONFIRMED` (backed by at least one citation; the ref count in the Evidence line reflects how many independent sources agree) or `CONFLICTING` (two or more sources disagree and it needs human resolution).

Date of last update: <!-- TODO: fill in -->

## 1. Compliance & Governance

### CONSTR-COMPLY-001 · All commit messages, PR descriptions, and internal documentation must be

Confidence: CONFIRMED
Category: compliance-governance
Evidence: `docs/GLOBAL_RULES.md:Section 1` (1 ref)

All commit messages, PR descriptions, and internal documentation must be written 100% in formal technical Spanish.

**Why it matters:** Prevents language fragmentation in the repository and ensures readability for the primary engineering team. English or Spanglish is strictly forbidden.

**Evidence notes:**
- `docs/GLOBAL_RULES.md:Section 1` -- Mandates Spanish as the exclusive language for internal communication and documentation.

## 2. Security, Privacy, IP & CUI

### CONSTR-SEC-001 · Logging must use JSON format via structlog with obfuscation of PII (Personally

Confidence: CONFIRMED
Category: security-privacy-ip-cui
Evidence: `docs/GLOBAL_RULES.md:Section 4` (1 ref)

Logging must use JSON format via structlog with obfuscation of PII (Personally Identifiable Information).

**Why it matters:** Prevents leaking sensitive user data in application logs, ensuring compliance with privacy standards.

**Evidence notes:**
- `docs/GLOBAL_RULES.md:Section 4` -- Mandates structlog with PII obfuscation.

## 3. Hosting & Infrastructure Boundaries

### CONSTR-INFRA-001 · SQLite connections must use BEGIN IMMEDIATE to prevent deadlocks (SQLITE_BUSY)

Confidence: CONFIRMED
Category: hosting-infrastructure
Evidence: `docs/GLOBAL_RULES.md:Section 4` (1 ref)

SQLite connections must use BEGIN IMMEDIATE to prevent deadlocks (SQLITE_BUSY).

**Why it matters:** Prevents concurrent write conflicts and database locking when running multi-threaded or multi-process operations.

**Evidence notes:**
- `docs/GLOBAL_RULES.md:Section 4` -- Requires BEGIN IMMEDIATE for SQLite concurrency.

## 4. Tooling & Approved-Path Restrictions

### CONSTR-TOOL-001 · All database tests must use SQLite in memory mode, without relying on mocks

Confidence: CONFIRMED
Category: tooling-approved-path
Evidence: `docs/GLOBAL_RULES.md:Section 3` (1 ref)

All database tests must use SQLite in memory mode, without relying on mocks like MagicMock for domain logic.

**Why it matters:** Ensures testing against an actual database engine, preventing synthetic coverage that misses real persistence bugs.

**Evidence notes:**
- `docs/GLOBAL_RULES.md:Section 3` -- Forbids MagicMock for database or local domain logic and mandates SQLite :memory:.

## 5. Workflow & Sequencing Requirements

*No entries yet.*

## 6. Stakeholder & Executive Expectations

*No entries yet.*

## 7. Scope, Prioritization & Delivery Boundaries

### CONSTR-SCOPE-001 · RAM usage must be strictly constrained to < 45MB during massive streaming

Confidence: CONFIRMED
Category: scope-prioritization-delivery
Evidence: `docs/GLOBAL_RULES.md:Section 4` (1 ref)

RAM usage must be strictly constrained to < 45MB during massive streaming operations.

**Why it matters:** If memory exceeds 45MB, the application may be killed in highly constrained environments. Prevents OOM crashes during multi-gigabyte/terabyte backups.

**Evidence notes:**
- `docs/GLOBAL_RULES.md:Section 4` -- Explicitly demands bounded queues and semaphores to guarantee RAM < 45MB in massive streaming.

## 8. External Dependencies Shaping Future Planning

*No entries yet.*
