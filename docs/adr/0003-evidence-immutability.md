# ADR-0003: Evidence Immutability as Architectural Constraint

## Status

Accepted

## Date

2025-01-01

## Context

RedForge's core philosophy is "Evidence First." Evidence is the raw output captured during validation runs — it is the source of truth from which findings are generated. If evidence can be modified, the integrity of all derived findings is compromised.

## Decision

Evidence is immutable at every layer of the system:

- **Domain layer:** Evidence entities have no mutator methods.
- **Repository layer:** The evidence repository interface exposes no `update()` method.
- **Database layer:** Evidence tables will be append-only. No UPDATE or DELETE operations permitted.
- **API layer:** No PUT/PATCH/DELETE endpoints for evidence resources.

Findings are always regenerable from evidence. If analysis logic improves, findings can be regenerated without re-running validations.

## Consequences

- Evidence integrity is guaranteed by architecture, not convention.
- Storage grows monotonically — archival and retention policies will be needed.
- Incorrect evidence cannot be "fixed" — it can only be superseded by a new validation run.
- Findings can be safely regenerated at any time without data loss concerns.
- Audit trail is inherently complete.

## Alternatives Considered

- **Soft-delete with audit log** — Adds complexity and allows accidental mutations.
- **Event sourcing** — More powerful but introduces significant infrastructure overhead prematurely.
