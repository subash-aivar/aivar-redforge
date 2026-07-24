# ADR-0005: Canonical Identifier Strategy — ULID via Shared EntityId

## Status

Accepted

## Date

2026-07-22

## Context

RedForge established a platform-wide identifier standard in the M1–M16 baseline: `redforge/shared/identifiers.py` defines `EntityId`, a ULID-backed value object, and the core `Organization` aggregate generates its `id` via `EntityId.generate()`. Organization/tenant IDs are therefore genuinely 26-character ULID strings end-to-end — from generation, through the `organizations` table (`String(26)` column), through the signed JWT `org` claim, into `TenantContext.organization_id: str`.

Between 2026-07-19 and 2026-07-22 (milestones M25a–M36), 27 new bounded contexts were scaffolded with HTTP-exposed APIs (a further 5 — `campaign`, `campaignexecution`, `evaluation`, `scenario`, `taskgraph` — were scaffolded without an API layer yet). Each of these contexts independently defined its own `domain/value_objects/identifiers.py` with a `TenantId` (and related ID) value object backed by Python's `uuid.UUID`, and each context's `api/dependencies.py` casts the incoming tenant context with `UUID(tenant.organization_id)`. This was not a deliberate architectural choice: no ADR, scaffold tool, or shared template in the repository specifies UUID, and the identical shape of the 27 copies is consistent with the pattern being copy-pasted forward from context to context during scaffolding, diverging from the already-established ULID standard.

The consequence: `UUID(tenant.organization_id)` raises `ValueError` for any real (ULID) tenant, so every one of the 27 contexts' APIs fails for authenticated real users. The defect is full-stack within each affected context — it also appears in domain value objects, SQLAlchemy ORM column types (`postgresql.UUID`), repository signatures, and Pydantic DTOs — not only at the dependency-injection boundary.

Full findings are recorded in the RCA produced 2026-07-22 (bounded-context inventory, affected migrations/tables, affected tests, and options analysis).

## Decision

1. **`EntityId` (ULID-backed, `redforge/shared/identifiers.py`) is the single canonical identifier type for every entity, aggregate, and tenant/organization reference across the entire platform — core and every bounded context alike.** No bounded context defines its own tenant/entity identifier value object going forward.
2. Every bounded context's ad-hoc UUID-based `TenantId` (and any other UUID-backed identifier value object standing in for a platform entity id) is replaced with the shared `EntityId`, at the domain, application, and API (DTO) layers.
3. No new identifier abstraction is introduced. We are converging on the identifier type that already exists and was already correct at the platform's core — not inventing a third type or a permanent compatibility wrapper.
4. This decision is implemented in two independent phases, because the application-layer defect (crash on every request) and the database-layer defect (columns physically typed as native `UUID`, incompatible with ULID strings) have different risk profiles and no shared blocking dependency going in the fix direction (fixing the application layer does not require the schema to change first):
   - **Phase 1 (this ADR's immediate scope):** application-layer convergence only — value objects, repositories, DTOs, dependency injection, authentication/authorization checks, and tests updated to use `EntityId`/ULID strings. No schema or migration changes.
   - **Phase 2 (separate initiative, not yet executed):** corrective Alembic migrations changing the 86 affected `tenant_id` columns from `postgresql.UUID` to a ULID-compatible string type (matching how `organizations.id` is already stored), executed as its own reviewed, staged initiative.
5. Phase 1 knowingly does not make the 27 contexts' database writes fully correct — a real ULID tenant id still cannot be persisted into a native `UUID` column. Phase 1's purpose is to stop the immediate, request-layer crash and put the entire application layer on the canonical type, so Phase 2 is a pure schema-alignment change with no further application-code changes required.

## Consequences

- One identifier type, one generation mechanism, one validation rule, platform-wide. Future bounded contexts have no ambiguity to copy incorrectly.
- Phase 1 resolves the crash-on-every-request defect for all 27 contexts without touching the database.
- Phase 1 alone does **not** make these 27 contexts production-ready end-to-end: any code path that reaches an actual database write/read of a real ULID tenant id against the still-UUID-typed column will fail at the database layer instead of the dependency layer, until Phase 2 lands. This is a deliberate, tracked interim state, not a hidden gap.
- 181 test files across the 27 contexts require updating to generate ULID-string fixtures instead of `uuid4()`.
- Phase 2 is the first column-*type*-changing migration in this codebase's history (the only prior `alter_column` usage changed nullability, not type) and must be planned and reviewed as its own initiative, per this decision.

## Alternatives Considered

- **Introduce a new shared "opaque string ID" type instead of reusing `EntityId`.** Rejected: `EntityId` already exists, is already correct, and is already used by the core `redforge` module and several `redforge/domain/*` submodules (inventory, cloud_security, investigations, platform, connectors, threat_intel, attack_library). Introducing a second type would recreate the exact fragmentation this ADR exists to eliminate.
- **Central adapter/compatibility layer that translates between UUID and ULID at each context boundary, left in place indefinitely.** Rejected: this treats the symptom, not the cause — it would become permanent technical debt masking the real problem, and does not resolve the schema-level incompatibility (a ULID still cannot be coerced into a UUID column), so it does not actually reach a production-ready end state.
- **Fix application and schema layers in a single combined change.** Rejected for sequencing risk: this codebase has no precedent for a column-type-changing migration, and combining a 27-context application refactor with an unprecedented schema migration in one change maximizes blast radius for a single rollback unit. Splitting into two independently verifiable phases reduces risk without weakening the eventual outcome.
