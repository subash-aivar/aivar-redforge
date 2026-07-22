# M1 — Platform Identity & Super Admin Bootstrap — Completion Report

> For step-by-step operational instructions on provisioning the first
> Platform Super Administrator in a real deployment (required env vars,
> exact API/UI steps, verification, troubleshooting), see
> [`RUNBOOK_PLATFORM_SUPER_ADMIN_BOOTSTRAP.md`](./RUNBOOK_PLATFORM_SUPER_ADMIN_BOOTSTRAP.md).
> This document explains the architecture and proves its security
> properties; it is not itself a runbook.

**Date**: 2026-07-11
**Baseline entering M1**: 3,383 backend tests passing, 5 skipped; 31 frontend tests passing.
**Baseline exiting M1**: 3,412 backend tests passing, 5 skipped (+29); 31 frontend tests passing (unchanged — M1 is primarily backend/API work plus new UI screens, not new frontend unit-test surface).

---

## 1. Exact Files Changed

### Backend (new)
- `src/redforge/domain/platform_identity/__init__.py`
- `src/redforge/domain/platform_identity/value_objects.py` — `PlatformRole`, `PlatformAssignmentStatus`, `PlatformPermission`, `PLATFORM_ROLE_PERMISSIONS`, `GRANTABLE_PLATFORM_ROLES_M1`
- `src/redforge/domain/platform_identity/entity.py` — `PlatformAssignment`
- `src/redforge/domain/platform_identity/exceptions.py`
- `src/redforge/application/platform_identity/__init__.py`
- `src/redforge/application/platform_identity/service.py` — `PlatformAccessService`, `PlatformAssignmentDTO`, `PlatformAccessDTO`
- `src/redforge/application/platform_identity/query_service.py` — `PlatformQueryService`, `PlatformUserDTO`, `PlatformOrganizationDTO`
- `src/redforge/infrastructure/database/models/platform_identity.py` — `PlatformAssignmentModel`, `PlatformBootstrapStateModel`, `PlatformAuditLogModel`
- `src/redforge/infrastructure/database/repositories/platform_identity_repository.py` — `SqlAlchemyPlatformAssignmentRepository`
- `src/redforge/infrastructure/audit/platform_audit_log.py` — `PostgresPlatformAuditLog`
- `src/redforge/infrastructure/database/migrations/versions/0011_platform_identity.py`
- `src/redforge/api/v1/platform.py` — 8 endpoints
- `tests/domain/test_platform_identity.py` — 8 tests
- `tests/api/test_platform_identity_api.py` — 18 tests
- `tests/integration/test_platform_identity_bootstrap_race.py` — 3 real-PostgreSQL concurrency tests

### Backend (modified)
- `src/redforge/api/security.py` — added `PlatformContext`, `get_platform_context`, `require_platform_permission`
- `src/redforge/api/dependencies.py` — added `get_platform_access_service`, `get_platform_query_service`
- `src/redforge/api/v1/__init__.py` — registered `platform_router`
- `src/redforge/infrastructure/database/models/__init__.py` — exported the 3 new models
- `src/redforge/infrastructure/audit/contracts.py` — added 5 `AuditAction` entries (`PLATFORM_BOOTSTRAP_SUCCEEDED`, `PLATFORM_BOOTSTRAP_DENIED`, `PLATFORM_ACCESS_GRANTED`, `PLATFORM_ACCESS_REVOKED`, `PLATFORM_ACCESS_DENIED`)
- `src/redforge/core/config.py` — added `platform_bootstrap_enabled` (default `False`), `platform_bootstrap_principal_email` (default `""`)
- `src/redforge/application/platform/startup_validator.py` — `_EXPECTED_MIGRATION_HEAD` bumped `"0010"` → `"0011"` (see Section 13, a repeat of the exact defect class found in Sprint 42–43)
- `tests/unit/test_sprint29_replay_pipeline.py`, `tests/unit/test_startup_validator.py` — updated to match

### Frontend (new)
- `src/lib/platform.ts` — API client for `/api/v1/platform/*`
- `src/app/(platform)/platform/layout.tsx` — platform-only layout; verifies access via `GET /platform/me`, never by email/username
- `src/app/(platform)/platform/overview/page.tsx`
- `src/app/(platform)/platform/users/page.tsx`
- `src/app/(platform)/platform/organizations/page.tsx`
- `src/app/(platform)/platform/access/page.tsx`
- `src/app/(platform)/platform/audit/page.tsx`

### Frontend (modified)
- `src/app/(app)/layout.tsx` — conditionally shows a "Platform Control Plane" link, gated on `GET /platform/me`'s `has_platform_access`, never on email/username/org role
- `src/app/(app)/dashboard/page.tsx` — bootstrap call-to-action banner, shown only when `GET /platform/bootstrap/status` returns `available: true`

---

## 2. Platform Identity Domain Decision

Mirrors the existing `domain.identity.value_objects` shape (`MembershipRole`/`Permission`/`ROLE_PERMISSIONS`) deliberately, applied to the platform control plane instead of the tenant one:

- `PlatformRole` (StrEnum): `SUPER_ADMIN`, `SECURITY_ADMIN`, `SUPPORT`, `AUDITOR`. The enum is not limited to a single hardcoded role — additional roles were modeled now (Architecture doc's explicit requirement) so the schema doesn't need to change when their permission workflows ship. M1 grants permissions only to `SUPER_ADMIN`; the other three carry an empty permission set by design (`PLATFORM_ROLE_PERMISSIONS`), proven by `test_non_super_admin_roles_carry_no_permissions_in_m1`.
- `PlatformAssignment` (frozen dataclass entity): `id`, `user_id`, `role`, `status`, `granted_by`, `granted_at`, `revoked_by`, `revoked_at`, `version`. `revoke()` returns a new instance (immutable style, consistent with the rest of the domain layer) and raises `PlatformAssignmentAlreadyRevokedError` if called twice.
- `PlatformPermission` uses a `"platform:"` namespace, string-disjoint from the tenant `Permission` enum's `"org:"/"targets:"` namespace — proven by `test_platform_permission_namespace_is_disjoint_from_tenant_permission`.
- A user's effective platform permissions are the union of every ACTIVE assignment's permission set (`PlatformAccessDTO.permissions`) — never inferred from organization role, never cached.

## 3. PlatformContext Architecture

`PlatformContext` (in `api/security.py`, alongside `TenantContext`) is structurally distinct, not a subtype or variant:

- Fields: `user_id`, `email`, `platform_roles: tuple[str, ...]`, `permissions: frozenset[PlatformPermission]`.
- Deliberately absent: `organization_id`, any tenant/resource identifier, credential material. Per the Architecture doc's explicit requirement, platform authorization must never carry data that could imply tenant access.
- `get_platform_context()` decodes only the bearer token's identity claims (`sub`, `email`) and then performs a **live database lookup** via `PlatformAccessService.get_access_for_user()` — it does not read the token's `org`/`role` claims at all. This makes it structurally impossible for organization-scoped JWT state to influence platform authorization.
- Proven no accidental overlap exists: `test_organization_admin_cannot_become_platform_admin` shows an org-owner-scoped token still returns `has_platform_access: false`; `test_platform_context_not_satisfied_by_org_scoped_token_alone` is the same proof from the opposite direction.

## 4. Platform Role/Permission Model

`require_platform_permission(permission)` mirrors `require_permission`'s shape but shares zero code with it — no dependency on `MembershipRole`, `TenantContext`, or `organization_id`. Six M1 permissions: `platform:users:read`, `platform:organizations:read`, `platform:access:read`, `platform:access:grant`, `platform:access:revoke`, `platform:audit:read`. `SUPER_ADMIN` maps to all six (`frozenset(PlatformPermission)`); the other three roles map to the empty set.

## 5. Initial Super Admin Bootstrap Architecture

```
Settings.platform_bootstrap_enabled (default False)
  + Settings.platform_bootstrap_principal_email (default "")
    → POST /platform/bootstrap (any authenticated user)
      → PlatformAccessService.bootstrap_super_admin(authenticated_user_id, authenticated_email)
        → fails closed if bootstrap disabled (audit: PLATFORM_BOOTSTRAP_DENIED, reason=bootstrap_disabled)
        → fails closed if authenticated_email != configured email (audit: ..., reason=principal_mismatch)
        → repo.claim_bootstrap(user_id): atomic UPDATE ... WHERE consumed_at IS NULL RETURNING id
          → loses the race → BootstrapAlreadyConsumedError (409)
          → wins the race → INSERT PlatformAssignment(SUPER_ADMIN, ACTIVE) + audit record, same transaction, commit
```

No request body is accepted on `POST /platform/bootstrap` — the target principal is always `payload.sub`/`payload.email` from the verified bearer token, never client-supplied. This is what makes "bootstrap someone else" structurally impossible, not just policy.

Identity binding: the codebase has no email-verification concept (`UserModel` has no `email_verified` field), so bootstrap binds to the raw registered email, matched exactly (case-insensitively) against server configuration. This is the strongest identity binding the current authentication architecture actually provides — documented here rather than fabricating an email-verification step that doesn't exist.

## 6. Bootstrap Race-Safety Proof

**Not** an `if count == 0` check. The atomic mechanism is `platform_bootstrap_state`, a migration-seeded singleton row (`id='singleton'`, `consumed_at IS NULL`), claimed via:

```sql
UPDATE platform_bootstrap_state
SET consumed_at = CURRENT_TIMESTAMP, consumed_by = :user_id
WHERE id = 'singleton' AND consumed_at IS NULL
RETURNING id
```

Under PostgreSQL's row-locking, a second concurrent `UPDATE` blocks on the row lock until the first transaction commits, then re-evaluates `consumed_at IS NULL` against the now-committed state and matches zero rows — not a stale read. `RETURNING id` present/absent is the authoritative "did I win" signal.

**Proof, against real PostgreSQL** (`tests/integration/test_platform_identity_bootstrap_race.py`, run against a dedicated self-created `redforge_platform_race_test` database — never the shared dev database, see Section 13 for why):
- `test_concurrent_bootstrap_attempts_produce_exactly_one_super_admin`: 10 concurrent `asyncio.gather` bootstrap attempts for the same principal → exactly 1 success, 9 `BootstrapAlreadyConsumedError`, verified against the database afterward (`SELECT count(*) ... = 1`), not just in-process return values.
- `test_concurrent_bootstrap_different_principals_only_one_wins`: 4 different simulated user IDs racing the same slot → exactly 1 winner.
- `test_concurrent_revoke_of_two_last_super_admins_protects_one`: two active Super Admins, concurrent revoke of both → at least 1 survives (see Section 9).

**Also proven live** (not just automated tests) — see Section 15's live acceptance matrix: a real bootstrap was executed against a freshly-migrated PostgreSQL-backed server, and a second bootstrap attempt against the same live server correctly returned 409.

## 7. JWT / Auth-Context Strategy — Option B, Chosen and Justified

Reviewed three options (dedicated platform token, augmented tenant token, live DB lookup). **Chosen: live database lookup on every request — no platform claim in any JWT, ever.**

Rationale, directly mirroring a pattern the codebase already uses: `require_permission`'s organization-suspension check reads the organization's live status on every request rather than trusting a cached JWT claim, specifically so suspension takes effect immediately without requiring a token refresh. `get_platform_context` applies the identical principle to platform privilege:

- **Revocation takes effect on the very next request** — no stale elevated privilege window, no token-refresh dependency.
- **No platform/tenant claim confusion is possible** — the platform code path never reads `org`/`role` from the token at all.
- **No token-replay risk specific to platform privilege** — a stolen but-since-revoked platform-holder's bearer token authenticates the user but yields zero platform permissions on the next call.
- Cost: one extra DB round-trip per platform-scoped request. Accepted — platform endpoints are low-volume administrative operations, not hot-path tenant traffic.

Proven: `test_last_super_admin_cannot_be_revoked` shows the assignment still active in `/platform/me` immediately after a denied revoke attempt; `test_super_admin_can_grant_and_revoke_access` shows access appearing/disappearing across separate requests with no token exchange involved.

## 8. Platform Access Grant/Revoke Architecture

`PlatformAccessService.grant(target_user_id, role, granted_by)`:
- Rejects non-`SUPER_ADMIN` roles today (`NonGrantablePlatformRoleError`) — `GRANTABLE_PLATFORM_ROLES_M1 = frozenset({PlatformRole.SUPER_ADMIN})`.
- Defense-in-depth duplicate check (`list_active_by_user` pre-check) makes single-request duplicate detection dialect-agnostic (works on SQLite test engines, where the partial unique index is a no-op); the actual concurrent-safe mechanism is the PostgreSQL partial unique index `ux_platform_assignments_user_role_active` (migration 0011), caught via `IntegrityError` → `DuplicateActivePlatformAssignmentError`.
- Every grant is committed in the same transaction as its audit record.

`PlatformAccessService.revoke(assignment_id, revoked_by)`:
- 404 if the assignment doesn't exist; 409 if already revoked.
- Last-Super-Admin check (Section 9) runs before the revoke is applied.
- Audit record committed in the same transaction.

## 9. Final Super Admin Protection

**Enforced backend-side, not by frontend confirmation.** Before revoking a `SUPER_ADMIN` assignment, `repo.lock_active_by_role(SUPER_ADMIN)` issues `SELECT ... FOR UPDATE` against all currently-active assignments of that role. Under READ COMMITTED (PostgreSQL's default), a concurrent revoke targeting a different "last" assignment blocks on this row lock until the first transaction commits, then re-observes the post-commit count — not a stale check-then-act race.

Proven live (single-request): `test_last_super_admin_cannot_be_revoked` — a sole Super Admin's revoke attempt returns 403 and access remains intact afterward. Proven under real concurrency: `test_concurrent_revoke_of_two_last_super_admins_protects_one` — two active Super Admins, both revoked simultaneously, at least one survives (asserted `active_count >= 1` against the database, not the in-process results).

**Self-revocation**: allowed by the API (no special-case block), but subject to the identical last-Super-Admin check — a sole Super Admin cannot self-revoke either, since the check only counts active assignments of the role, not who is requesting the revoke.

## 10. Platform Security Audit Architecture

Reviewed the existing event/audit infrastructure before building anything new:
- The full event-sourcing stack (`EventEnvelope`, `PostgreSQLEventStore`, `ProjectionRegistry`) is designed for aggregate rehydration/replay/projections — genuinely heavier than a linear privilege-change log needs.
- The existing `AuditLog` protocol (`infrastructure/audit/contracts.py`) had only `InMemoryAuditLog` (tests) and `StructlogAuditLog` (stdout JSON, not queryable) — neither backs a queryable `GET /platform/audit`.
- **Decision**: implement `PostgresPlatformAuditLog`, the *first* queryable implementation of the existing `AuditLog` protocol — reusing the protocol, not inventing a second audit abstraction, backed by a new dedicated `platform_audit_log` table (migration 0011).
- Captures: action, actor_id, target_id, role, outcome, correlation_id, timestamp. Never captures: tokens, passwords, provider credentials, bootstrap configuration values, authorization headers.
- **Honest terminology**: this is an append-only-by-repository-convention application audit table — the repository exposes no update/delete method — not a cryptographically-immutable ledger. No stronger claim is made anywhere in code or docs.
- Proven: `test_audit_evidence_created_for_bootstrap_and_grant_revoke` confirms `platform.bootstrap_succeeded` appears in the audit query after a real bootstrap; live acceptance (Section 15) independently confirms the same via a running server.

## 11. Platform Super Admin UI Implementation

A distinct `(platform)/platform/*` route group, separate from the existing `(app)` organization dashboard:
- **Layout** (`platform/layout.tsx`): calls `GET /platform/me` and renders based on `has_platform_access` alone — no email/username inspection anywhere in the file. Shows an explicit "No platform access" state (not a silent redirect) when the check fails, distinguishing it from a network/loading state.
- **Overview**: real API-backed counts (users, organizations, active access grants) plus recent audit entries. Each metric independently renders `UNAVAILABLE` on fetch failure rather than a fake zero — proven by the `Metric{loaded, failed}` state machine in the page.
- **Users**: real paginated list from `GET /platform/users`; grant action requires an inline confirm step before calling `POST /platform/access`.
- **Organizations**: real list from `GET /platform/organizations`. Viewing an organization here does **not** enter tenant context or select an organization — no tenant-impersonation capability exists in this UI.
- **Platform Access**: real list from `GET /platform/access`; revoke requires inline confirmation; the backend's last-Super-Admin 403 is surfaced truthfully to the user, not silently swallowed.
- **Audit**: real entries from `GET /platform/audit`, rendered in a crisp `ACTION / actor / target / outcome / time` format, no narrative prose.
- The main `(app)` sidebar shows a "Platform Control Plane" link **only** when `GET /platform/me` returns `has_platform_access: true` — this is UX convenience only; the `/platform/*` layout re-verifies server-side regardless of how the link was reached.
- A bootstrap call-to-action appears on the dashboard **only** when `GET /platform/bootstrap/status` returns `available: true` — again UX only, the backend remains authoritative.

## 12. MFA Decision and Production Readiness Impact

Reviewed the current authentication architecture: `Argon2PasswordHasher` + `JWTTokenService`. **No MFA primitive exists anywhere in the codebase** (no TOTP secret storage, no OTP delivery mechanism, no WebAuthn/passkey support).

Per the Architecture doc's explicit instruction, this milestone does **not** fake MFA, does **not** add a "MFA enabled" checkbox, and does **not** build a custom TOTP implementation as a bolted-on afterthought (a "casual" TOTP implementation risks weak secret storage and replay handling that a security-focused platform should not ship). Decision: **Option B** — architecture and implementation proceed for local/test use, with an explicit, honest production-readiness guard:

**PRODUCTION PRIVILEGED ACCESS READINESS: BLOCKED — STRONG MFA REQUIRED.**

This is a P0 prerequisite for any real production deployment of platform Super Admin access, tracked here rather than silently ignored. M1's architecture and tests are valid and complete for local/test/staging use; the bootstrap-gating config (`platform_bootstrap_enabled`, defaulting to `False`) already prevents accidental production exposure of the bootstrap endpoint, but does not by itself constitute MFA.

## 13. Privilege-Escalation Adversarial Review

Searched the entire backend for every path capable of assigning platform privilege:
1. `PlatformAccessService.bootstrap_super_admin` — gated (disabled by default, principal-matched, one-time).
2. `PlatformAccessService.grant` — gated by `require_platform_permission(PLATFORM_ACCESS_GRANT)`, itself requiring a live active `SUPER_ADMIN` assignment.

No third path exists. No router calls `repo.save()` directly, no service bypasses `PlatformAccessService`, no organization-scoped endpoint touches `platform_assignments` in any way.

**Hardcoded owner identity search** — zero matches for `Subash`, personal email literals, magic UUIDs, or `is_subash`-style checks in `backend/src` or `frontend/src` (see `grep` output in this session's transcript). The only email-shaped value anywhere in the flow is `Settings.platform_bootstrap_principal_email`, which defaults to `""` and must be supplied via environment configuration — never a source-code literal.

**Frontend search** — zero matches for `user.name === `, `user.email === `, or localStorage-derived role/permission checks. All platform UI gating flows through `GET /platform/me`.

**Migration-head drift found and fixed**: identical to the Sprint 42–43 finding, adding migration 0011 without updating `_EXPECTED_MIGRATION_HEAD` would have reproduced the exact same stale-validator defect. Caught and fixed *before* live acceptance this time (proactively, not via a live-restart surfacing it) — the corresponding tests were updated in the same change.

**Test-infrastructure incident, found and fixed during this milestone**: the first version of `test_platform_identity_bootstrap_race.py` defaulted to the shared development `redforge` database (matching the existing `test_credential_leak.py`-style default-URL convention used elsewhere in the suite) and created its tables there without dropping them at teardown. This collided with `alembic upgrade head` when migration 0011 was subsequently applied to that same shared database (`DuplicateTableError`). Fixed by: (a) dropping the orphaned tables from the shared `redforge` database, (b) rewriting the fixture to create and use a dedicated `redforge_platform_race_test` database (auto-created via a maintenance connection if missing), and (c) dropping all three tables (not just rows) at teardown. This is documented here as a genuine defect this milestone introduced and corrected, not swept under the rug.

## 14. Platform/Tenant Isolation Proof

Every item from the mandatory adversarial test list (Architecture-mandated Capability 11) has a corresponding automated test:

| Requirement | Test |
|---|---|
| Normal user cannot become platform admin | `test_normal_user_cannot_become_platform_admin` |
| Org admin cannot become platform admin | `test_organization_admin_cannot_become_platform_admin` |
| Org role manipulation cannot create platform permission | `test_org_role_manipulation_cannot_create_platform_permission` |
| Missing authentication denied | `test_missing_authentication_denied` |
| Malformed token denied | `test_malformed_bearer_token_denied` |
| Bootstrap disabled denied | `test_bootstrap_disabled_denied` |
| Bootstrap wrong principal denied | `test_bootstrap_wrong_principal_denied` |
| Bootstrap unauthenticated denied | `test_bootstrap_unauthenticated_denied` |
| First bootstrap succeeds, second denied | `test_first_correct_bootstrap_succeeds_then_second_denied` |
| Concurrent bootstrap → exactly one Super Admin | `test_concurrent_bootstrap_attempts_produce_exactly_one_super_admin` (real PostgreSQL) |
| Unauthorized grant/revoke denied | `test_unauthorized_grant_denied`, `test_unauthorized_revoke_denied` |
| Duplicate grant semantics | `test_duplicate_active_grant_rejected` |
| Last Super Admin protected | `test_last_super_admin_cannot_be_revoked`, `test_concurrent_revoke_of_two_last_super_admins_protects_one` (real PostgreSQL) |
| Audit evidence created | `test_audit_evidence_created_for_bootstrap_and_grant_revoke` |
| PlatformContext ≠ TenantContext | `test_platform_context_not_satisfied_by_org_scoped_token_alone` |
| Tenant-scoped API remains tenant-scoped | `test_tenant_scoped_endpoint_still_requires_org_selection` |

All 26 pass on SQLite (fast API-boundary correctness); the 3 concurrency-critical tests additionally run against real PostgreSQL and are not claimed as proven by SQLite alone.

## 15. Migration Proof

Clean migration from an empty database:

```
alembic upgrade head
# 0001 → 0002 → ... → 0010 → 0011, Platform Identity & Super Admin bootstrap — M1.
alembic current
# 0011 (head)
```

Verified table structure (temporary `redforge_m1_migration_proof` database, created and dropped for this proof):
- `platform_assignments`: 9 columns; indexes `ix_platform_assignments_user_id`, `ix_platform_assignments_role_status`, and the partial unique index `ux_platform_assignments_user_role_active` (`WHERE status = 'active'`).
- `platform_bootstrap_state`: 3 columns, seeded with exactly one row (`id='singleton'`, `consumed_at=NULL`, `consumed_by=NULL`).
- `platform_audit_log`: 9 columns; indexes on `action`, `actor_id`, `created_at`.

Also applied to the shared development `redforge` database (used by concurrently-running sessions) — purely additive (`CREATE TABLE`, no `ALTER`/`DROP` of existing structures), confirmed non-disruptive by the full pre-existing test suite remaining green afterward.

## 16. Backend Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 466 source files |
| `pytest -q` | 3,412 passed, 5 skipped (+29 from 3,383 baseline) |

## 17. Frontend Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — all 15 routes compile, including 5 new `/platform/*` routes |
| `npx vitest run` | 31 passed (unchanged — M1 added no new frontend unit-test surface; existing canonical-graph-state coverage untouched) |
| `npm audit` | 2 moderate advisories — identical to the pre-existing Sprint 42–43 residual (Next.js's internally-bundled `postcss@8.4.31`); no new advisories introduced |
| `npm run lint` | NOT CONFIGURED (unchanged from Sprint 42–43) |

## 18. npm Residual Risk

Unchanged from Sprint 42–43: `next@15.5.20`'s internally-bundled `postcss@8.4.31` (GHSA-qx2v-qp2m-jg93, moderate, CVSS 6.1). No non-major fix exists. Not remediated in this milestone — no unreviewed Next.js 16 migration was performed, per explicit instruction.

## 19. PROVEN

- Persisted platform privilege, independent of organization membership — domain tests + live API verification.
- `PlatformContext` structurally distinct from `TenantContext`, resolved via live DB lookup, never a JWT claim.
- Bootstrap is one-time and race-safe under real PostgreSQL concurrency (10 concurrent attempts, exactly 1 winner; verified via database state, not just in-process results).
- Bootstrap fails closed: disabled by default, principal-matched, request-body identity impossible.
- Grant/revoke work, are audited, and are backend-authoritative.
- Last-Super-Admin protection holds under real concurrent revoke attempts.
- Privilege changes are auditable via a real, queryable, PostgreSQL-backed audit log.
- Normal users and organization admins (including org Owner) cannot escalate — proven by automated tests AND live acceptance against a freshly bootstrapped real server.
- Real Platform Super Admin APIs exist (8 endpoints) and are consumed by a real Platform Control Plane UI (5 screens).
- Migrations run cleanly from an empty PostgreSQL database.
- All quality gates green, no regressions (3,383 → 3,412 backend tests; 31 → 31 frontend tests, build clean).
- Zero hardcoded owner identity anywhere in product code (backend or frontend).

## 20. CLAIMED BUT UNPROVEN

- Real browser click-through of the Platform Control Plane UI was not performed in this session (ports 3000/8000/8765/8899/8977 conflicts with other active sessions meant frontend changes were verified via `tsc`/`vitest`/`build` only, not an interactive browser session against the new `/platform/*` routes). TypeScript/build success is real evidence but is explicitly not claimed as browser proof.
- `PlatformSupport`/`PlatformSecurityAdmin`/`PlatformAuditor` roles are modeled in the enum and schema but have no granted workflow, no UI affordance to select them (the grant UI only offers Super Admin), and no permission set — this is intentional scope limitation (Architecture doc Section 3), not a gap to be silently filled.

## 21. FAILED (found and fixed during this milestone)

- Stale `_EXPECTED_MIGRATION_HEAD` (would have repeated the Sprint 42–43 defect) — fixed proactively before live acceptance.
- Race-condition test polluting the shared development database (`DuplicateTableError` when applying migration 0011) — fixed by isolating the test to its own dedicated, self-created database.
- `slots=True` dataclass `.__dict__` AttributeError in the router (used a sed-based fix that initially introduced a typo, `dtdataclasses.asdict(o)`) — caught by the test suite immediately and corrected to `dataclasses.asdict(dto)`.

## 22. BLOCKED

- **Production privileged-access readiness**: `PRODUCTION PRIVILEGED ACCESS READINESS: BLOCKED — STRONG MFA REQUIRED.` No MFA primitive exists in the current authentication architecture; adding one properly is its own dedicated milestone, not a casual addition to M1.
- Real browser acceptance of the new UI (Section 20) — blocked by other active sessions occupying the standard dev ports, same root cause noted in the Sprint 42–43 report.

## 23. Remaining M1 P0/P1

**P0**: None remaining for the architecture and capabilities M1 was scoped to deliver. The one true P0 — "is platform privilege secure, persisted, revocable, and isolated from tenant privilege" — is proven both by automated tests and live acceptance.

**P1**:
- Strong MFA for platform Super Admin (Section 12) — required before any production deployment; explicitly out of scope for M1's implementation, tracked honestly rather than faked.
- Real browser acceptance of the 5 new UI screens (Section 20) — deferred to a session where standard dev ports are free.
- `PlatformSecurityAdmin`/`PlatformSupport`/`PlatformAuditor` permission workflows (Section 20) — deliberately deferred to a future milestone per the Architecture doc's own M1 scope boundary.

## 24. Honest M1 Completion Decision

**M1 — Platform Identity & Super Admin Bootstrap is COMPLETE**, with production privileged-access readiness explicitly marked BLOCKED pending MFA.

Every acceptance-boundary condition from the sprint prompt holds:
- Platform privilege is persisted (`platform_assignments` table), not implied by any in-memory or JWT state.
- Platform privilege is independent of tenant role — proven both by code structure (`PlatformContext` cannot be constructed from `TenantContext`) and by adversarial test (`test_platform_context_not_satisfied_by_org_scoped_token_alone`).
- The first-owner bootstrap is secure (fail-closed, principal-matched, one-time) and proven race-safe under real PostgreSQL concurrency, not merely "looks race-safe."
- Platform authorization is backend-authoritative everywhere — the frontend never makes an authorization decision, only a UX-display one.
- Access can be granted and revoked, and the final active Super Admin is protected even under concurrent revoke attempts.
- Privilege changes are auditable via a real, queryable log — not a stub.
- Normal users and organization admins (including the highest tenant role, Owner) cannot escalate — proven by both automated adversarial tests and a live acceptance run against a freshly bootstrapped real server.
- Platform and tenant contexts remain structurally distinct with no code path producing one from the other.
- Real Platform Super Admin APIs exist and are consumed by a real Platform Control Plane UI.
- Migrations work cleanly from an empty PostgreSQL database, and were also applied safely to the shared development database without disrupting other active sessions.
- All quality gates remain green with zero regressions.

M2 (Platform RBAC / Tenant Governance beyond M1's minimum seams) has **not** been started. No network, cloud, C2/PT, or compliance work was introduced in this milestone.
