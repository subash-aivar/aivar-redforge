# M17 — Enterprise Identity, Super Admin & RBAC Control Plane

## Architecture decision

Reconnaissance established that platform-level Super Admin authority is **100% pre-existing** (built in M1/M2): `domain/platform_identity/` (`PlatformAssignment` with optimistic-concurrency `version`, `PlatformRole`, `PlatformAssignmentStatus`), `application/platform_identity/` (`PlatformAccessService`, `PlatformGovernanceService`, `PlatformQueryService`), `api/security.py`'s `PlatformContext`/`get_platform_context` (a live DB lookup on every request, never trusted from JWT claims — structurally distinct from `TenantContext`), migration `0011_platform_identity.py`, and a config-gated, principal-matched, atomically-one-time `POST /api/v1/platform/bootstrap`. This is exactly the canonical, persisted, non-forgeable platform authority model M17 required — it was reused **unchanged**.

The genuinely missing capability was **organization-scoped custom Roles, Groups, and their effective-access machinery** on top of the pre-existing fixed `MembershipRole`/`ROLE_PERMISSIONS` RBAC table (`domain/identity/value_objects.py`). The pre-existing code's own docstring anticipated this as deferred future work and was structured so the addition is additive, not a rewrite of `Membership.has_permission()`'s enforcement path.

**No new identity system, no new auth path, no duplicate user database, no parallel RBAC engine was created.** M17 added one new bounded context (`domain/rbac/`, `application/rbac/`) that composes with the existing `Permission`/`MembershipRole`/`TenantContext` types, plus one additive enrichment inside the existing `get_tenant_context` dependency.

## Platform authority model

Unchanged from M1/M2. Super Admin authority lives in `platform_assignments`, is resolved via a live `PlatformAccessService.get_access_for_user()` call on every platform-scoped request (never cached in a JWT claim), requires explicit grant/revoke through `PlatformAccessService`, and cannot be self-granted, obtained via any organization role, or forged via JWT. Organization custom roles are structurally incapable of carrying platform authority: `OrganizationRole.permissions` is typed `frozenset[Permission]` (the tenant-scoped enum), which has no constructor path to a `PlatformPermission`.

## Bootstrap

Unchanged from M1/M2: `POST /api/v1/platform/bootstrap`, gated by `platform_bootstrap_enabled` + `platform_bootstrap_principal_email` configuration (documented in `.env.example`, no real personal values), atomically one-time via a singleton-claim table (`platform_bootstrap_state`), no public unauthenticated path, no default password, no hidden backdoor.

## User lifecycle & organization administration

Reused unchanged: `PlatformGovernanceService` (suspend/reactivate users and organizations), `PlatformQueryService` (list/search/detail), and the existing Super Admin frontend pages (`frontend/src/app/(platform)/platform/{overview,users,organizations,access,audit,security}/page.tsx`). Organization admin assignment remains canonically RBAC-based (`MembershipRole.ADMIN` / custom roles with `ROLES_MANAGE`) — there is no boolean "is admin" flag anywhere in the schema.

## Group model

New domain entity `OrganizationGroup` (`domain/rbac/entity.py`): ULID id, `organization_id`, normalized-unique name per org (`normalize_name()` — lowercase + collapsed whitespace, mirroring the existing `OrganizationSlug` discipline), `version` for optimistic concurrency, `AuditTimestamps`. No nested groups (not previously supported, not added). Persisted via migration `0026`'s `organization_groups` / `organization_group_memberships` / `organization_group_roles` tables, each with tenant-integrity composite foreign keys (see Migration section) making cross-tenant group membership or role assignment a **database-level impossibility**, not just an application-layer check.

## Role model

New domain entity `OrganizationRole` (`domain/rbac/entity.py`): ULID id, `organization_id`, normalized-unique name per org, `permissions: frozenset[Permission]`, `is_system: bool`, `version`, `AuditTimestamps`. `rename()`/`set_permissions()` raise `SystemRoleImmutableError` if `is_system`.

**System roles are synthetic and never persisted.** `RoleService.list_roles()`/`get_role()` synthesize a `RoleDTO` for each of the 6 `MembershipRole` values (`id="system:<role>"`, permissions from the existing `ROLE_PERMISSIONS` table, `is_system=True`). Because no database row exists for a system role, "system roles cannot be mutated" is a **structural guarantee** — `RoleService._load()` raises before even attempting a lookup if the id has the `system:` prefix — not merely an application-level check that could be bypassed by a code path that forgets to call it.

Custom roles are ordinary persisted rows (migration `0026`'s `organization_roles` / `organization_role_permissions`), each scoped to one organization with a composite-unique `(id, organization_id)` used as the FK target for every downstream assignment table.

## Permission catalog

`GET /api/v1/admin/permissions` is the single backend-authoritative source, grouped by domain (split on `:` in the permission's string value), gated by `Permission.ROLES_READ`. The frontend fetches this catalog and renders it — it does not maintain any hardcoded permission list of its own.

## Effective-access calculation

One canonical calculation, `application/rbac/effective_access_service.py`'s `EffectiveAccessService`:

- `explain(organization_id, user_id)` — the full read model: fixed-role (`ROLE_PERMISSIONS[membership.role]`) ∪ direct custom-role permissions ∪ group-derived custom-role permissions, with each contributing source broken out separately (`membership_permissions`, `direct_role_*`, `groups: [{group_id, role_ids, permissions}]`) plus the final `effective_permissions` union. This is the literal "why does this user have this permission?" explain view, exposed at `GET /api/v1/admin/users/{user_id}/effective-access` (self-service for one's own user_id, otherwise gated by `ROLES_READ`).
- `get_additional_permissions(organization_id, user_id)` — the fast path (two indexed JOINs, direct ∪ group-derived, no fixed-role permissions mixed in since those are already known from the JWT's role claim) called on **every** authenticated tenant-scoped request from `api/security.py`'s `get_tenant_context`. Purely additive: `permissions=ROLE_PERMISSIONS[role] | additional`. For any organization with no M17 custom roles/groups configured, `additional` is the empty set and behavior is byte-for-byte identical to pre-M17.
- `is_membership_active(organization_id, user_id)` — a live per-request check, added during adversarial testing after it surfaced that a membership suspended *after* a token was issued kept working indefinitely (see Independent security review). Now enforced on every tenant-scoped request, matching the "never trust the JWT for standing" discipline the codebase already applied to global user status and organization suspension.

Platform Super Admin authority is never mixed into this calculation — `EffectiveAccessDTO` has no platform fields, and `PlatformContext`/`TenantContext` remain structurally distinct types with no shared base class.

## Privilege grant policy

One centralized policy, `application/rbac/grant_policy.py`'s `assert_can_grant(actor_permissions, requested)`: raises `PrivilegeEscalationError` if `requested - actor_permissions` is non-empty. This is the single call site used by every permission-granting mutation (`RoleService.create_role`, `RoleService.set_permissions`, `RoleService.assign_direct_role`, `GroupService.assign_role`) — an actor can never grant a permission they do not themselves effectively hold. Because granting is always bounded by the actor's *current* effective permissions, no sequence of role/group mutations can ever produce a permission set larger than what an OWNER/ADMIN already independently holds — this structurally forecloses self-escalation, role-widening, and indirect group-derived escalation, without needing separate ad-hoc checks scattered across endpoints.

## Administrative audit

`infrastructure/audit/organization_admin_audit_log.py`'s `PostgresOrganizationAdminAuditLog` (deliberately separate from the platform's `PostgresPlatformAuditLog` — it takes an `organization_id` parameter the generic `AuditLog` protocol doesn't have). 13 new `AuditAction` members cover every RBAC mutation (role/group create/update/delete/permissions-changed/member-added/removed/role-assigned/revoked, user-role-assigned/revoked). Read via `GET /api/v1/admin/audit-events`. Never records passwords, tokens, secrets, or raw auth headers — `metadata` is a bounded, deliberately-populated JSON object per call site.

## Super Admin API / frontend

Unchanged from M1/M2 — reused as-is, per the reconnaissance finding that this surface was already complete and correct.

## Organization Admin API

`api/v1/admin_rbac.py`, mounted at `/api/v1/admin`, deliberately following the M14-M16 "no organization_id in the URL" convention (derived from `TenantContext`, not a path parameter) to eliminate ID-confusion attack surface entirely. Full CRUD for roles/groups, permission catalog, direct role assignment, group membership/role assignment, effective-access explain, and the audit trail — see the RBAC report's route table in `api/v1/admin_rbac.py`'s own router definition for the exact list.

## Organization Admin frontend / Access Explorer

See the M17 completion checkpoint for the exact file list and verification status of the frontend build (Roles & Permissions with a permission-matrix editor, Groups with membership/role management, and the Access Explorer view).

## Migration 0026

`0026_rbac_groups_and_custom_roles.py`, `down_revision="0025"`. Seven new tables: `organization_roles`, `organization_role_permissions`, `organization_groups`, `organization_group_memberships`, `organization_group_roles`, `organization_user_roles`, `organization_admin_audit_log`. Tenant-integrity is enforced at the database level, not just in application code: every assignment table's foreign key targets a **composite** `(id, organization_id)` unique constraint on the parent (roles/groups), so a role or group can only ever be referenced from within its own organization — cross-tenant assignment is a constraint violation, not merely a rejected application check. Normalized-name uniqueness (`UniqueConstraint(organization_id, normalized_name)`) is concurrency-safe at the database level; the application layer additionally catches the resulting `IntegrityError` and re-raises it as the domain-specific `DuplicateRoleNameError`/`DuplicateGroupNameError` (see Real defects found, below) rather than surfacing a raw 500.

Verified: `0001` → `0026` → `0025` → `0026` up/down/up on the dedicated proof database, clean.

## PostgreSQL concurrency proof

`tests/integration/test_rbac_live_acceptance.py`'s 4 concurrency tests, run against real PostgreSQL via `asyncio.gather` over real HTTP calls: `test_concurrent_duplicate_group_creation_converges_on_one_winner`, `test_concurrent_duplicate_role_creation_converges_on_one_winner`, `test_concurrent_group_membership_assignment_never_duplicates`, `test_concurrent_role_assignment_to_group_never_duplicates`. All pass, proving the database-level unique constraints (not the racy pre-check) are the true backstop for concurrent duplicate creation and duplicate membership/assignment.

## Adversarial test suite

`tests/integration/test_rbac_live_acceptance.py` (18 tests) plus `tests/unit/test_rbac_grant_policy_and_domain.py` (9 fast no-DB unit tests) cover: the golden path (role/group creation → assignment → effective access), real enforcement (a custom role's permission genuinely unlocks an endpoint on the *same* already-issued token, no re-login), privilege-escalation rejection (a member with `ROLES_MANAGE` cannot grant a permission they don't hold), unknown-permission-string rejection (400, not 500), cross-tenant non-disclosure (roles/groups/effective-access), malformed/unknown ID handling (404, not 500), duplicate name rejection, idempotent duplicate membership/assignment, system-role immutability, deletion blocked while assigned/while members exist, suspended-member immediate lockout, 4 real-PostgreSQL concurrency races, and audit-trail correctness/tenant-scoping.

## Real defects found and fixed during this milestone

1. **Suspended-membership bypass (security gap, not merely a test gap).** `get_tenant_context` checked global user status and organization suspension live on every request, but never re-checked the individual organization *membership's* status — a membership suspended after a token was issued kept working until the token naturally expired. Fixed by adding `EffectiveAccessService.is_membership_active()` and enforcing it in `get_tenant_context`, closing the gap for every organization, not just ones using M17 custom roles/groups.
2. **TOCTOU duplicate-name race.** `create_role`/`create_group`/`update_role_metadata`/`update_group`'s pre-check (`get_by_normalized_name`) raced against the actual INSERT under concurrent load. Found by code review (not a failing test), fixed by wrapping the save in `try/except IntegrityError` → rollback → re-raise as the domain exception, making the database's own unique constraint the real backstop.
3. **M17-introduced test regression.** Adding `EffectiveAccessService` as a dependency of `get_tenant_context` broke 28 pre-existing test files that build isolated FastAPI apps without a real database engine (they override every other DB-touching dependency but hadn't been updated for the new one). Fixed by adding the matching `dependency_overrides` entry to each (a `_NoOpEffectiveAccessService` stub for files with no real test-local database, or a real `EffectiveAccessService(factory)` for the one file that already runs its own SQLite-backed services).

## Independent security review

Performed as part of building and adversarially testing the grant policy, effective-access calculation, and tenant-context enrichment (see Real defects found, above, for the one genuine finding: suspended-membership bypass). Reviewed and found sound: privilege escalation (structurally bounded by `assert_can_grant`), confused deputy (every mutation re-derives the actor's permissions live, never trusts a client-supplied actor identity), tenant isolation (composite FKs at the database level), platform/org authority mixing (structurally distinct types, no shared fields), stale JWT authority (both platform and now tenant-membership status are live-checked, never cached), escalation via role/group mutation (bounded delegation), stale-aggregate races (optimistic `version` + `IntegrityError` backstop), malformed-ID handling (404, not 500, verified by test), audit secret leakage (bounded metadata, never raw headers/tokens/passwords), frontend authorization assumptions (backend is sole enforcement point; frontend visibility is UX-only), bootstrap exposure/replay (unchanged, already proven in M1/M2), system-role mutation (structurally impossible, no row exists), effective-access inconsistency (one canonical calculation, two call sites sharing the same underlying repository queries).

## Quality gates

See the M17 completion checkpoint for exact backend/frontend gate results, live API acceptance counts, and browser acceptance status.
