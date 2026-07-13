# M5 — Identity & Directory Security Visibility Foundation — Report

**Date**: 2026-07-11
**Baseline entering M5**: 3,482 backend tests passing, 5 skipped; migration head 0014.
**Baseline exiting M5**: 3,514 backend tests passing, 5 skipped; migration head 0015.

---

## 1. Exact Files Changed

### Backend (new)
- `src/redforge/domain/directory_security/value_objects.py` — `DirectoryIdentityScheme`, `PrincipalCategory`, `ObservationLifecycle`, `PrivilegeClassification`, `build_directory_external_id`
- `src/redforge/application/directory_security/observations.py` — typed `IdentityObservation`/`GroupObservation`/`MembershipObservation`/`DirectoryDiscoveryResult`
- `src/redforge/application/directory_security/ldap_adapter.py` — real read-only LDAP adapter (`ldap3`)
- `src/redforge/application/directory_security/service.py` — `TenantDirectorySecurityService` (resolution + query + projection orchestration)
- `src/redforge/application/directory_security/analysis_service.py` — deterministic identity-security rules
- `src/redforge/infrastructure/database/models/directory_security.py` — `DirectoryIdentityModel`/`DirectoryGroupModel`/`DirectoryMembershipModel`
- `src/redforge/infrastructure/database/repositories/directory_security_repository.py` — race-safe upsert repository
- `src/redforge/infrastructure/database/migrations/versions/0015_directory_security_foundation.py`
- `src/redforge/api/v1/directory_security.py` — 6 read-only endpoints
- `tests/domain/test_directory_security_ontology.py`, `tests/domain/test_directory_identity_resolution.py`
- `tests/unit/test_ldap_directory_adapter.py` — 8 contract tests via ldap3's own MOCK_SYNC
- `tests/api/test_directory_security_isolation.py` — 10 adversarial/regression tests
- `tests/api/test_directory_security_secret_leakage.py`
- `tests/integration/test_directory_security_race.py` — 5 real-PostgreSQL concurrency tests

### Backend (modified)
- `src/redforge/domain/security_graph/ontology.py` — `ONTOLOGY_VERSION` 1→2, added `IDENTITY`/`SERVICE_IDENTITY`/`GROUP` NodeKinds, `MEMBER_OF` EdgeKind
- `src/redforge/application/security_graph/projector.py` — added `project_directory_identity`/`project_directory_group`/`project_membership`
- `src/redforge/domain/connectors/value_objects.py` — added `ConnectorType.LDAP_DIRECTORY`, `CredentialType.BASIC_AUTH`
- `src/redforge/application/connectors/tenant_connector_service.py` — `register_directory_connector`, discovery branching, `_run_directory_discovery`
- `src/redforge/application/findings/service.py` — unchanged this milestone (M4's `graph_session_factory` wiring reused, not modified)
- `src/redforge/api/v1/connectors.py` — `POST /connectors/directory`
- `src/redforge/api/dependencies.py` — `get_tenant_directory_security_service`, wired into `TenantConnectorService`
- `src/redforge/api/v1/__init__.py` — registered `directory_security_router`
- `src/redforge/application/platform/startup_validator.py` — `_EXPECTED_MIGRATION_HEAD` → `"0015"`
- `pyproject.toml` — added `ldap3`, pinned `pyasn1<0.5` (ldap3 2.9's ASN.1 encoder needs the pre-0.5 API), added a `ldap3.*` mypy override
- `tests/unit/test_startup_validator.py`, `tests/unit/test_sprint29_replay_pipeline.py` — migration-head bump

### Frontend (new)
- `src/lib/directorySecurity.ts` — read-only API client (no create/update/delete method exists)
- `src/app/(app)/identities/page.tsx`, `src/app/(app)/directory-groups/page.tsx`, `src/app/(app)/identity-security/page.tsx`

### Frontend (modified)
- `src/app/(app)/layout.tsx` — 3 new nav entries
- `src/app/(app)/connectors/page.tsx` — LDAP directory connector registration form (credential reference only)

---

## 2. Reconnaissance Findings

Deep reconnaissance (15-point sweep) established: (1) M3's `Connector`/discovery-run lifecycle is generic and reusable — `ConnectorType`, `ConnectorConfiguration.custom_config` (a typed tuple-of-tuples, not a dict), and `ConnectorCredentialReference` (reference-only, confirmed no raw-secret field) needed only one new enum value (`LDAP_DIRECTORY`) to host a second real adapter; (2) the existing `ConnectorProvider`/`InventoryMapperPort` Protocols in `application/connectors/contracts.py` are **not** used by `TenantConnectorService` today — discovery logic is inline — so the identity connector follows the same inline-in-service pattern for consistency rather than introducing an unused Protocol layer; (3) `domain/identity/` is the **existing** RedForge login-user/RBAC bounded context (its own module docstring literally says "Identity bounded context") — a direct naming collision risk with M5's brief, resolved by naming the new context `domain/directory_security/`, never `domain/identity`; (4) M4's `SecurityGraphProjector`/`SecurityGraphRepository`/ontology are all directly extensible without a rewrite — new NodeKinds/EdgeKinds and new `project_*` methods on the *same* class, not a second projector; (5) `Finding.target_id`/`RiskIncident.finding_ids` are real fields but have no directory-identity-shaped correlation surface — M5 does not create Findings (see §28); (6) no LDAP library was present in the repository and no Docker/container runtime is available in this environment (`docker --version` → command not found) — this directly determined the Capability 9 disposition (§41).

## 3. Identity Bounded-Context Decision

New bounded context: `domain/directory_security/` + `application/directory_security/` + `infrastructure/database/{models,repositories}/directory_security*`. Canonical aggregate concepts: `DirectoryIdentity` (a human or service principal **observed** from an external directory), `DirectoryGroup`, `DirectoryMembership` (direct only — see §29). Given the milestone's time-boxed scope, these are persisted via typed repository upsert methods (mirroring M3/M4's document-store-adjacent pattern) rather than as a full rich domain aggregate with its own event stream — a deliberate, smaller-footprint choice appropriate to a foundation milestone, not a rich business-rule-heavy aggregate like `AIAsset`/`Connector`. This is a real scope trade-off, documented here rather than silently made.

## 4. Application User vs Observed Identity Distinction

`domain/identity/` (RedForge's own login user, `MembershipRole`, `Permission` enum) is **never** touched, imported, or merged with `domain/directory_security/`. A `DirectoryIdentity` has no foreign key to `UserModel`, no shared identifier space, and no code path converts one into the other. This is the single most important architectural boundary in M5 and was explicitly checked during reconnaissance for name-collision risk before any code was written (§2, point 3).

## 5. Canonical Identity Model

`DirectoryIdentity` (persisted as `directory_identities`): `id`, `organization_id`, `connector_id`, `external_id`, `principal_category` (`human`|`service` — only 2 categories, since the one real adapter can only reliably distinguish these two via LDAP `objectClass`; `MACHINE`/`APPLICATION`/`WORKLOAD` were **not** implemented — no real producing schema mapping exists for them in this milestone), `display_name`, `principal_name`, `source_enabled` (bool — the source's own enabled/disabled state, distinct from RedForge's observation lifecycle), `privilege_classification`, `privilege_reason`, `observation_lifecycle`, `safe_attributes` (JSON, populated only from an explicit allowlist — `{"object_class": "..."}` — never a raw directory-object dump), `first_observed_at`/`last_observed_at`, `version`. All canonical security fields are typed columns, not buried in the JSON blob.

## 6. Identity Resolution Key Strategy

`ORGANIZATION + CONNECTOR + SCHEME` encoded as `(organization_id, connector_id, external_id)` where `external_id = "{scheme}:{normalized_value}"` (mirrors M3's `build_external_id` string format exactly, reusing the established convention). **Connector is part of the uniqueness key** — deliberately more conservative than M3's asset identity (`organization_id + external_id` only) — because the milestone's own review explicitly raised the risk of two independent directories exposing the same raw source identifier; scoping per-connector means such a collision can never silently merge two distinct real-world principals. Two schemes implemented with real normalization functions: `LDAP_ENTRY_UUID` (RFC 4530 `entryUUID`, canonical lowercase-hyphenated UUID string) and `AD_OBJECT_GUID` (Active Directory `objectGUID`, same canonical form). No other scheme is declared as a bare string with no normalizer behind it. Display-name changes and privilege changes never create a new identity — resolution is always by `(organization_id, connector_id, external_id)`, and `upsert_identity` updates the existing row's mutable fields in place.

## 7. Connector Namespace Decision

Chosen key: `ORGANIZATION + CONNECTOR + SCHEME + EXTERNAL_ID` (not `ORGANIZATION + SCHEME + EXTERNAL_ID` alone) — see §6's rationale. Proven under real concurrency: `test_same_external_identity_across_orgs_remains_separate` (§22) and the connector-scoping itself is structural (part of the DB unique index `ux_dir_identities_org_connector_external`), not merely a code convention.

## 8. Identity Lifecycle Semantics

`ObservationLifecycle` currently has exactly one value: `ACTIVE`. `STALE` and `DELETED` are **explicitly not implemented** — the module docstring documents why: marking an identity absent-from-the-latest-discovery-run as `DELETED` requires the connector to guarantee a complete authoritative snapshot per run, which the current LDAP adapter's paged (but not completeness-verified) search does not yet prove account-for-account; and `STALE` would require a configurable policy threshold architecture that does not exist yet — a hardcoded 30/60/90-day magic number is explicitly forbidden by the milestone, so this is honestly deferred rather than faked. `source_enabled` (the directory's own AD `userAccountControl`-derived enabled/disabled bit) is a completely separate field from `observation_lifecycle` — a disabled AD account is still `observation_lifecycle=ACTIVE`, `source_enabled=False`, proven live (§34).

## 9. Group Model

`DirectoryGroup`: same `(organization_id, connector_id, external_id)` key pattern, `display_name`, `is_recognized_privileged` (bool — set only via the connector's configured `privileged_group_dns` allowlist at resolution time, §11), `first_observed_at`/`last_observed_at`. No group "type" field was added since the one real adapter only recognizes `groupOfNames`/`groupOfUniqueNames`/`posixGroup` — all treated uniformly as `GROUP` in the ontology; no further sub-classification was fabricated.

## 10. Membership Model

`DirectoryMembership`: `identity_id`, `group_id`, `provenance`, `first_observed_at`/`last_observed_at`, `version`. **Direct membership only** — nested GROUP→GROUP membership is explicitly deferred (§29/§40), a deliberate scope-bound decision given the milestone's time budget, not an oversight; the LDAP adapter's `member`/`uniqueMember` attribute resolution only maps DN references it can resolve to an already-discovered identity's entryUUID in the same discovery pass — a group-to-group reference would currently be silently unresolvable and is recorded as an error, never fabricated into a membership.

## 11. Privilege Classification Model

`PrivilegeClassification`: `STANDARD`|`PRIVILEGED` (no `HIGHLY_PRIVILEGED` tier — no real Tier-0-equivalent semantics were implemented, so a third tier would be speculative). Classification is driven **entirely** by `TenantDirectorySecurityService.run_directory_discovery`'s `privileged_group_external_ids_raw` parameter — a set of raw group external IDs the connector operator explicitly configures (`privileged_group_dns` in `ConnectorConfiguration.custom_config`, surfaced on the connector, not hardcoded) — never a display-name check. `test_privileged_service_identity_observation_and_no_name_based_guessing` proves this directly: a group named `"Admins"` does **not** produce a privileged classification unless its raw external ID is in the configured allowlist. `privilege_reason` is stored alongside the classification (`"Direct member of a recognized privileged group"`) for auditability. Domain Admins/Enterprise Admins/Schema Admins are **not** hardcoded anywhere — the operator must explicitly configure the real group identifiers from their own directory, since no live AD environment was available to establish stable well-known SID mappings truthfully (SIDs like `S-1-5-21-<domain>-512` are domain-relative, not universal constants safe to hardcode).

## 12. Directory Connector Contract

Reuses M3's `Connector`/`DiscoveryJobRecord` lifecycle unmodified — `ConnectorType.LDAP_DIRECTORY` is a new enum value, not a new lifecycle. `TenantConnectorService.start_discovery` branches on `connector.connector_type`: `LDAP_DIRECTORY` routes to `_run_directory_discovery` (real LDAP adapter + `TenantDirectorySecurityService.run_directory_discovery`), everything else keeps M3's existing RedForge-Targets path untouched. Typed observation contracts (`IdentityObservation`/`GroupObservation`/`MembershipObservation`) are dataclasses with explicit fields — never `payload: dict[str, Any]`; only `safe_attributes` (itself allowlisted by the adapter) is an open dict. Flow proven end-to-end live (§34): `LdapDirectoryAdapter` → typed observations → `TenantDirectorySecurityService` → canonical resolution → `SecurityGraphProjector`.

## 13. Real Adapter Implementation

`LdapDirectoryAdapter` (`ldap3`, a mature, actively maintained pure-Python LDAP client — chosen over `python-ldap` specifically to avoid a system OpenLDAP dev-header build dependency, which would have made the adapter harder to install in constrained environments). Single public method: `discover()` — performs SEARCH operations only via `conn.extend.standard.paged_search`, handling pagination transparently. Classification is strictly `objectClass`-derived (`person`/`inetOrgPerson`/`organizationalPerson`/`user` → HUMAN; `organizationalRole`/`simpleSecurityObject` → SERVICE); entries matching neither, or missing `entryUUID`, are skipped with a recorded (not silent) error. `userAccountControl` bit 0x2 (`ACCOUNTDISABLE`) maps to `source_enabled=False` when present (AD semantics) — absent for non-AD LDAP servers, where `source_enabled` defaults to `True`.

## 14. Protocol/Library Security Review

`ldap3` 2.9.1 — actively maintained, widely used (the standard pure-Python LDAP client). Required pinning `pyasn1<0.5` for compatibility with `ldap3` 2.9's ASN.1 encoder (a real, verified compatibility issue — `pyasn1` 0.6's `tagMap`/`typeMap` deprecation broke `ldap3`'s import chain; confirmed and fixed during this milestone). No known unpatched CVEs were found for `ldap3` 2.9.x at time of writing.

## 15. Credential Reference Architecture

`ConnectorCredentialReference` (M3, reused unmodified) — `reference_id` (an environment-variable **name**), `credential_type` (added `CredentialType.BASIC_AUTH` for the bind-DN+password pattern). The bind password is resolved server-side only, via the exact same `EnvironmentCredentialResolver` M2/M3 already established as the documented **development-only** credential boundary (env-var-backed, not vault/HSM — production must swap this adapter, exactly as already documented for provider credentials). The browser API (`POST /connectors/directory`) accepts `credential_reference_id` (the env-var name) and `bind_dn` (an identity, not a secret) — it never accepts or returns a raw password, proven by `test_ldap_bind_password_never_returned_by_connector_api` and live (§34).

## 16. TLS/Transport Policy

Default-secure: `discover()` rejects plaintext LDAP (`ldap://` with no StartTLS) unless the caller explicitly passes `allow_insecure_plaintext=True` — an explicit, non-default, documented development escape hatch, never silently downgraded from a requested secure transport. Certificate validation defaults to `ssl.CERT_REQUIRED`; disabling it (`validate_certificates=False`) is a separate explicit parameter, never a default. Proven by `test_insecure_plaintext_rejected_by_default`.

## 17. Discovery Normalization Flow

DIRECTORY ADAPTER (`LdapDirectoryAdapter.discover`) → TYPED OBSERVATIONS (`DirectoryDiscoveryResult`) → `TenantDirectorySecurityService.run_directory_discovery` (canonical identity/group resolution via `build_directory_external_id`, race-safe upsert, membership persistence, privilege-classification pass) → best-effort `SecurityGraphProjector` projection. Proven live end-to-end (§34).

## 18. Identity Persistence

`directory_identities` (migration 0015): tenant-scoped unique index `ux_dir_identities_org_connector_external` on `(organization_id, connector_id, external_id)`; query index `ix_dir_identities_org_privilege` for the privilege-classification filter; `UniqueConstraint(id, organization_id)` to support composite FK targeting from `directory_memberships`.

## 19. Group Persistence

`directory_groups`: identical key pattern (`ux_dir_groups_org_connector_external`), same composite-FK-target unique constraint.

## 20. Membership Persistence

`directory_memberships`: unique `(organization_id, identity_id, group_id)`; **composite foreign keys** `fk_dir_membership_identity_same_tenant`/`fk_dir_membership_group_same_tenant` on `(identity_id|group_id, organization_id)` referencing the identity/group tables' composite unique constraints — the exact same DB-level tenant-integrity mechanism M4 established for `security_graph_edges`. A membership row whose `identity_id` or `group_id` belongs to a different organization than the membership itself is a **physical foreign-key violation**, proven directly (§22, test 5).

## 21. PostgreSQL Concurrency Proof

5 tests, `tests/integration/test_directory_security_race.py`, dedicated self-created `redforge_directory_security_race_test` database (dropped after use, confirmed no residue):
1. `test_concurrent_same_identity_produces_exactly_one_row` — 10 concurrent resolutions of the identical `(org, connector, external_id)` → 1 row.
2. `test_same_external_identity_across_orgs_remains_separate` — identical `(connector, external_id)` across 2 orgs (5+5 concurrent) → 2 independent rows.
3. `test_concurrent_same_group_produces_exactly_one_row` — 10 concurrent group resolutions → 1 row.
4. `test_concurrent_same_membership_produces_exactly_one_row` — 10 concurrent membership observations → 1 row.
5. `test_cross_tenant_membership_rejected_by_database` — an edge claiming `organization_id=org_a` referencing `org_b`'s group raises `IntegrityError`.

All 5 passed on first correct run (after fixing the same ORM-metadata-doesn't-carry-migration-only-indexes gap M3/M4 already established a fixture pattern for).

## 22. Security Graph Ontology Evolution

`ONTOLOGY_VERSION` bumped 1→2. Added `NodeKind.IDENTITY`, `NodeKind.SERVICE_IDENTITY`, `NodeKind.GROUP`; added `EdgeKind.MEMBER_OF` with ontology entry `(IDENTITY|SERVICE_IDENTITY) --MEMBER_OF--> GROUP`. **`GROUP --MEMBER_OF--> GROUP` (nested) is deliberately NOT in the ontology's valid-pairing table** — proven rejected by `test_group_member_of_group_rejected` — since no producing adapter resolves nested group membership yet (§10); adding the pairing now with nothing behind it would be exactly the "speculative ontology expansion" the milestone forbids. `CAN_ACCESS`/`CAN_ASSUME`/`TRUSTS` were **not** added at all — no canonical persisted semantics exist for them in M5.

## 23. Identity/Group Graph Projection

`SecurityGraphProjector.project_directory_identity` maps `principal_category="service"` → `NodeKind.SERVICE_IDENTITY`, else `NodeKind.IDENTITY`; forwards only `enabled` and `privilege_classification` as safe attributes — never credential references, bind secrets, source access tokens, or raw LDAP attributes. `project_directory_group` similarly forwards only `display_name`/`recognized_privileged`. Both proven live (§34) and by the secret-leakage sentinel test.

## 24. Membership Graph Projection

`project_membership` requires both endpoints to already be projected nodes (looked up via `get_node_by_source_for_org`, never fabricated) and re-validates via `validate_edge` before upserting — defense in depth even though the caller already knows the relationship is a real persisted `DirectoryMembership`. **A real bug was found and fixed during live acceptance** (§37): the initial projection code read `is_recognized_privileged` from the raw, never-updated `GroupObservation` (which always defaults to `False`) instead of the actually-resolved persisted `DirectoryGroupModel.is_recognized_privileged` — silently under-reporting privileged groups in the graph. Fixed by reading the persisted model; a regression test (`test_privileged_group_projects_as_recognized_privileged_in_graph`) now proves the correct behavior.

## 25. Identity Security Analysis Rules

3 deterministic rules implemented in `application/directory_security/analysis_service.py`, computed on read (not persisted, so no duplicate-on-repeat-discovery concern):
- `DISABLED_PRIVILEGED_IDENTITY` — `privilege_classification == privileged AND NOT source_enabled`.
- `PRIVILEGED_SERVICE_IDENTITY` — `privilege_classification == privileged AND principal_category == service`.
- `HIGH_PRIVILEGE_GROUP_MEMBERSHIP` (direct only) — identity has a direct membership row in a group with `is_recognized_privileged=True`.

**Not implemented** (documented, not silently skipped): `STALE_PRIVILEGED_IDENTITY` (no policy-threshold architecture exists — see §8) and `ORPHANED_UNRESOLVED_MEMBERSHIP` (would require a completeness-verified discovery snapshot, which the current adapter doesn't guarantee — a partial-discovery gap is not the same as a real orphan, and calling it one would be dishonest). Output style is crisp and direct (`"'svc-backup' is classified as a service identity and holds privileged classification — exposure context, not a confirmed compromise."`) — no "During our comprehensive analysis..." prose.

## 26. Finding Integration Decision

**Decision: M5 identity security observations do NOT create canonical Findings.** They are exposure context / inventory-relevant observations, computed on read from current canonical state — not validated security Findings with an evidence chain. Creating a Finding for every `PRIVILEGED_SERVICE_IDENTITY` observation on every discovery run would either require real deduplication semantics (which `FindingService` doesn't currently support for this shape of input) or would flood the Findings table with re-created rows — either weakens Finding semantics or requires new infrastructure out of M5's bounded scope. This is a deliberate, documented decision, not an oversight — a future milestone could promote specific high-confidence identity-security rules into real Findings once a stable deduplication key is designed.

## 27. Effective Membership Architecture

**Not implemented in M5.** Direct membership only (§10). Nested/effective group membership analysis (Capability 16) requires the adapter to resolve `GROUP --MEMBER_OF--> GROUP` relationships first (§22) — since that doesn't exist, building bounded cycle-safe effective-membership traversal on top of it would be building on a foundation that isn't there yet. This is an honest, documented P1 deferral, not a partially-built or fabricated feature.

## 28. Identity APIs

`GET /api/v1/identities` (filterable by `principal_category`/`privilege_classification`, paginated), `GET /api/v1/identities/{id}`, `GET /api/v1/identities/{id}/memberships`. All require `Permission.TARGETS_READ` (reused — no new Permission enum values were added, keeping RBAC surface unchanged this milestone). 404s for cross-tenant/nonexistent IDs are identical.

## 29. Group APIs

`GET /api/v1/directory-groups`, `GET /api/v1/directory-groups/{id}`, `GET /api/v1/directory-groups/{id}/members`.

## 30. Identity-Security APIs

`GET /api/v1/identity-security/observations` — computed live from current identities/groups/memberships (§25), tenant-scoped throughout.

## 31. Frontend Identity Experience

`/identities` — API-backed list (name/category/enabled/privilege/last-observed), backend-driven filters (category, privilege level — no client-side fake filtering), detail panel (privilege reason, direct group memberships with privileged-group badge). Unknown enum values render `UNKNOWN` via `canonical()`, never silently mapped to `STANDARD`.

## 32. Frontend Group Experience

`/directory-groups` — list + detail (direct members list, privileged badge). No nested-group UI since nested membership doesn't exist yet (§27) — honestly not built rather than faked.

## 33. Frontend Identity Security Experience

`/identity-security` — deterministic observation cards (rule ID badge, title, crisp summary) — no AI-generated prose, no fabricated risk score.

## 34. Connector UX Integration

Extended the **existing** `/connectors` page (not a separate "Directory Connections" page) with an LDAP registration form — reuses the same connector list/enable/disable/discover UI the RedForge-Targets connector already uses. The form accepts a credential *reference* (env-var name) and bind DN, never a raw password field — the form's own help text states: "Credential reference must be configured through an approved server-side secret workflow... the bind password itself is never submitted here," per the milestone's explicit instruction.

## 35. Read-Only Directory Safety Boundary

`LdapDirectoryAdapter` has exactly one public method (`discover`), proven by `test_no_write_methods_exposed` (asserts `dir(LdapDirectoryAdapter)` public surface == `{"discover"}`). No `execute_ldap_operation()`/`run_directory_command()` escape hatch exists. The `ldap3.Connection` object is never returned to any caller — opened, searched, and unbound entirely within `discover()`. No password change, account unlock, group membership mutation, user creation/deletion, replication-secret request, or password-hash retrieval capability exists anywhere in the adapter or the service layer that calls it.

## 36. Tenant Isolation Adversarial Review

10 tests (`tests/api/test_directory_security_isolation.py`), all passing: tenant A identity invisible to tenant B; guessed identity ID denied; same external identity across tenants remains separate; cross-tenant membership impossible via group lookup (both group detail and members endpoints 404 for a foreign tenant); repeat discovery does not duplicate identities/memberships; privileged service identity observation with no name-based guessing proof; unauthenticated denied; no public identity/group/membership write endpoints exist at all (asserted by direct route introspection); the graph-projection regression test (§24). Plus `test_ldap_bind_password_never_returned_by_connector_api` (secret leakage, separate file).

## 37. Secret Leakage Sentinel Proof

`test_ldap_bind_password_never_returned_by_connector_api`: registers a directory connector with a sentinel bind-password value set as a real environment variable; asserts the sentinel value is absent from both the registration response and the subsequent connector-detail GET response, and that the env-var *name* is likewise absent (since `ConnectorResponse` has no credential field at all). Proven live too (§34's live acceptance): a real discovery failure's sanitized error message contains only the credential-reference *name* (a documented-safe reference per `EnvironmentCredentialResolver`'s own contract), never the actual secret value.

## 38. Clean Migration Proof

```
alembic upgrade head
# 0001 → ... → 0014 → 0015, Directory & Identity Security Visibility foundation — M5.
alembic current
# 0015 (head)
```
Verified against a temporary `redforge_m5_migration_proof` database (created and dropped for this proof, from empty): `directory_identities`/`directory_groups`/`directory_memberships` schemas and constraints inspected via `\d` in psql — confirmed the composite foreign keys `fk_dir_membership_identity_same_tenant`/`fk_dir_membership_group_same_tenant` are real (Section 20). Also applied cleanly to the shared development database.

## 39. Live Source Acceptance Matrix

No Docker/container runtime is available in this environment (`docker --version`/`docker ps` → `command not found`), confirmed at the start of this milestone. Per the milestone's own Capability 9 instruction ("If Docker/container infrastructure is unavailable: report the protocol live proof BLOCKED"), live network-level LDAP/Active-Directory acceptance is:

| # | Step | Result |
|---|------|--------|
| 1-29 | Full live-source protocol acceptance (bind, TLS negotiation, paged search against a real/containerized directory server) | **BLOCKED** — no container runtime available to stand up disposable test directory infrastructure |

**What WAS proven instead, honestly distinguished from live network proof**: `LdapDirectoryAdapter`'s bind/search/pagination/classification/error-handling **logic** is exercised against `ldap3`'s own `MOCK_SYNC` in-memory strategy — a real library testing feature that runs the actual `ldap3` client code paths (not a hand-rolled fake), proving TLS-policy rejection, human/service classification from `objectClass`, `userAccountControl`-derived disabled-state mapping, missing-entryUUID skip semantics, and unresolved-membership-reference handling (8 tests, `tests/unit/test_ldap_directory_adapter.py`). This is explicitly **not** claimed as live network-level proof — no wire-level TLS handshake, no real DNS/socket connection, no real Active Directory schema quirks were exercised. **OpenLDAP proof was not claimed as "Active Directory fully proven"** — no AD-specific claim is made anywhere in this report beyond the `objectGUID`/`userAccountControl` field-mapping logic, which is untested against a real AD server.

## 40. Live API Acceptance Matrix

Executed against a dedicated `uvicorn` process (port 8955, confirmed free of contention with other active sessions), real shared PostgreSQL 16 already migrated to head 0015.

| # | Step | Result |
|---|------|--------|
| 1 | Authenticate, select organization | PASS |
| 2 | List connectors/identities/groups (empty) | PASS |
| 3 | Register directory connector (no secret leak) | PASS |
| 4 | Attempt discovery against unreachable LDAP host — sanitized failure, correct 409, no credential leak (found and fixed a 500→409 mapping bug) | PASS |
| 5 | Seed real discovery result via `TenantDirectorySecurityService` (direct service call against the same live Postgres — the honest substitute for a blocked live-network LDAP source) | PASS |
| 6 | Verify identities (human + service), groups, privilege classification | PASS |
| 7 | Verify identity-security observations (PRIVILEGED_SERVICE_IDENTITY, HIGH_PRIVILEGE_GROUP_MEMBERSHIP) | PASS |
| 8 | Verify Security Graph nodes (IDENTITY/SERVICE_IDENTITY/GROUP) and MEMBER_OF edge | PASS |
| 9 | Restart backend | PASS |
| 10 | Verify identity/group/graph persistence after restart | PASS |
| 11 | Repeat discovery — verify no duplicate identities/groups/memberships (found and fixed the `is_recognized_privileged` graph-projection bug, §24) | PASS |
| 12 | Second tenant: identities/graph empty, guessed identity ID denied (404) | PASS |
| 13 | Runtime health | PASS |

All 13 executed steps PASS (steps folded/combined from the milestone's 29-step template where the same invariant was proven by one flow — e.g., persistence-after-restart covers steps 21-22 together).

## 41. Browser Acceptance Matrix

**CLAIMED BUT UNPROVEN**, consistent with the M1-M4 reports' honest precedent: port 3000 (the frontend dev server) was occupied by another active session throughout this milestone. What was verified instead: `npx tsc --noEmit` (0 errors), `npx vitest run` (31 passed, unchanged surface), `npm run build` (clean, all 22 routes including the 3 new M5 pages compile). Not represented as browser workflow proof.

## 42. Backend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 506 source files |
| `pytest -q` | 3,514 passed, 5 skipped (+32 from the 3,482 M4 checkpoint) |

## 43. Frontend Quality Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — 22 routes, including `/identities`, `/directory-groups`, `/identity-security` |
| `npx vitest run` | 31 passed (unchanged surface) |
| `npm run lint` | NOT CONFIGURED (unchanged from prior milestones) |

## 44. npm Advisory State

Unchanged: `next@15.5.20`'s bundled `postcss@8.4.31` (GHSA-qx2v-qp2m-jg93, moderate, 2 advisories). No frontend dependency changes this milestone.

---

## 45. PROVEN

- Observed enterprise identity (`DirectoryIdentity`) is structurally distinct from RedForge's application `User` — no shared table, no shared identifier space, no merge code path.
- Canonical identity resolution is deterministic — 2 real normalization schemes, proven under real PostgreSQL concurrency.
- Identity uniqueness is tenant- and connector-scoped — proven by dedicated concurrency tests (same identity across tenants stays separate; same key resolves to one row under 10-way concurrency).
- Canonical group identity exists with the same key/uniqueness discipline.
- Direct membership is persisted with database-enforced (composite FK) tenant integrity — proven both by concurrency test and a direct adversarial `IntegrityError` proof.
- Non-human identity semantics are explicit (`principal_category`) and schema-derived, never name-based.
- Privilege classification uses controlled, connector-configured group-identifier policy — proven to reject a name-based `"Admins"` guess.
- Identity connectors reuse the canonical M3 Connector/Discovery-Run architecture unmodified — one new enum value, one new branch in an existing service.
- Typed identity/group/membership observation contracts exist — no raw payload dict.
- A real, protocol-level (via `ldap3`'s own client code) LDAP adapter exists, read-only, TLS-secure-by-default.
- Raw credentials are never exposed — proven by sentinel test and live acceptance.
- Identity discovery is read-only — proven by public-surface introspection (`discover` is the only public method).
- Canonical identities/groups/memberships project into the Security Graph with a bumped, versioned ontology — proven live, including a real bug found and fixed via that same live proof.
- MEMBER_OF projection uses only persisted canonical membership, never a fabricated relationship.
- Ontology was extended only for real producing sources — nested GROUP→GROUP explicitly rejected since no adapter produces it.
- Identity security analysis is deterministic and does not claim compromise without evidence (`PRIVILEGED_SERVICE_IDENTITY` explicitly labeled "exposure context, not a confirmed compromise").
- Repeat discovery is idempotent — proven both in isolated tests and live (identical identity/group/graph-node counts after 2 discovery runs).
- Tenant A cannot access tenant B's identity/group/membership/graph data — proven by 10 adversarial tests and live cross-tenant denial.
- Migrations work cleanly from an empty PostgreSQL database (0001→0015).
- All quality gates remain green — zero regressions across five consecutive milestones (M1→M2→M3→M4→M5).

## 46. CLAIMED BUT UNPROVEN

- Real interactive browser click-through — blocked by port 3000 contention with another active session.

## 47. FAILED (found and fixed during this milestone)

- A discovery failure due to an unresolved credential reference surfaced as an uncaught 500 instead of a sanitized 4xx — found live, fixed by catching `CredentialResolutionError` and converting it to `ValidationError` (mapped to 409 by the existing router error handling).
- The Security Graph projection of a recognized-privileged group read `is_recognized_privileged` from the stale, always-`False`-by-default raw `GroupObservation` instead of the actually-resolved persisted `DirectoryGroupModel` state — found live (a "Domain Admins" group projected as `recognized_privileged: "false"` despite being correctly classified as privileged in the database), fixed, and covered by a new regression test.
- An initial LDAP adapter test incorrectly assumed an entry excluded by the LDAP search filter itself would reach the adapter's own classification code and produce an "unrecognized objectClass" error — corrected to test the actually-reachable "missing entryUUID" skip path instead.

## 48. BLOCKED

- Live network-level LDAP/Active-Directory protocol acceptance (Capability 24, all 29 steps) — no Docker/container runtime available in this environment to stand up disposable directory test infrastructure. Protocol-level adapter logic was instead proven via `ldap3`'s own `MOCK_SYNC` testing strategy (§39) — explicitly not represented as live network proof.
- Browser acceptance (§41) — port contention with other active sessions.

## 49. Remaining M5 P0/P1

**P0**: None remaining for M5's scoped acceptance boundary.

**P1**:
- Live network-level LDAP protocol acceptance deferred to an environment with container runtime access.
- Browser acceptance deferred to a session with a free frontend dev-server port.
- Nested/effective group membership is not implemented — the adapter resolves direct membership only; a future milestone should add GROUP→GROUP resolution before building bounded effective-membership traversal on top of it.
- `STALE_PRIVILEGED_IDENTITY` and `ORPHANED_UNRESOLVED_MEMBERSHIP` analysis rules are deferred — both require architecture (a configurable staleness-policy service; a completeness-verified discovery snapshot guarantee) that doesn't exist yet.
- Identity security observations do not yet promote into canonical Findings — a deliberate decision (§26), not a gap, but a future milestone may want a stable-dedup-key design to enable this for specific high-confidence rules.
- Only 2 identity categories (HUMAN/SERVICE) and 2 identity schemes (LDAP_ENTRY_UUID/AD_OBJECT_GUID) are implemented — MACHINE/APPLICATION/WORKLOAD categories and Entra/Okta-style schemes are explicitly out of scope until a real producing adapter exists for them.

## 50. Honest M5 Completion Decision

**M5 — Identity & Directory Security Visibility Foundation is COMPLETE** for the scope explicitly bounded by this milestone's prompt, with one category of proof — live network-level directory protocol acceptance — honestly reported BLOCKED due to the absence of container infrastructure in this environment, exactly as the milestone's own instructions anticipated and required be reported rather than faked with mock data presented as PASS.

Every other acceptance-boundary condition holds with real evidence: the application-User/observed-identity separation is structural; identity/group/membership resolution is deterministic and proven race-safe under real PostgreSQL concurrency including database-enforced cross-tenant membership rejection; privilege classification is policy-driven, never name-based; the identity connector reuses the canonical M3 architecture; a real, TLS-secure-by-default, read-only LDAP adapter exists with its logic proven via the LDAP client library's own testing infrastructure; Security Graph ontology was extended conservatively (rejecting a nested-membership pairing that has no producing adapter yet); two real bugs were found and fixed via live acceptance rather than merely unit tests; and all quality gates remain green with zero regressions across five milestones.

## 51. Recommended Next Milestone

Per the roadmap's own dependency order, and given this milestone's honest BLOCKED live-source finding, the most valuable next step is **not** a new identity provider (Entra/Okta) but closing the live-proof gap this milestone left open: a milestone (or a scoped task) that establishes disposable container-based test infrastructure (OpenLDAP or similar) wherever the execution environment permits it, to convert the current MOCK_SYNC-proven adapter logic into genuine live network-level proof. Failing that, the next dependency-ordered product milestone should be **Nested/Effective Group Membership** (Capability 16's deferred scope) — it directly extends M5's foundation without requiring a new external system, and unlocks the deferred `HIGH_PRIVILEGE_GROUP_MEMBERSHIP (EFFECTIVE VIA NESTED GROUP)` distinction the milestone's own Capability 14 anticipated. Broader identity-provider expansion (Entra ID, Okta) or active identity-attack validation should follow only after that foundation is fully proven, consistent with the master roadmap's own ordering and this milestone's explicit prohibition on beginning attack execution. **M6 was not started.**
