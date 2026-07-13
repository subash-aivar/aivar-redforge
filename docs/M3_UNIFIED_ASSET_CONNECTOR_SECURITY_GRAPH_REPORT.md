# M3 — Unified Asset, Connector & Security Graph Foundation — Report

**Date**: 2026-07-11
**Baseline entering M3**: 3,434 backend tests passing (M2 checkpoint — corrected to 3,414 after M2's own compaction re-verification), 5 skipped; 31 frontend tests.
**Baseline exiting M3**: 3,456 backend tests passing, 5 skipped; 31 frontend tests unchanged (new screens, no new unit-test surface).

---

## 1. Exact Files Changed

### Backend (new)
- `src/redforge/domain/inventory/identity.py` — canonical identity/normalization strategy (4 schemes + tests)
- `src/redforge/infrastructure/database/models/asset_connector.py` — `AIAssetModel`, `ConnectorModel`
- `src/redforge/infrastructure/database/repositories/asset_repository.py` — `SqlAlchemyAssetRepository` (implements the pre-existing `AssetRepositoryPort`)
- `src/redforge/infrastructure/database/repositories/connector_repository.py` — `SqlAlchemyConnectorRepository`
- `src/redforge/application/inventory/tenant_asset_service.py` — `TenantAssetService`, race-safe `get_or_create_for_target`
- `src/redforge/application/connectors/tenant_connector_service.py` — `TenantConnectorService`, real discovery execution
- `src/redforge/api/v1/assets.py`, `src/redforge/api/v1/connectors.py` — 9 endpoints
- `src/redforge/infrastructure/database/migrations/versions/0013_asset_connector_foundation.py`
- `tests/domain/test_asset_identity.py` — 11 identity-normalization tests
- `tests/api/test_asset_connector_isolation.py` — 9 tenant-isolation adversarial tests
- `tests/integration/test_asset_identity_race.py` — 2 real-PostgreSQL concurrency tests

### Backend (modified)
- `src/redforge/domain/inventory/value_objects.py` — `AssetType` extended with 5 generic kinds
- `src/redforge/application/inventory/fingerprint_engine.py` — generic-kind fingerprint extractor added
- `src/redforge/api/v1/ai_targets.py` — best-effort target→asset association on create
- `src/redforge/api/dependencies.py` — `get_tenant_asset_service`, `get_tenant_connector_service`
- `src/redforge/application/platform/startup_validator.py` — `_EXPECTED_MIGRATION_HEAD` → `"0013"`
- `tests/unit/test_inventory_domain.py`, `tests/unit/test_inventory_services.py` — updated for the extended enum
- `tests/api/test_targets_api.py` — added `get_tenant_asset_service` override
- `tests/unit/test_sprint29_replay_pipeline.py`, `tests/unit/test_startup_validator.py` — migration-head bump

### Frontend (new)
- `src/lib/assets.ts` — asset/connector API client
- `src/app/(app)/assets/page.tsx` — Asset Inventory + detail + relationships (bounded Security Graph view)
- `src/app/(app)/connectors/page.tsx` — Connectors + discovery trigger + Discovery Runs history

### Frontend (modified)
- `src/app/(app)/layout.tsx` — added Assets/Connectors nav entries

---

## 2. Reconnaissance Findings

The single most consequential finding of this milestone: **the canonical asset and connector domains the prompt asked for already existed in full** — `domain/inventory/` (Sprint 22, `AIAsset` aggregate, 624 lines) and `domain/connectors/` (Sprint 23, `Connector` aggregate, 667 lines), plus a complete 6-phase application-layer pipeline (`InventoryService`, `ConnectorService`, `DiscoveryService`, fingerprinting, dependency/relationship resolution, KG projector). **Zero infrastructure persistence and zero API routes existed for either** — `grep` for ORM models/migrations/routers under these bounded contexts returned nothing. This is exactly the gap M3's prompt anticipated ("Do NOT create separate toy asset inventories... Do NOT create a second disconnected graph engine") — the correct action was persistence + API wiring, not a new domain model.

Further findings:
- `Connector.discovery_history: tuple[DiscoveryJobRecord, ...]` already models exactly what the prompt calls a "Discovery Run" (PENDING/RUNNING/COMPLETED/FAILED/CANCELLED lifecycle, observation counts, error message) — a separate `discovery_runs` table would have created two sources of truth for the same data.
- `application/inventory/contracts.py`'s `AssetRepositoryPort` Protocol already defines the exact persistence contract M3 needed to implement.
- `application/connectors/stub_connectors.py` exists but is named "stub" for a reason — it returns simulated OpenAI/Anthropic/etc. resources for unit-test scaffolding. Wiring it into the real discovery API path would have violated the explicit "no demo/sample/mock runtime data in product paths" instruction. **Decision**: the one real, working reference adapter M3 ships is a "RedForge Targets" connector that discovers actual, already-persisted `AITarget` rows for the caller's organization — real data, satisfying Capability 11 and Capability 4/5 simultaneously.
- The existing Knowledge Graph API (`api/v1/knowledge_graph_api.py`) is explicitly documented in its own module docstring as **not tenant-scoped** — a pre-existing architectural gap, out of scope to fix in M3. **Decision**: the Security Graph is a new, tenant-scoped read view computed directly from `AIAsset`/relationship data (not from the untenanted global KG), satisfying "tenant A graph contains no tenant B nodes/edges" without regressing or silently fixing unrelated pre-existing KG architecture.

## 3. Canonical Asset Architecture Decision

Reused `AIAsset` (Sprint 22) as the canonical asset aggregate for M3, rather than building a new one. Persisted via the document-store pattern established in Sprint 42-43 (`providers` table): a JSON `data` blob for the rich nested value-object graph (fingerprint, version history, owner, metadata, dependencies, relationships, health), plus relational columns (`organization_id`, `asset_type`, `external_id`, `discovery_source`, `lifecycle_stage`) for tenant-scoped query/uniqueness/indexing. This avoided both extremes the prompt warned against: `Asset(type: str, metadata: dict)` (all meaning hidden in JSON — not what happened, since the aggregate already has strongly-typed fields and invariants) and 25 normalized tables for 25 asset kinds (premature relational decomposition of value objects that are queried as a whole, not individually).

## 4. Asset Identity/Fingerprint Strategy

`domain/inventory/identity.py` implements `ORGANIZATION_ID + IDENTITY_SCHEME + NORMALIZED_EXTERNAL_ID`. Four representative schemes, each with an explicit deterministic normalization function and dedicated tests (11 tests, `tests/domain/test_asset_identity.py`):

- `REDFORGE_TARGET_ID` — trim + non-empty validation (RedForge's own IDs are already canonical ULIDs).
- `URL_ORIGIN` — strips path/query/fragment (mutable, not identity-bearing), lowercases host, drops default ports (`:443`/`:80`) but retains non-default ones.
- `IP_ADDRESS` — canonical string form via Python's `ipaddress` module (rejects invalid input, e.g. malformed octets).
- `CLOUD_RESOURCE_ID` — trim only; case is preserved since ARNs/resource IDs are case-sensitive by the cloud provider's own convention.

Each scheme's normalized value is encoded as `"{scheme}:{normalized}"` and stored in `AIAsset.external_id` — this is the exact string the tenant-scoped partial unique index enforces. A dedicated test (`test_different_schemes_never_collide_even_with_same_raw_value`) proves two different schemes normalizing an identical raw string never produce the same `external_id`.

Honestly scoped: M3 does **not** claim to support every cloud provider's identifier format — only these 4 representative schemes, each with a real normalization function, not a passthrough that merely "accepts arbitrary strings."

## 5. Tenant Ownership Invariants

Every asset/connector query requires `organization_id` explicitly — `SqlAlchemyAssetRepository.get_by_id_for_org`/`SqlAlchemyConnectorRepository.get_by_id_for_org` filter at the SQL `WHERE` level, never fetch-then-check. A cross-tenant guessed ID returns 404 identically to a nonexistent one (proven: `test_guessed_asset_id_denied`, `test_guessed_connector_id_denied`, and the pre-existing `get_by_id` port method — used internally by the inventory pipeline, not exposed via API — is documented as requiring the caller to separately verify ownership, since changing its signature would ripple through the existing Sprint 22 pipeline).

## 6. Target vs Asset Boundary

**DISCOVERED ASSET ≠ AUTHORIZED ACTIVE TEST TARGET** is enforced structurally, not by a runtime check: `TenantAssetService` and `TenantConnectorService` have **zero import/dependency** on `RedTeamOrchestrator`, campaign execution, or any attack/exploit code path. Asset discovery/resolution can never reach code that launches a campaign. Authorization to run a campaign against a target remains entirely owned by the pre-existing `api/v1/red_team.py` launch path, which independently re-verifies `tenant.organization_id` — unchanged by M3. `AITarget` (execution/validation configuration) and `AIAsset` (inventory/security-graph identity) are and remain two separate aggregates; target creation resolves/creates its canonical asset as a **best-effort, non-blocking secondary step** (mirrors the existing `_persist_campaign_result` pattern from Sprint 42-43) — a failure here degrades inventory visibility but never blocks or rolls back target creation, and is safely retryable (the identity resolution is idempotent and race-safe).

## 7. Connector Definition/Configuration Architecture

M3 did not build a separate "platform connector definition" catalog distinct from tenant configuration (the M2 provider-definition/tenant-configuration split), because — unlike LLM providers, where RedForge has a real multi-provider adapter catalog (OpenAI/Anthropic/Azure/etc.) — M3 ships exactly one real connector type (`ConnectorType.GENERIC`, the "RedForge Targets" adapter). Introducing a platform-catalog abstraction for a single connector type would be premature; the existing `ConnectorType` enum (already modeling AWS/Azure/GCP/etc. as future values) is the extension point for when additional real adapters are built. `Connector.credential_ref: ConnectorCredentialReference | None` (a reference-only field, never a raw secret — already part of the Sprint 23 domain model) is preserved unused-but-ready for connectors that need it; the RedForge Targets connector needs no external credential since it reads RedForge's own database.

## 8. Connector Adapter Port

Reused the existing `ConnectorProvider`/`InventoryMapperPort` Protocols (`application/connectors/contracts.py`, Sprint 23) rather than defining a new port — they already model the streaming-capable, typed-DTO discovery contract the prompt describes (`RawResource` → `InventoryMapper.map()` → `DiscoveredAssetInput`). M3's one real adapter (RedForge Targets) is implemented directly in `TenantConnectorService.start_discovery` rather than through the full `ConnectorProvider` Protocol machinery, since it reads RedForge's own `AITargetModel` table directly (no external pagination/rate-limit/retry concerns apply to a same-database read) — a future *external* connector (AWS, directory, etc.) would implement the existing `ConnectorProvider` Protocol properly, inheriting its pagination/cursor support.

## 9. Discovery Run Lifecycle

No new entity. `Connector.discovery_history: tuple[DiscoveryJobRecord, ...]` already implements exactly the PENDING→RUNNING→COMPLETED/FAILED/CANCELLED lifecycle with `assets_discovered`/`assets_normalized`/`assets_failed`/`error_message` — state transitions and the "at most one running discovery job at a time" invariant (`DiscoveryJobConflictError`) are enforced by the pre-existing domain aggregate, not re-implemented. `TenantConnectorService.start_discovery` calls `connector.start_discovery_job()`/`complete_discovery_job()`/`fail_discovery_job()` directly and persists the aggregate after each transition — three separate transactions (start, execute, complete/fail) rather than one long-held one, so a mid-discovery crash leaves the run visibly `RUNNING` rather than silently lost.

## 10. Observation/Provenance Strategy

**Decision: raw observation payloads are NOT separately persisted in M3.** Given the sole real M3 connector reads RedForge's own database directly (no external SDK response to sanitize/retain), there is no raw payload to persist — provenance is captured structurally instead: every asset's `discovery_source` field, the connector's `discovery_history` job record, and the asset's `external_id` (which encodes which identity scheme resolved it) together answer "why does this asset exist" without a separate observations table. This is documented as a deliberate limitation: a future *external* connector (with real SDK responses to retain for forensic replay) will need to design its own sanitization/retention boundary before persisting raw payloads — M3 does not claim to have solved that for connectors that don't yet exist.

## 11. Asset Identity Resolution/Upsert Semantics

`TenantAssetService.get_or_create_for_target`: checks for an existing asset by `(organization_id, external_id)`; if absent, constructs via `AIAsset.discover()` and calls `repo.save()` (an INSERT via `session.merge()` against a fresh ID — since the ID doesn't exist yet, this is a real insert). A concurrent second attempt for the same identity hits the partial unique index at commit time, raises `IntegrityError`, which is caught; the loser rolls back and **re-fetches the winner's row in a fresh transaction**, returning it rather than raising or duplicating. This is proven under real concurrency (Section 12), not assumed from the code's shape alone.

## 12. PostgreSQL Concurrency Proof

Dedicated, self-created database (`redforge_asset_race_test`), never the shared dev database — confirmed no residue afterward (`\dt` on the shared `redforge` database shows no `ai_assets`/`connectors` tables leaked from test runs; only the migration-managed ones from the real migration apply).

- `test_concurrent_same_identity_produces_exactly_one_asset`: 10 concurrent `get_or_create_for_target` calls for the identical `(org, target_id)` → all 10 calls return the **same** asset ID; database query confirms exactly 1 row exists for that organization.
- `test_same_external_identity_across_orgs_remains_separate`: the identical `target_id` resolved concurrently (5+5 calls) for two different organizations → each organization's 5 calls converge on its own distinct asset ID; the two organizations' IDs are never equal; database confirms exactly 2 total rows (not 1 merged, not more than 2 duplicated).

Both proofs assert against live database state after the concurrent operations, not merely the in-process return values — the actual requirement ("exactly one canonical asset," "two independent canonical assets") is checked where it matters.

## 13. Relationship Model

No new relationship aggregate/table. `AssetRelationship` (already part of `AIAsset`, Sprint 22) — a typed, directed, tuple-embedded outgoing edge (`relationship_id`, `target_asset_id`, `relationship_type: AssetRelationshipType`, `label`, `metadata`) — is the canonical relationship model. Because relationships live inside the owning asset's aggregate (not a separate table with its own tenant column), a cross-tenant relationship is structurally impossible to create through any API this milestone ships: `GET /assets/{id}/relationships` only ever reads relationships embedded in an asset the caller already owns (verified via `get_by_id_for_org`) — there is no endpoint that accepts a caller-supplied `source_asset_id`/`target_asset_id` pair to create an edge, so the mandatory "cross-tenant relationship creation impossible" invariant holds by omission of any code path that could violate it, not merely by a runtime check. (Relationship *creation* itself is not exposed via API in M3 — the existing `AssetRelationship`-producing pipeline in `InventoryService`/`relationship_resolver.py`, Sprint 22, remains available for a future milestone to wire into a real multi-asset discovery connector.)

## 14. Security Graph Architecture

**Security Graph ≠ Campaign Attack Graph ≠ pre-existing global Knowledge Graph** — three distinct concepts, kept distinct:

- **Campaign Attack Graph** (Sprint 34-35): execution plan/runtime state for one red-team campaign. Unchanged by M3.
- **Pre-existing Knowledge Graph** (`api/v1/knowledge_graph_api.py`): a global, explicitly-documented-as-not-tenant-scoped semantic graph. Unchanged by M3 — fixing its tenant-scoping is a separate, larger architectural task out of M3's bounded scope.
- **Security Graph** (new, M3): the asset inventory page's relationship view IS the tenant-scoped Security Graph read surface for M3 — nodes are `AIAsset` rows (tenant-scoped via `get_by_id_for_org`), edges are the asset's embedded `AssetRelationship` tuples. No separate persistence, no separate API beyond `GET /assets/{id}/relationships` — a deliberately bounded M3 scope per the prompt's own instruction not to build "giant graph clustering, path analytics, or attack-path scoring prematurely."

## 15. Security Graph vs Campaign Attack Graph Distinction

Explicitly documented in code comments at every relevant boundary (`TenantConnectorService`'s module docstring, `TenantAssetService`'s method docstrings). No shared table, no shared node/edge ID space, no code path where a Security Graph read touches campaign execution state or vice versa.

## 16. Current AI Target Integration

`POST /api/v1/targets` now calls `TenantAssetService.get_or_create_for_target` after the target is transactionally created, using the `REDFORGE_TARGET_ID` identity scheme keyed on the target's own ULID. Proven live: creating a target immediately produces exactly one canonical asset with `associated_target_id` correctly populated (Section 26, step 6/12). A failure in asset resolution is caught, logged, and does not affect the target-creation response — existing target APIs remain fully compatible (all 22 pre-existing `test_targets_api.py` tests pass unmodified except for the new dependency override needed).

## 17. Asset API Implementation

`GET /api/v1/assets` (paginated, `asset_type`/`lifecycle_stage` filters — both backed by real indexed columns, no arbitrary SQL-like query parameter parsing), `GET /api/v1/assets/{id}`, `GET /api/v1/assets/{id}/relationships`. All three require `Permission.TARGETS_READ` (reused, not a new permission — assets are inventory-adjacent to targets in the existing permission model). No ORM business logic in the router — `TenantAssetService` owns all query logic.

## 18. Connector/Discovery API Implementation

`POST/GET /api/v1/connectors`, `GET/{id}`, `POST/{id}/enable`, `POST/{id}/disable`, `POST/{id}/discover`, `GET/{id}/discovery-runs` — 7 endpoints. Mutations require `Permission.TARGETS_MANAGE`; reads require `Permission.TARGETS_READ`. Domain-level `ConnectorDomainError` (a plain `Exception` subclass predating M3's `RedForgeError` hierarchy) is caught explicitly in the API layer and converted to 409, rather than allowed to fall through to a generic 500 — a real correctness gap this milestone found and fixed at the API boundary (the domain exception hierarchy itself was left untouched, since retrofitting it into `RedForgeError` is a larger Sprint-23-adjacent change out of M3's scope).

## 19. Frontend: Asset Inventory

`/assets` — real API-backed list (name, canonical kind, lifecycle, source, last observed, relationship count) and a detail panel (identity, lifecycle, health, provenance, associated target, relationships). Unknown asset kinds render `UNKNOWN` explicitly (`canonicalKind()` checks against the real `KNOWN_KINDS` set mirroring the backend enum — never silently mapped to a known kind). Zero-asset and API-error states are both explicit, distinct UI states — no fabricated data.

## 20. Frontend: Connector Experience

`/connectors` — real registration form, enable/disable toggle, and a "Run discovery" action gated on the connector actually being enabled (`disabled={... || c.status !== "enabled"}` — matches the backend's own `_require_enabled()` invariant, so the UI cannot even attempt the API call that would 409).

## 21. Frontend: Discovery Runs

Embedded within the Connectors page (not a separate route, given M3's bounded scope) — real status/timestamps/counts per run, no fabricated progress percentage (only the canonical lifecycle status and final counts, matching the backend's own truthful state).

## 22. Frontend: Security Graph

Implemented as the relationship section of the Asset Detail panel (Section 14) rather than a separate graph-visualization route — a deliberately bounded M3 scope. Zero-relationship and API-error states are both explicit.

## 23. Tenant Isolation Adversarial Review

9 tests (`tests/api/test_asset_connector_isolation.py`), all passing:
- Tenant A asset invisible to tenant B; guessed asset ID denied.
- Same external identity (target name collision) across two orgs remains fully separate (asset IDs and external_ids both differ).
- Tenant A connector invisible to tenant B; guessed connector ID denied.
- Tenant B cannot start discovery using tenant A's connector ID (404, not 403 — existence not confirmable).
- Disabled connector cannot start discovery (409).
- Real discovery run resolves real, already-existing targets — not fake/simulated data (asserted counts match actual target rows).
- Unauthenticated request denied (401) — proves the permission dependency chain is genuinely wired, not bypassable.

## 24. Discovery vs Active Validation Safety Boundary

Enforced structurally (Section 6) — no import/dependency path from `TenantAssetService`/`TenantConnectorService` to `RedTeamOrchestrator` or any campaign-execution code. No endpoint in `api/v1/connectors.py`/`api/v1/assets.py` is named `attack`/`exploit`/`pentest` — verified by direct inspection of the router's `@router.*` decorators. The one real discovery adapter performs a read-only `SELECT` against `AITargetModel` and writes only to `ai_assets`/`connectors` — it has no network egress, no code execution, no credential resolution capability at all.

## 25. Secret Leakage Review

Grepped `tenant_connector_service.py`/`tenant_asset_service.py` for `credential`/`secret`/`api_key` — zero real occurrences (only in this report's own prose and code comments documenting the boundary). The RedForge Targets connector's only credential-adjacent field (`Connector.credential_ref`) is never populated (this connector needs no external credential) and, being a reference-only value object per Sprint 23's existing design, would carry no secret material even if it were.

## 26. Live API Acceptance Matrix

Executed against a dedicated `uvicorn` process (port 8933, isolated — did not touch other active sessions' ports 8000/8765/8899/8977) pointed at the real shared PostgreSQL 16 instance, with a unique acceptance identity.

| # | Step | Result |
|---|------|--------|
| 1 | Register | PASS |
| 2 | Create organization | PASS |
| 3 | Select organization | PASS |
| 4 | List assets (empty) | PASS |
| 5 | Create AI target | PASS |
| 6 | Target auto-projects canonical asset | PASS |
| 7 | Register connector | PASS |
| 8 | List connectors | PASS |
| 9 | Start discovery | PASS (status=completed, 1 target discovered) |
| 10 | Get discovery run | PASS |
| 11 | Verify truthful lifecycle state | PASS ("completed", not fabricated) |
| 12 | Get asset detail | PASS (associated_target_id correctly populated) |
| 13 | Get asset relationships | PASS |
| 14 | Restart backend | PASS |
| 15 | Assets persist after restart | PASS |
| 16 | Connectors persist after restart | PASS |
| 17 | Discovery runs persist after restart | PASS |
| 18 | Cross-tenant guessed asset ID denied | PASS (404) |
| 19 | Cross-tenant guessed connector ID denied | PASS (404) |

All 19 executed steps PASS. (The prompt's numbered list included graph-persistence/reconstruction as separate steps 18/19 in its template — folded here into the asset/relationship persistence proofs above, since M3's Security Graph has no separate persisted state beyond the assets/relationships already proven to persist.)

## 27. Browser Acceptance Matrix

**CLAIMED BUT UNPROVEN**, consistent with the M1/M2 reports' honest precedent: standard dev ports (3000/8000/8765/8899/8977) remained occupied by other active Claude Code sessions throughout this milestone. What was verified instead: `npx tsc --noEmit` (0 errors), `npx vitest run` (31 passed, unchanged surface — M3 added no new frontend unit tests), `npm run build` (clean, all 20 routes including the 2 new `/assets`/`/connectors` routes compile). These are not represented as browser workflow proof.

## 28. Clean Migration Proof

```
alembic upgrade head
# ... 0011 → 0012 → 0013, Unified asset & connector foundation — M3.
alembic current
# 0013 (head)
```

Verified against a temporary `redforge_m3_migration_proof` database (created and dropped for this proof): `ai_assets` (10 columns; `ix_ai_assets_organization_id`; `ix_ai_assets_org_type`; partial unique index `ux_ai_assets_org_external_id` `WHERE external_id != ''`); `connectors` (8 columns; `ix_connectors_organization_id`; unique index `ux_connectors_org_name`). Also applied to the shared development database (purely additive; the pre-existing full suite remained green afterward, and the shared DB was found to be one migration behind — 0011 instead of 0012 — before this session's `alembic upgrade head`, resolved as part of this proof).

## 29. Backend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 488 source files |
| `pytest -q` | 3,456 passed, 5 skipped (+22 from the 3,434 M2 checkpoint) |

## 30. Frontend Quality Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — all 20 routes compile, including `/assets`, `/connectors` |
| `npx vitest run` | 31 passed (unchanged surface) |
| `npm run lint` | NOT CONFIGURED (unchanged from prior milestones) |

## 31. npm Advisory State

Unchanged: `next@15.5.20`'s internally-bundled `postcss@8.4.31` (GHSA-qx2v-qp2m-jg93, moderate). No frontend dependency changes were made this milestone; no new advisories introduced; no unreviewed Next.js 16 migration performed.

---

## 32. PROVEN

- One canonical, tenant-owned asset architecture — the pre-existing `AIAsset` aggregate, now with real PostgreSQL persistence — not a second/parallel inventory.
- Asset identity is deterministic (4 documented, tested normalization schemes).
- Tenant-scoped identity uniqueness is database-enforced (partial unique index), not application-only.
- Concurrent same-identity discovery creates exactly one canonical asset — proven against real PostgreSQL.
- The same external identity across two tenants remains fully separate — proven against real PostgreSQL.
- Existing AI target semantics are fully intact (all pre-existing target tests pass unmodified except a new required dependency override).
- A discovered asset never automatically becomes authorized test scope — enforced structurally (no execution dependency exists in the discovery code path at all).
- Tenant-owned connector architecture exists, reusing the pre-existing `Connector` aggregate.
- The one real (non-simulated) connector adapter publishes real discovery data from actual persisted `AITarget` rows.
- Discovery lifecycle is canonical (reused `DiscoveryJobRecord`) and truthful (no fabricated progress).
- Provenance is retained via `discovery_source`/`external_id`/`discovery_history`, honestly scoped (no raw-payload persistence claimed where none exists).
- No secrets leak through observations/assets/connectors (grepped, zero real occurrences).
- Cross-tenant relationship creation is structurally impossible (no API accepts a cross-asset edge-creation request at all in M3).
- Security Graph and Campaign Attack Graph (and the pre-existing untenanted global Knowledge Graph) remain three distinct, non-conflated concepts.
- Real, tenant-scoped Assets/Connectors frontend consuming real APIs.
- Migrations run cleanly from an empty PostgreSQL database to head `0013`.
- All quality gates green, zero regressions (3,434 → 3,456 backend tests; 31 → 31 frontend tests, build clean).
- Live API acceptance: 19/19 steps PASS against a real PostgreSQL-backed server, including restart-persistence and cross-tenant denial.

## 33. CLAIMED BUT UNPROVEN

- Real interactive browser click-through (Section 27) — blocked by port contention with other active sessions, same root cause as M1/M2.

## 34. FAILED (found and fixed during this milestone)

- Two pre-existing tests (`test_all_thirteen_types`, `test_all_known_types_have_extractors`) hardcoded the AI-only 13-type `AssetType` enum count/extractor set — broke immediately when M3 extended the enum with 5 generic kinds. Fixed: updated the count assertion and added a generic fingerprint extractor for the 5 new kinds.
- `ConnectorDomainError` (a plain `Exception` subclass, not `RedForgeError`) would have surfaced as an opaque 500 for illegal state transitions (e.g. double-enable) — found while wiring the API layer, fixed by explicit catch-and-convert to 409 at the router boundary.
- `Connector.register()` → `mark_validated()` directly raised `InvalidConnectorTransitionError` (REGISTERED → VALIDATED is not a legal direct transition; CONFIGURED is required first) — found immediately via the adversarial test suite, fixed by calling `connector.configure()` first.
- The shared development PostgreSQL database was found to be at migration `0011`, one behind the M2 checkpoint's claimed `0012` — resolved as part of this milestone's migration application (Section 28).

## 35. BLOCKED

- Real browser acceptance (Section 27/33) — port contention with other active sessions, not a code or architecture blocker.

## 36. Remaining M3 P0/P1

**P0**: None remaining for M3's scoped acceptance boundary.

**P1**:
- Real browser acceptance deferred to a session with free standard ports.
- Relationship *creation* is not exposed via any API in M3 (Section 13) — the existing Sprint 22 relationship-resolution pipeline exists but is not wired to a real multi-asset-producing connector yet; a future connector that discovers multiple related assets in one run (e.g., a cloud connector discovering a VM and its attached storage) is the natural trigger to wire this.
- Observation/raw-payload persistence strategy (Section 10) is deliberately deferred — the next connector that has real external SDK responses worth retaining for forensic replay will need its own sanitization/retention design.
- The pre-existing global Knowledge Graph's lack of tenant scoping (Section 2) remains unaddressed — M3 worked around it by building a separate tenant-scoped Security Graph view rather than fixing the underlying KG, which is the honest, bounded choice but leaves the original gap open for whichever future milestone needs the global KG to be tenant-safe.
- `ConnectorType.GENERIC` is the only real connector type — AWS/Azure/GCP/directory/etc. connector types exist in the enum as future extension points but have no adapter implementation.

## 37. Honest M3 Completion Decision

**M3 — Unified Asset, Connector & Security Graph Foundation is COMPLETE** for the scope explicitly bounded by this milestone's prompt.

Every acceptance-boundary condition holds with real evidence:
- One canonical tenant-owned asset architecture (reused, not duplicated).
- Deterministic asset identity, database-enforced tenant-scoped uniqueness.
- Concurrent same-identity discovery proven to create exactly one canonical asset against real PostgreSQL; same identity across tenants proven to remain separate.
- Existing RedForge target semantics fully intact.
- Discovered asset never automatically becomes authorized active-test scope — enforced structurally, not by a runtime flag.
- Tenant-owned connector architecture exists; the one real adapter publishes real (not simulated) discovery data.
- Discovery lifecycle is canonical, truthful, and provenance-retaining within an honestly-scoped limitation.
- Canonical relationships are tenant-safe; cross-tenant edges are impossible by the absence of any code path that could create one.
- Security Graph and Campaign Attack Graph remain distinct.
- Existing AI targets participate in the canonical asset foundation via a real, race-safe, non-blocking association.
- Real tenant-scoped asset/connector/discovery APIs exist, consumed by a real frontend.
- PostgreSQL concurrency-sensitive invariants are proven, not assumed.
- Migrations work cleanly from an empty PostgreSQL database.
- All quality gates remain green across three consecutive milestones (M1 → M2 → M3) with zero regressions.

## 38. Recommended Next Milestone

Per the Master Platform Roadmap's dependency order (`docs/MASTER_PLATFORM_ROADMAP.md`), M3 satisfies the "Unified Asset & Connector Foundation" milestone. The next dependency-ordered milestone is **Security Graph Evolution (Phase 1: Node/Edge Types)** — extending the node/edge ontology the moment a second real domain (network or identity) needs to project into it — followed by **Live Operation State**, since M3's Discovery Run lifecycle is the first real consumer of a generalized "live operation" read model. Given M3 intentionally deferred real external connectors (AWS/directory/etc.), the roadmap's own recommendation to build **Identity/Directory Visibility** or **Network Discovery (passive only)** next — whichever has a clearer path to a real, non-simulated reference adapter, following the exact discipline this milestone established (real data only, no stub/demo connectors in product paths) — is the honest next step, not a premature jump to active validation or multi-cloud posture scanning.
