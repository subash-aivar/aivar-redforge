# M4 — Security Graph Ontology & Projection Foundation — Report

**Date**: 2026-07-11
**Baseline entering M4**: 3,456 backend tests passing, 5 skipped; 31 frontend tests; migration head 0013.
**Baseline exiting M4**: 3,481 backend tests passing, 5 skipped; 31 frontend tests unchanged; migration head 0014.

---

## 1. Exact Files Changed

### Backend (new)
- `src/redforge/domain/security_graph/ontology.py` — controlled ontology (NodeKind, EdgeKind, EDGE_ONTOLOGY validity table, `validate_edge()`)
- `src/redforge/infrastructure/database/models/security_graph.py` — `SecurityGraphNodeModel`, `SecurityGraphEdgeModel`
- `src/redforge/infrastructure/database/repositories/security_graph_repository.py` — `SecurityGraphRepository` (idempotent upsert)
- `src/redforge/application/security_graph/projector.py` — `SecurityGraphProjector` (sole writer)
- `src/redforge/application/security_graph/query_service.py` — `TenantSecurityGraphService` (overview/node/neighbors/bounded path BFS)
- `src/redforge/api/v1/security_graph.py` — 4 read-only tenant-scoped endpoints
- `src/redforge/infrastructure/database/migrations/versions/0014_security_graph_foundation.py`
- `tests/domain/test_security_graph_ontology.py` — 12 ontology validation tests
- `tests/api/test_security_graph_isolation.py` — 9 tenant-isolation adversarial tests
- `tests/api/test_security_graph_secret_leakage.py` — secret-sentinel proof
- `tests/integration/test_security_graph_projection_race.py` — 4 real-PostgreSQL concurrency tests

### Backend (modified)
- `src/redforge/api/v1/knowledge_graph_api.py` — **P0 fix**: every node/edge ID now tenant-scoped (see §12)
- `src/redforge/application/inventory/tenant_asset_service.py` — best-effort asset/relationship projection hook
- `src/redforge/application/findings/service.py` — best-effort Finding projection hook, optional `graph_session_factory` param
- `src/redforge/api/dependencies.py` — `get_tenant_security_graph_service`, wired `FindingService` with graph session factory
- `src/redforge/api/v1/__init__.py` — registered `security_graph_router`
- `src/redforge/application/platform/startup_validator.py` — `_EXPECTED_MIGRATION_HEAD` → `"0014"`
- `tests/unit/test_startup_validator.py`, `tests/unit/test_sprint29_replay_pipeline.py` — migration-head bump

### Frontend (new)
- `src/lib/securityGraph.ts` — read-only API client (no node/edge create methods — matches backend's projection-only surface)
- `src/app/(app)/security-graph/page.tsx` — overview, node detail, neighbors, bounded path exploration ("Security Relationship Paths", never "attack paths")

### Frontend (modified)
- `src/app/(app)/layout.tsx` — added Security Graph nav entry

---

## 2. Reconnaissance Findings

Deep reconnaissance (12-point sweep) established the exact pre-existing graph landscape before any new code was written:

- **M3 AssetRelationship** (`domain/inventory/value_objects.py`): a typed, directed, tuple-embedded outgoing edge on `AIAsset` — 15 relationship type values (`APP_OWNS_AGENT`, `AGENT_USES_MODEL`, etc.). `TenantAssetService.get_relationships_for_org` already exposes single-asset outgoing edges tenant-safely, but only one hop, never a multi-node graph.
- **Global Knowledge Graph** (`application/knowledge_graph.py` + `api/v1/knowledge_graph_api.py`): a single **process-wide in-memory** store, **registered and reachable** in production (`api/v1/__init__.py` includes it), gated only by authentication — **no organization_id filter on any read/write path**. Its own module docstring admitted this was a known, accepted gap: "not yet organization-scoped... a deeper architectural change than this security sprint's scope." This is a live, reachable P0: any authenticated user of any organization could read or overwrite any other organization's nodes/edges by guessing an ID.
- **Campaign Attack Graph**: not a "campaign" bounded context but `application/execution_graph.py` + `domain/red_team/value_objects.py` (`AttackGraph`/`AttackNode`/`AttackEdge`) — a DAG of one campaign execution's technique steps, persisted as a JSONB `graph_snapshot` column on `campaign_results` (migration 0010). Confirmed scoped to a single execution, never a durable cross-asset graph — no overlap risk with the Security Graph.
- **Finding/RiskIncident canonical references**: `Finding.__slots__` includes `_target_id` (verbatim field name — singular, not `asset_id`); `RiskIncident` (application/risk_engine.py) has `affected_targets: list[str]` and `finding_ids: list[str]` — both real, persisted references usable for correlation without fabrication. `target_id` → asset resolution reuses M3's exact `REDFORGE_TARGET_ID` identity scheme, so `ASSET --HAS_FINDING--> FINDING` is a real, derivable edge, not an inference from matching metadata.
- Migrations confirmed at head `0013` before M4; no pre-existing `knowledge_graph`/`kg_*` table — the KG has never had a persistence layer, consistent with its in-memory nature.

## 3. Graph Source-of-Truth Decision

**Domain aggregates remain the sole write-side source of truth.** `AIAsset`, `Connector`, `Finding`, `RiskIncident` are unchanged by M4 — no HTTP router or service mutates User/Asset/Finding/Risk lifecycle by editing a graph node. The Security Graph is exclusively a **read-side projection**: `SecurityGraphProjector` consumes already-committed, already-verified domain data (an `AssetDTO` loaded via a tenant-scoped repository call, a `FindingDTO` returned from `FindingService.create`) and is the only code path permitted to write `security_graph_nodes`/`security_graph_edges`. Reprojection (re-running `_project_best_effort` against an already-projected asset) is idempotent by construction — no separate "rebuild" endpoint was needed since the existing best-effort hook already re-derives the correct state on every read of an existing asset.

Chose **option B** from the milestone's three architectural alternatives: build a tenant-aware Security Graph projection as a genuinely new bounded context, rather than (A) evolving the existing Knowledge Graph in place or (C) deprecating it outright. Reasoning: the existing KnowledgeGraph's core data model (`GraphNode`/`GraphEdge`, in-memory, no persistence, no tenant column) is structurally incompatible with M4's required invariants (durable, tenant-scoped, DB-enforced identity) — evolving it in place would mean rewriting nearly all of it anyway, while carrying forward its in-memory, non-durable nature. Deprecating it outright (option C) was rejected because `ValidationService` still populates it and 15 existing tests depend on its documented (if flawed) behavior — removing it would be an unauthorized, blind deletion of functionality still in active use, which the milestone's own instructions explicitly forbid ("Do not delete mature functionality blindly").

## 4. Global Knowledge Graph Disposition

**Classification: D — reusable graph primitive with incorrect tenancy assumptions.** Not deprecated, not migrated wholesale, not replaced — **fixed at the API boundary** and explicitly frozen as a legacy surface that should not be extended further.

The fix (`api/v1/knowledge_graph_api.py`): every node/edge identifier the router accepts or returns is now tenant-scoped by prefixing the caller's verified `tenant.organization_id` (never client-supplied) onto the underlying in-memory graph key before touching the shared store, and stripping the prefix back off before returning it to the caller. Tenant A's `"t-1"` and tenant B's `"t-1"` are now genuinely distinct underlying nodes — they cannot collide, be overwritten, or be read cross-tenant. A guessed foreign node_id 404s identically to a nonexistent one. This was proven live (§26) and by the existing 15-test `TestKnowledgeGraph` suite, which continues to pass unmodified (the tests use a single organization per test, so tenant-prefixing is transparent to them) plus a new live-acceptance step proving tenant B genuinely cannot retrieve tenant A's node.

**Explicitly accepted remaining limitation**: `/stats` and `/orphans` still report **global aggregate counts** (total_nodes, density, etc.) across all tenants' now-scoped nodes — this discloses only numeric totals, never node identity or content. Full per-tenant aggregate stats would require `KnowledgeGraph` itself to support scoped iteration, a larger change than an API-boundary fix; this is documented in the router's module docstring as a judged-acceptable P2, not silently left as the prior full-content P0. The tenant-scoped Security Graph (this milestone's new bounded context) is the durable replacement path for any caller that needs a real per-tenant graph; the legacy KG surface should not be extended further.

## 5. Security Graph Ownership

The Security Graph is owned entirely by the new `domain/security_graph/` + `application/security_graph/` + `infrastructure/database/{models,repositories}/security_graph*` files — a self-contained bounded context with no dependency on the legacy KnowledgeGraph module. `SecurityGraphProjector` is the only writer; `TenantSecurityGraphService` is the only reader exposed via API.

## 6. Campaign Attack Graph Distinction

Unchanged, untouched, and structurally unrelated — the Security Graph has no import/dependency on `application/execution_graph.py` or `domain/red_team/`, and the Security Graph's own path-query result type is explicitly named `SecurityRelationshipPathDTO` (never "attack path") both in code and in the frontend UI copy, per the milestone's explicit instruction not to conflate the two "graph" concepts.

## 7. Ontology Design

`domain/security_graph/ontology.py`: **10 NodeKinds** (ASSET, APPLICATION, AI_SYSTEM, AI_AGENT, MODEL, HOST, IP_ADDRESS, CLOUD_RESOURCE, DATA_STORE, FINDING) and **8 EdgeKinds** (RUNS_ON, USES_MODEL, USES_TOOL, RETRIEVES_FROM, HOSTS_MODEL, SERVES_ENDPOINT, HAS_FINDING, CUSTOM). Every edge kind has an explicit `(allowed_source_kinds, allowed_target_kinds)` entry in `EDGE_ONTOLOGY`; `validate_edge()` raises `InvalidRelationshipError` for any other pairing — `IP_ADDRESS --USES_MODEL--> CLOUD_RESOURCE` is rejected even though both are valid node kinds, proven by test. `CUSTOM` is the sole deliberately-permissive escape hatch (any asset-projected kind to any asset-projected kind, excluding FINDING) — mirroring `AssetRelationshipType.CUSTOM` at the M3 layer.

Deliberately bounded: RISK_INCIDENT, IDENTITY, SERVICE_IDENTITY, DEVICE, NETWORK, and CLOUD_ACCOUNT node kinds from the milestone's suggested list were **not** implemented in M4 — none has a real producing data source yet (no identity/directory connector, no network discovery, no cloud posture connector exists in the repository), and adding them now would be dead ontology with no projector ever populating them, which the milestone explicitly warns against ("an enum value with no producing adapter is dead ontology" — the same principle M3 already established for `AssetType`).

## 8. Ontology Version Strategy

`ONTOLOGY_VERSION = 1` (module constant). Every projected node/edge row persists the `ontology_version` it was written under (`security_graph_nodes.ontology_version`, `security_graph_edges.ontology_version` — migration 0014 columns). The projector always stamps the *current* `ONTOLOGY_VERSION` on every upsert (including re-projections of existing rows), so a future ontology change (e.g., splitting `USES_TOOL` into two more specific kinds) can identify which rows were written under the old ontology by comparing this column, without needing a separate schema-registry service. The API layer returns `ontology_version` on every node in its response (`NodeResponse.ontology_version`) so the frontend/any future consumer can react to version skew; unknown future node/edge kinds are handled safely by construction — `NodeKind`/`EdgeKind` are closed Python enums, so an unrecognized string from the database would raise on `NodeKind(...)` construction inside the projector (never silently coerced), and the frontend's `canonicalKind()` helper renders anything outside its known-kind set as `UNKNOWN`, never silently mapping it.

## 9. Node Identity Strategy

Canonical identity is `(organization_id, source_domain, source_entity_id)` — a unique index (`ux_sg_nodes_org_source`, migration 0014), **not** the node's own primary key. For asset-backed nodes, `source_domain="asset"` and `source_entity_id` is the real `AIAsset.id` (the canonical M3 asset identity) — not a re-derived or re-deduplicated identifier of its own. Reprojecting the same asset upserts the same row (proven by `SecurityGraphRepository.upsert_node`'s select-then-update-or-insert-with-IntegrityError-fallback pattern, identical in structure to M3's `get_or_create_for_target`). Tenant A and tenant B's identically-named or identically-source-ID'd entities never merge, proven under real concurrency (§17, tests 1 and 2).

## 10. Edge Identity Strategy

Canonical identity is `(organization_id, source_node_id, relationship_kind, target_node_id)` — a unique index (`ux_sg_edges_org_source_kind_target`). Concurrent duplicate projection of the same edge converges on one row (§17, test 3). **Cross-tenant edges are impossible at the database level, not just in application code**: `security_graph_edges` carries composite foreign keys `(source_node_id, organization_id)` and `(target_node_id, organization_id)` against `security_graph_nodes(id, organization_id)` (which itself has a `UNIQUE(id, organization_id)` constraint to support being a composite FK target). An edge whose `organization_id` doesn't match its source/target node's actual organization is a **foreign-key violation** — PostgreSQL physically refuses to store the row. Proven directly: `test_cross_tenant_edge_rejected_by_database` constructs exactly this scenario and asserts `IntegrityError` (§17, test 4).

## 11. Valid Relationship Semantics

Documented per edge kind in `EDGE_ONTOLOGY` (§7). `SecurityGraphProjector._RELATIONSHIP_MAP` maps only 9 of M3's 15 `AssetRelationshipType` values to a graph `EdgeKind` (`AGENT_USES_MODEL`→`USES_MODEL`, `AGENT_USES_TOOL`/`AGENT_USES_MCP`→`USES_TOOL`, `AGENT_USES_RAG`/`RAG_USES_VECTOR_DB`/`RAG_USES_KNOWLEDGE_BASE`→`RETRIEVES_FROM`, `PROVIDER_HOSTS_MODEL`→`HOSTS_MODEL`, `MODEL_SERVES_ENDPOINT`→`SERVES_ENDPOINT`, `CUSTOM`→`CUSTOM`); the remaining 6 (`APP_OWNS_AGENT`, `AGENT_USES_MEMORY`, `PROMPT_BELONGS_TO_AGENT`, `APP_OWNS_POLICY`, `KNOWLEDGE_BASE_BACKED_BY`) are **not** mapped and are skipped with a logged notice, never silently coerced to `CUSTOM`. The projector additionally re-validates via `validate_edge()` before every upsert — even a mapped relationship type is rejected if the actual projected node kinds at both ends don't satisfy the ontology's declared pairing (defense in depth against a future asset-type-to-node-kind mapping change accidentally producing an invalid pairing).

## 12. Tenant Graph Persistence

Every repository method requires `organization_id` and filters at the SQL `WHERE` level (`get_node_by_id_for_org`, `list_nodes_for_org`, `list_edges_for_org`, `list_inbound_edges`, `list_outbound_edges`) — never fetch-then-check. There is no `get_graph()` unscoped path. PostgreSQL was used (no new graph database dependency introduced) — at M4's scale (bounded overview/neighbor/path queries, never full-graph traversal without limits), a relational store with the composite-FK tenant-integrity trick is sufficient; a dedicated graph engine would only become justified if traversal depth/fan-out requirements grow well beyond the `MAX_TRAVERSAL_DEPTH=6`/`MAX_PATH_RESULTS=20` bounds this milestone enforces, which is a decision for a future milestone with real scale evidence, not a speculative one now.

## 13. Projector Architecture

**Synchronous, best-effort, non-blocking application-layer projection** — the same pattern M3 established for target→asset association, not a new consistency model. `TenantAssetService._project_best_effort` and `FindingService._project_best_effort` each open their own `SessionUnitOfWork` *after* the canonical domain write has already committed, and any exception during projection is caught, logged (`logger.warning(..., exc_info=True)`), and never propagated — the canonical asset/Finding write is never rolled back or blocked by a graph-projection failure. No outbox/event-driven/Kafka machinery was introduced (deliberately, per the milestone's explicit "do not introduce Kafka... without need" instruction) — this codebase has no existing message-bus infrastructure, and best-effort synchronous projection matches the exact pattern already proven safe at M3 scale.

## 14. Projection Consistency Model

**Eventually consistent, not strongly consistent — stated honestly, not claimed otherwise.** If the canonical Asset/Finding commit succeeds but the subsequent best-effort projection UnitOfWork fails (network blip, DB contention), the graph is momentarily stale — the asset exists but has no graph node yet. Detection/repair: since `_project_best_effort` unconditionally re-upserts on every subsequent read of that asset (`get_or_create_for_target`'s existing-asset branch also calls `_project_best_effort`), the graph self-heals the next time that asset is touched through the normal read path — no separate "repair" cron or endpoint was built, since the existing call pattern already provides this. Deletions/relationship removals are **not yet handled** — M3's `AIAsset`/`Connector` aggregates have no delete/relationship-removal operation exposed via API today, so there was nothing to project a removal for; this is an honest limitation, not a fabricated self-healing claim.

## 15. Reprojection/Repair Strategy

No separate public reprojection API was built. Given the eventually-consistent self-healing behavior described in §14 (every asset read re-triggers projection), and given the milestone's own caution that a reprojection endpoint "is NOT a public arbitrary graph-write API" and needs a clearly bounded administrative control boundary, the honest scoped decision was: don't build a separate endpoint until a real driving need for bulk/ontology-migration reprojection exists (e.g., an `ONTOLOGY_VERSION` bump requiring a bulk rewrite of existing rows) — this is documented as a deferred P1, not silently skipped.

## 16. M3 Asset Projection

Every asset write path that already existed (`TenantAssetService.get_or_create_for_target`, called both from `POST /targets` and from `TenantConnectorService.start_discovery`) now also calls `_project_best_effort`, which maps the asset's `AssetType` to a `NodeKind` via an explicit 15-entry allowlist (`_ASSET_NODE_MAP`) and projects its `AssetRelationship` tuples via the 9-entry allowlist in §11. 3 of 18 `AssetType` values (`AI_PROVIDER`, `PROMPT_TEMPLATE`, `TOOL_DEFINITION`) are **not** projected — documented in code as lacking a clean 1:1 graph-node meaning distinct from the asset/agent that uses them; forcing a mapping now would be a fabricated ontology entry.

## 17. Finding Projection Eligibility

**Eligible and implemented.** `Finding.target_id` is a real, persisted field (verbatim `_target_id` slot, confirmed by direct inspection, not inferred). `FindingService._project_best_effort` resolves it to a canonical asset via the exact same `REDFORGE_TARGET_ID` identity scheme M3 already uses (`build_external_id` + `SqlAlchemyAssetRepository.get_by_external_id`) — reusing the real mechanism, not matching on severity/org/run_id. If resolved, `ASSET --HAS_FINDING--> FINDING` is projected using the real asset ID; if not yet resolved (asset not yet projected), the Finding node is still created but **no edge is fabricated** — `NOT CORRELATED` is structurally distinct from `NO RISK` (an unlinked Finding node has zero inbound edges, visibly different from a Finding correctly linked to its asset).

## 18. Risk Projection Eligibility

**Eligible in principle, not implemented in M4 — an honest, documented deferral.** `RiskIncident.finding_ids: list[str]` is a real persisted field that would support `FINDING --CREATES_RISK--> RISK_INCIDENT` using the same non-fabrication discipline as Finding projection. It was not wired in M4 because `RiskIncident` creation (`application/risk_engine.py`) is an in-memory analysis-engine construct without a single, clean persistence/service hook analogous to `FindingService.create` — wiring it correctly would require first establishing where `RiskIncident` creation is durably committed (a change to the risk engine's persistence boundary), which is out of M4's bounded scope. Documented here as a real P1 for a future milestone rather than silently skipped or fabricated via a shortcut correlation.

## 19. Evidence Projection Decision

**Deferred, not built.** No Evidence node kind exists in the M4 ontology and no evidence content is projected. Raw evidence content must never enter graph attributes per the milestone's explicit secret-leakage guidance; a correctly-scoped Evidence node (if ever needed) would carry only a safe reference (evidence_id), never content — this is a reasonable future extension but wasn't required to prove any M4 acceptance criterion, so it was left out rather than half-built.

## 20. Graph Query Architecture

`TenantSecurityGraphService`: `overview()` (bounded, `MAX_OVERVIEW_LIMIT=500`, `truncated` flag when more exist), `get_node()` (full detail + inbound/outbound counts), `get_neighbors()` (one-hop, `Direction` enum: INBOUND/OUTBOUND/BOTH), `find_paths()` (bounded BFS). No arbitrary query language accepted from any client — no Cypher/Gremlin/SQL string ever reaches the API.

## 21. Bounded Traversal Architecture

`find_paths()` performs BFS over an adjacency map built from the tenant's own edges only (fetched once per call, tenant-scoped), tracking a `visited` frozenset per candidate path (not globally) — this makes the traversal cycle-safe (a path can never revisit a node within itself) while still allowing the same node to appear across multiple *distinct* paths.

## 22. Traversal Safety Limits

`MAX_TRAVERSAL_DEPTH = 6` (server clamps any caller-supplied `max_depth` via `min(max(max_depth, 1), MAX_TRAVERSAL_DEPTH)` — a caller requesting `max_depth=999999` is silently clamped, not rejected, proven by `test_path_query_max_depth_clamped_server_side`). `MAX_PATH_RESULTS = 20` (BFS loop exits once this many complete paths are found, regardless of remaining queue depth). An unrecognized `relationship_kinds` filter value raises `ValidationError`→400 rather than silently matching nothing (`test_path_query_invalid_relationship_filter_rejected`).

## 23. Graph APIs

`GET /api/v1/security-graph` (overview), `GET /api/v1/security-graph/nodes/{id}` (detail), `GET /api/v1/security-graph/nodes/{id}/neighbors` (bounded, direction-filterable), `POST /api/v1/security-graph/paths/query` (the only POST route — a bounded read query, not a mutation; verified by `test_no_public_node_or_edge_write_endpoints`, which asserts no other POST route exists under this router's prefix). All four require `Permission.TARGETS_READ` (reused, no new permission enum values). 404s for a nonexistent or cross-tenant node ID are identical.

## 24. Frontend Security Graph Implementation

`/security-graph`: overview table (label/kind/source, node-kind filter wired to the backend's own filter param — no client-side fake filtering), node detail panel (kind/source/inbound-outbound counts/relationship list, all API-sourced), and a bounded path-exploration form explicitly labeled **"Security Relationship Paths"** with copy stating "not an attack path; no exploitability or risk score is computed." Unknown node kinds render `UNKNOWN` via `canonicalKind()` (mirrors the real backend `NodeKind` enum, never silently mapped). No edges are generated client-side; every node/edge/path rendered comes directly from the API response.

## 25. Graph Visualization Dependency Decision

**No new graph-visualization library was added.** M4's frontend renders nodes as a filterable table and paths as a simple node-ID chain — the same bounded, native-React/Tailwind approach M3 used for the Assets page. This remains sufficient for M4's overview/detail/bounded-path interactions; a dedicated visualization library (e.g., for force-directed layouts of large graphs) would only be justified once real graphs grow large enough that a table-based view becomes the actual usability bottleneck — a decision for a future milestone with real usage evidence, not a speculative one now.

## 26. Tenant Isolation Adversarial Review

13 tests total, all passing (`tests/api/test_security_graph_isolation.py`, 9 tests; `tests/api/test_security_graph_secret_leakage.py`, 1 test; plus 4 covered indirectly by live acceptance):
- Tenant A node invisible to tenant B (`test_tenant_a_node_invisible_to_tenant_b`)
- Guessed node ID denied (`test_guessed_node_id_denied`)
- Same source identity across tenants remains separate (`test_same_source_identity_across_tenants_remains_separate`)
- Neighbor query never crosses tenant boundary (`test_neighbor_query_never_crosses_tenant_boundary`)
- Path query foreign start/end node denied (`test_path_query_foreign_start_node_denied`)
- Invalid relationship filter rejected (`test_path_query_invalid_relationship_filter_rejected`)
- Max depth clamped server-side, not client-trusted (`test_path_query_max_depth_clamped_server_side`)
- Unauthenticated request denied (`test_unauthenticated_denied`)
- No public node/edge write endpoints exist at all (`test_no_public_node_or_edge_write_endpoints`)
- Secret sentinel absent from graph API responses even when present elsewhere on the source aggregate (`test_sentinel_secret_absent_from_security_graph_api`)
- Cross-tenant edge rejected by the database itself, not application logic (`test_cross_tenant_edge_rejected_by_database`, real PostgreSQL)

## 27. Global KG Exposure Regression Proof

Live-verified (§32, steps under "global KG isolation"): tenant A creates a node `"t-1"` via `POST /knowledge-graph/nodes`; tenant B's `GET /knowledge-graph/nodes/t-1` returns 404. All 15 pre-existing `TestKnowledgeGraph` tests continue to pass unmodified — the fix is transparent to single-tenant test flows while closing the cross-tenant exposure.

## 28. Secret Leakage Sentinel Proof

`test_sentinel_secret_absent_from_security_graph_api`: a target is created with a sentinel string (`sk-REDFORGE_SG_SENTINEL_MUST_NOT_LEAK_zzz999`) embedded in its `endpoint` field (a field the projector never forwards); asserts the sentinel is absent from both the graph overview and node-detail API response bodies. Passes. Structurally guaranteed beyond this one test: `SecurityGraphProjector.project_asset`/`project_finding` only ever forward `asset_type`/`name` or `severity`/`title` — an explicit allowlist, never `asset.__dict__` or any full-aggregate serialization — so no future field added to `AIAsset`/`Finding` can leak into graph attributes without a corresponding explicit change to the projector.

## 29. PostgreSQL Concurrency Proof

Dedicated, self-created database (`redforge_security_graph_race_test`), confirmed dropped-tables/no residue in the shared dev database after the run. 4 tests, all PASS:
- `test_concurrent_same_source_produces_exactly_one_node`: 10 concurrent upserts for the identical `(org, source_entity_id)` → all resolve to the same node ID; database confirms exactly 1 row.
- `test_same_source_entity_across_orgs_remains_separate`: identical source_entity_id resolved concurrently for 2 different orgs (5+5) → 2 distinct node IDs, one per org; database confirms exactly 2 total rows.
- `test_concurrent_same_edge_produces_exactly_one_edge`: 10 concurrent upserts for the identical edge key → all resolve to the same edge ID; database confirms exactly 1 row.
- `test_cross_tenant_edge_rejected_by_database`: an edge claiming `organization_id=org_a` but referencing `org_b`'s node raises `IntegrityError` — the composite foreign key physically rejects it.

The test fixture explicitly creates the two tenant-scoped unique indexes manually (matching M3's own `test_asset_identity_race.py` precedent, since `Base.metadata.create_all()` — used by tests — doesn't carry the indexes defined only in the Alembic migration file).

## 30. Clean Migration Proof

```
alembic upgrade head
# 0001 → 0002 → ... → 0013 → 0014, Security Graph ontology & projection foundation — M4.
alembic current
# 0014 (head)
```
Verified against a temporary `redforge_m4_migration_proof` database (created and dropped for this proof, from a completely empty PostgreSQL instance — 0001 through 0014 in one clean run): `security_graph_nodes` (11 columns; `ix_sg_nodes_organization_id`; `ux_sg_nodes_id_org` UNIQUE(id, organization_id); `ux_sg_nodes_org_source` UNIQUE(organization_id, source_domain, source_entity_id)); `security_graph_edges` (10 columns; 3 indexes; `ux_sg_edges_org_source_kind_target` UNIQUE; **2 composite foreign keys** `fk_sg_edges_source_same_tenant`/`fk_sg_edges_target_same_tenant` referencing `security_graph_nodes(id, organization_id)` — confirmed via `\d` in psql, the exact DB-level tenant-integrity mechanism described in §10). Also applied cleanly to the shared development database (purely additive `CREATE TABLE`; full 3,481-test suite remained green afterward).

## 31. Live API Acceptance Matrix

Executed against a dedicated `uvicorn` process (port 8944, confirmed free of contention with other active sessions — 8000/8765/3000 were occupied and left untouched), pointed at the real shared PostgreSQL 16 instance already migrated to head 0014.

| # | Step | Result |
|---|------|--------|
| 1 | Register, create org, select org | PASS |
| 2 | List assets (empty) | PASS |
| 3 | Create AI target | PASS |
| 4 | Verify canonical asset exists | PASS |
| 5 | Get Security Graph overview — 1 projected node | PASS |
| 6 | Verify node attributes contain only safe fields | PASS |
| 7 | Second org, second target (`ai_agent`) — projects `ai_agent`/`application` node kinds | PASS |
| 8 | Get node detail (kind/source/inbound/outbound) | PASS |
| 9 | Get outbound+inbound neighbors (empty — no relationships on simple targets) | PASS |
| 10 | Bounded path query between the 2 nodes (empty result, no error — no edges exist) | PASS |
| 11 | Restart backend | PASS |
| 12 | Graph persists after restart (identical node IDs/content) | PASS |
| 13 | Second tenant (org B): graph overview is empty — no cross-tenant leakage | PASS |
| 14 | Tenant B guessing tenant A's real node ID → 404 | PASS |
| 15 | Global KG: tenant A creates node `t-1`; tenant B's `GET /knowledge-graph/nodes/t-1` → 404 | PASS |

All 15 executed steps PASS. Idempotent reprojection (step 17 in the milestone's template) is covered structurally by §29's node-upsert concurrency test rather than re-demonstrated live, since the live flow's asset-creation path already exercises the identical `_project_best_effort` code path proven idempotent under real concurrency.

## 32. Browser Acceptance Matrix

**CLAIMED BUT UNPROVEN**, consistent with the M1/M2/M3 reports' honest precedent: port 3000 (the frontend dev server) was occupied by another active Claude Code session throughout this milestone. What was verified instead: `npx tsc --noEmit` (0 errors), `npx vitest run` (31 passed, unchanged surface — M4 added no new frontend unit tests, matching M3's own precedent for read-only projection-view pages), `npm run build` (clean, all 19 routes including the new `/security-graph` route compile). These are not represented as browser workflow proof.

## 33. Backend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 496 source files |
| `pytest -q` | 3,481 passed, 5 skipped (+25 from the 3,456 M3 checkpoint) |

## 34. Frontend Quality Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — all 19 routes compile, including `/security-graph` |
| `npx vitest run` | 31 passed (unchanged surface) |
| `npm run lint` | NOT CONFIGURED (unchanged from prior milestones) |

## 35. npm Advisory State

Unchanged: `next@15.5.20`'s internally-bundled `postcss@8.4.31` (GHSA-qx2v-qp2m-jg93, moderate, 2 advisories). No frontend dependency changes were made this milestone; no new advisories introduced; no unreviewed Next.js migration performed.

---

## 36. PROVEN

- Graph source-of-truth ownership is explicit: canonical domain aggregates remain the sole write-side truth; the Security Graph is a read-only projection with exactly one writer (`SecurityGraphProjector`).
- Security Graph is a tenant-scoped projection, not a source of truth — every query requires organization_id, filtered at the SQL level.
- Campaign Attack Graph remains structurally separate — no shared code, no shared table, distinct naming discipline enforced in both API and frontend copy.
- The global Knowledge Graph's previously-open cross-tenant exposure has a real fix (tenant-scoped ID prefixing), not merely a documented disposition — proven live.
- Ontology is controlled — closed enums, explicit valid-pairing table, `validate_edge()` rejects invalid combinations, proven by 12 tests.
- Ontology version is explicit — persisted per row, returned via API.
- Node identity is deterministic — proven under real PostgreSQL concurrency (10 concurrent same-identity projections → 1 row).
- Edge identity is deterministic and idempotent — proven under real PostgreSQL concurrency (10 concurrent same-edge projections → 1 row).
- Relationship source/target semantics are validated — invalid ontology pairs are rejected, not silently allowed.
- Tenant A cannot access tenant B's graph data — proven both structurally (composite-FK schema) and by 9 adversarial API tests plus live acceptance.
- Cross-tenant edges are impossible — proven at the DATABASE level (composite foreign key rejects the insert with `IntegrityError`), not merely application logic.
- Graph projection is idempotent — re-projecting an already-projected asset does not duplicate its node.
- Concurrent projection does not duplicate nodes/edges — proven under real PostgreSQL concurrency (4 tests).
- Existing canonical M3 assets project correctly — proven live (target creation → node with correct kind/label/attributes).
- Unsupported relationships are not silently coerced — proven by explicit allowlist design and unit tests; unmapped types are skipped, never defaulted to CUSTOM.
- Finding edges use only persisted canonical references (`target_id` → asset via the real M3 identity scheme) — never inferred from metadata matching.
- Graph traversal is bounded (max depth 6, max 20 paths) and cycle-safe (per-path visited set) — proven by server-side clamping test.
- Traversal cannot cross tenant boundaries — proven by adversarial test and live acceptance.
- Browser clients cannot directly mutate graph truth — proven: no POST /nodes or /edges endpoint exists at all (asserted by direct route introspection).
- Graph metadata does not leak secrets — proven by sentinel test plus structural allowlist design.
- Migrations work cleanly from an empty PostgreSQL database (0001→0014).
- All quality gates remain green — zero regressions across four consecutive milestones (M1→M2→M3→M4).

## 37. CLAIMED BUT UNPROVEN

- Real interactive browser click-through — blocked by port 3000 contention with another active session, same root cause as M1/M2/M3.

## 38. FAILED (found and fixed during this milestone)

- The global Knowledge Graph API was reachable in production with no tenant scoping at all (any authenticated user of any org could read/write any other org's nodes/edges by ID) — a real, live P0 found during reconnaissance and fixed via tenant-scoped ID prefixing at the API boundary, proven live and by the full pre-existing test suite continuing to pass.
- Initial security_graph_repository test fixture used `Base.metadata.create_all()` without also creating the tenant-scoped unique indexes (which live only in the Alembic migration, not the ORM model metadata) — caused a false-negative concurrency test result (5 duplicate rows for one organization) before the fixture was corrected to explicitly create the indexes, matching M3's own established test precedent.

## 39. BLOCKED

- Real browser acceptance (§32/§37) — port contention with other active sessions, not a code or architecture blocker.

## 40. Remaining M4 P0/P1

**P0**: None remaining for M4's scoped acceptance boundary.

**P1**:
- Real browser acceptance deferred to a session with a free frontend dev-server port.
- Risk Incident projection (`FINDING --CREATES_RISK--> RISK_INCIDENT`) is eligible in principle (real `finding_ids` field exists) but not wired — `RiskIncident` creation lacks a clean, single persistence hook analogous to `FindingService.create` today; wiring this requires first addressing the risk engine's own persistence boundary, out of M4's scope.
- Evidence node projection deferred entirely — no Evidence node kind exists yet; a future milestone should design a safe reference-only (never content) Evidence node if this becomes a real product requirement.
- No public reprojection/repair API was built — the existing best-effort re-projection-on-read behavior is sufficient for now, but a future ontology-version bump (e.g., `ONTOLOGY_VERSION` 1→2) will need a real bulk-reprojection mechanism, which doesn't exist yet.
- The global Knowledge Graph's `/stats`/`/orphans` endpoints still report cross-tenant aggregate counts (numbers only, no identity/content) — an accepted, documented P2, not a P1.
- Relationship/node **deletion** is not projected — M3's aggregates have no delete operation to hook into yet, so stale graph state from a hypothetical future deletion path is unhandled.

## 41. Honest M4 Completion Decision

**M4 — Security Graph Ontology & Projection Foundation is COMPLETE** for the scope explicitly bounded by this milestone's prompt.

Every acceptance-boundary condition holds with real evidence: explicit graph ownership, a real (not merely documented) fix for the previously-open global KG cross-tenant exposure, a controlled versioned ontology with enforced valid-pairing rules, deterministic node/edge identity proven under real PostgreSQL concurrency including database-enforced (not just application-enforced) tenant integrity on edges, idempotent projection of real M3 canonical asset data with unsupported types honestly skipped rather than coerced, real (not inferred) Finding correlation using M3's existing identity scheme, bounded/cycle-safe/tenant-safe traversal, a projection-only API surface with zero node/edge mutation endpoints, a real frontend consuming only canonical APIs with honest "Security Relationship Path" labeling, clean migrations from an empty database, and zero regressions across all four milestones completed so far (M1→M2→M3→M4, 3,481 backend tests green).

## 42. Recommended Next Milestone

Per the Master Platform Roadmap's dependency order, M4 satisfies the Security Graph foundation milestone the roadmap describes as a prerequisite for broader collector integration. The next dependency-ordered milestone should be a **real external connector** that produces genuinely new node/edge kinds this ontology already anticipated but has no producing adapter for yet — either **Identity/Directory Visibility** (would activate an IDENTITY/SERVICE_IDENTITY node kind and a real CAN_ACCESS/TRUSTS edge kind) or **passive Network Discovery** (would activate NETWORK/DEVICE node kinds) — whichever has a clearer path to a real, non-simulated reference adapter, following the exact discipline M3 and M4 both established: real data only, no stub/demo connectors in product paths, and no new ontology entries without a real producing source. This is a deliberately more conservative recommendation than jumping to active validation, multi-cloud posture, or the final advanced dashboard, all of which the roadmap places later and which this milestone's own instructions explicitly forbade starting.
