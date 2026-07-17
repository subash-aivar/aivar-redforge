# M22 Phase 4 + Phase 5 — Threat Fusion + Attack Path Engine: Implementation Report

**Status**: COMPLETE (Phases 4 and 5 of 7 only — Investigation Integration, Frontend, and additional feed types explicitly out of scope)
**Date**: 2026-07-17
**Migration head**: `0038` (`0037` Threat Fusion → `0038` Attack Path Engine)
**Commit status**: NOT COMMITTED, NOT PUSHED — awaiting ChatGPT review per explicit instruction.

---

## 1. Scope

This deliverable implements two consecutive M22 bounded contexts on top of the Phase 1–3
Threat Intelligence foundation:

| Implementation phase | Freeze mapping | Deliverable |
|---|---|---|
| **Phase 4 — Threat Fusion** | Architecture Freeze P3 | Normalize, dedupe, correlate, enrich, and score confidence for indicators derived from Phase 1 reference-data catalog rows (populated by Phase 3 STIX/TAXII and/or Phase 1 admin loads). |
| **Phase 5 — Attack Path Engine** | Architecture Freeze P5 (+ ontology nodes/edges from Freeze P4) | Build an ATT&CK relationship graph from fused outputs, traverse under explosion budgets, persist tenant-scoped attack paths with confidence/risk/exposure propagation. |

**Implemented**:

- Threat Fusion aggregate (`FusedIndicator`) with lifecycle, temporal validity, source
  attributions, `AggregatedRisk` (including `NO_EVIDENCE` sentinel), confidence provenance,
  and conflict/TTL policies with a documented default weight table.
- Cross-feed correlation via `FusedRelationship` (separate from the indicator aggregate).
- Fusion application services, internal APIs, authorization, audit events, PostgreSQL
  persistence (migration `0037`).
- Attack Path aggregate (`AttackPath` summary only — steps via separate repository), MITRE
  ATT&CK graph construction/traversal/path discovery, confidence/risk/exposure propagation,
  kill-chain mapping metadata, cycle and budget protection, persistence (migration `0038`),
  internal APIs, authorization, audit events.
- Ontology v7 additive node/edge kinds for future ThreatIntel security-graph projection.
- Domain unit tests + PostgreSQL end-to-end STIX-catalog → Fusion → Attack Path integration.

**Explicitly NOT implemented** (deferred per instruction):

- Investigation Integration
- Frontend
- New feed source kinds / connectors beyond Phase 3's STIX/TAXII connector architecture
- Full ThreatIntel → Security Graph projector (ontology kinds added; path traversal uses the
  fused ATT&CK graph directly)

---

## 2. Architecture Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **Fusion consumes only Phase 1 reference-data catalog outputs** (tactics/techniques/relationships/vulnerabilities), never re-parses STIX and never calls M18 IP enrichment providers. | User constraint: “Threat Fusion must consume only the normalized outputs produced by the existing Phase 3 STIX/TAXII layer.” Phase 3 writes exclusively through Phase 1 `ReferenceDataAdminService` into Phase 1 tables — that catalog is the sole fusion input. |
| 2 | **`FusedIndicator` is the sole fusion aggregate; `FusedRelationship` is a separate entity.** | Hardening Review: unbounded relationship collections must not live inside the aggregate. Relationships are loaded/upserted via `FusedRelationshipRepository`. |
| 3 | **`FusionConfidence` ≠ M21 `CorrelationConfidence`; `PathConfidence` ≠ `FusionConfidence`.** | Hardening Review P2: calibration ladders must not silently couple across bounded contexts even when level names match. Conversion is explicit (`path_confidence_from_fusion`). |
| 4 | **`AggregatedRiskState.NO_EVIDENCE` when attributions are empty.** | Hardening Review P0: never reuse a stale risk snapshot when sources disappear. |
| 5 | **`DEFAULT_FUSION_WEIGHTS` documented in domain policy.** | Hardening Review P1: a fresh platform with no admin overrides must still have deterministic fusion behavior. Admin overrides live in `threat_intel_fusion_config`. |
| 6 | **`AttackPath` holds summary only; steps + evidence via child repos/tables.** | Hardening Review P0 unbounded-collection anti-pattern. Evidence refs use a join table (`attack_path_step_evidence`), not unbounded string arrays on the path row. |
| 7 | **`PathExplosionBudget` defaults: max_depth=6, max_fan_out=4** (more conservative than freeze's illustrative 12/8). | Protects graph construction from cycles and unbounded traversal (user + hardening security requirements). BFS skips already-visited nodes on a branch. |
| 8 | **On-demand compute: `POST /attack-paths/compute` requires `organization_id` + `seed_indicator_id`.** | Attack paths are tenant-scoped; fusion catalog is platform-global. Seeded compute keeps transactions short and avoids full-catalog path explosion. |
| 9 | **Ontology version bumped to 7** with `ATTACK_TECHNIQUE` / `THREAT_ACTOR` / `VULNERABILITY` nodes and `USES_TECHNIQUE` / `EXPLOITS_VULNERABILITY` / `ATTRIBUTED_TO` / `PRECEDES` edges. | Freeze P4 ontology surface for future projection; Phase 5 path engine does not depend on the projector being complete. |
| 10 | **Additive Phase 1 repo methods only** (`list_all` / `list_all_relationships`) for fusion catalog reads. | Fusion must page the full catalog without inventing a second persistence path; Phase 1–3 write paths remain unchanged. |
| 11 | **Stub fused indicators for non-technique STIX relationship endpoints** (software/campaign/group/mitigation). | Relationship resolution requires both endpoints; Phase 1 has no first-class aggregates for those STIX types yet — stubs preserve graph connectivity without fabricating ATT&CK technique rows. |
| 12 | **Flush parent `attack_path_steps` before inserting evidence rows.** | asyncpg/SQLAlchemy executemany otherwise violates FK `fk_attack_path_step_evidence_step_id_attack_path_steps` within the same transaction. |

---

## 3. Aggregate / Domain Model Changes

### Phase 4 — Threat Fusion

- **Aggregate**: `FusedIndicator` — lifecycle state machine (`active` → `superseded`/`expired`/`revoked`), temporal validity, attributions, metadata enrichment, `AggregatedRisk` snapshot.
- **Entity (non-aggregate)**: `FusedRelationship` — typed edge between two fused indicator IDs with optional `stix_relationship_id`.
- **Value objects**: `CanonicalIndicatorKey`, `FusedIndicatorType`, `FusionConfidence`, `SourceAttribution`, `TemporalValidity`, `AggregatedRisk` / `AggregatedRiskState`, `FusionWeight`, `RiskSourceBreakdown`.
- **Policies**: `FusionConflictPolicy` (weight + recency + group corroboration floor), `IndicatorTTLPolicy`.
- **Events**: `IndicatorFused`, `IndicatorLifecycleChanged`.
- **Exceptions**: lifecycle, batch-size, weight validation, etc.

### Phase 5 — Attack Path Engine

- **Aggregate**: `AttackPath` — org-scoped summary, status machine (`active` → `contained`/`historical`), path confidence, technique coverage, exposure.
- **Value objects**: `AttackStep`, `StepType` (OBSERVED/INFERRED), `PathConfidence`, `PathExplosionBudget`, graph nodes/edges.
- **Policies**: `InferenceGatePolicy` (INFERRED requires sequence-adjacent OBSERVED ≥ MEDIUM), `PathExplosionPolicy`.
- **Graph**: `AttackGraph` + BFS `discover_paths` with cycle skip, fan-out trim, depth/visit/path caps, weakest-link confidence, risk/exposure propagation, kill-chain phase carry-through from fusion metadata.
- **Events**: `AttackPathComputed`, `AttackPathUpdated`.

---

## 4. Repository / Persistence Changes

### New migrations

| Revision | Tables |
|---|---|
| `0037` | `fused_indicators`, `fused_indicator_sources`, `fused_relationships`, `threat_intel_fusion_config` |
| `0038` | `attack_paths`, `attack_path_steps`, `attack_path_step_evidence` |

### New repositories (infrastructure)

- `SqlAlchemyFusedIndicatorRepository`, `SqlAlchemyFusedRelationshipRepository`, `SqlAlchemyFusionConfigRepository`
- `SqlAlchemyAttackPathRepository`, `SqlAlchemyAttackPathStepRepository`

### Additive Phase 1 repository methods

- `AttackTechniqueRepository.list_all` / `list_all_relationships`
- `AttackTacticRepository.list_all`
- `VulnerabilityRepository.list_all`
  (domain Protocol + SQLAlchemy implementations)

---

## 5. Application Services

| Service | Responsibility |
|---|---|
| `ThreatFusionService.fuse_reference_catalog` | Page catalog → upsert fused indicators (tactics/techniques/vulns) → stub relationship endpoints → upsert fused relationships → audit `INDICATOR_FUSED`. |
| `ThreatFusionQueryService` | Read indicators / weights. |
| `ThreatFusionService` weight APIs | Persist admin weight overrides + audit `FUSION_WEIGHT_UPDATED`. |
| `AttackPathService.compute` | Load active fused indicators + relationships → build graph → discover paths from seed → archive prior ACTIVE paths for org+seed → persist path/steps/evidence → audit `ATTACK_PATH_COMPUTED`. |
| `AttackPathService.contain` / `archive` | Status transitions + `ATTACK_PATH_UPDATED`. |
| `AttackPathQueryService` | List/get paths with steps. |

---

## 6. API Additions

### Threat Fusion — `/threat-intel/fusion`

| Method | Path | Permission |
|---|---|---|
| `POST` | `/run` | `platform:threat_fusion:manage` |
| `GET` | `/weights` | `platform:threat_fusion:read` |
| `PUT` | `/weights` | `platform:threat_fusion:manage` |
| `GET` | `/indicators` | `platform:threat_fusion:read` |
| `GET` | `/indicators/{indicator_id}` | `platform:threat_fusion:read` |

### Attack Paths — `/attack-paths`

| Method | Path | Permission |
|---|---|---|
| `POST` | `/compute` | `platform:attack_path:manage` |
| `GET` | `` | `platform:attack_path:read` (org-scoped query) |
| `GET` | `/{path_id}` | `platform:attack_path:read` |
| `POST` | `/{path_id}/contain` | `platform:attack_path:manage` |
| `POST` | `/{path_id}/archive` | `platform:attack_path:manage` |

Permissions wired into SECURITY_ADMIN (read+manage) and AUDITOR (read).

### Audit actions added

- `INDICATOR_FUSED`
- `FUSION_WEIGHT_UPDATED`
- `ATTACK_PATH_COMPUTED`
- `ATTACK_PATH_UPDATED`

---

## 7. Files Added

### Domain — Fusion

- `backend/src/redforge/domain/threat_intel/fusion_value_objects.py`
- `backend/src/redforge/domain/threat_intel/fusion_exceptions.py`
- `backend/src/redforge/domain/threat_intel/fusion_events.py`
- `backend/src/redforge/domain/threat_intel/fusion_policies.py`
- `backend/src/redforge/domain/threat_intel/fusion_entity.py`
- `backend/src/redforge/domain/threat_intel/fusion_repository.py`

### Domain — Attack Path

- `backend/src/redforge/domain/attack_path/__init__.py`
- `backend/src/redforge/domain/attack_path/value_objects.py`
- `backend/src/redforge/domain/attack_path/exceptions.py`
- `backend/src/redforge/domain/attack_path/events.py`
- `backend/src/redforge/domain/attack_path/policies.py`
- `backend/src/redforge/domain/attack_path/entity.py`
- `backend/src/redforge/domain/attack_path/graph.py`
- `backend/src/redforge/domain/attack_path/repository.py`

### Application / API / Infra

- `backend/src/redforge/application/threat_intel/threat_fusion_service.py`
- `backend/src/redforge/application/threat_intel/threat_fusion_query_service.py`
- `backend/src/redforge/application/attack_path/__init__.py`
- `backend/src/redforge/application/attack_path/attack_path_service.py`
- `backend/src/redforge/api/v1/threat_fusion.py`
- `backend/src/redforge/api/v1/attack_paths.py`
- `backend/src/redforge/infrastructure/database/migrations/versions/0037_threat_fusion.py`
- `backend/src/redforge/infrastructure/database/migrations/versions/0038_attack_path_engine.py`
- `backend/src/redforge/infrastructure/database/models/threat_fusion.py`
- `backend/src/redforge/infrastructure/database/models/attack_path.py`
- `backend/src/redforge/infrastructure/database/repositories/threat_fusion_repository.py`
- `backend/src/redforge/infrastructure/database/repositories/attack_path_repository.py`

### Tests / Docs

- `backend/tests/domain/test_fusion_domain.py` (9)
- `backend/tests/domain/test_attack_path_domain.py` (9)
- `backend/tests/integration/test_m22_threat_fusion_attack_path_pg.py` (3)
- `docs/M22_PHASE4_PHASE5_THREAT_FUSION_ATTACK_PATH_REPORT.md` (this report)

---

## 8. Files Modified

| File | Change |
|---|---|
| `backend/src/redforge/api/v1/__init__.py` | Register fusion + attack-path routers. |
| `backend/src/redforge/infrastructure/database/models/__init__.py` | Export new ORM models. |
| `backend/src/redforge/application/platform/startup_validator.py` | Migration head → `0038`. |
| `backend/src/redforge/domain/platform_identity/value_objects.py` | `PLATFORM_THREAT_FUSION_*`, `PLATFORM_ATTACK_PATH_*` + role wiring. |
| `backend/src/redforge/domain/security_graph/ontology.py` | `ONTOLOGY_VERSION = 7` + new node/edge kinds. |
| `backend/src/redforge/infrastructure/audit/contracts.py` | Four new `AuditAction` values. |
| `backend/src/redforge/domain/threat_intel/reference_data_repository.py` | Additive `list_all` / `list_all_relationships` Protocol methods. |
| `backend/src/redforge/infrastructure/database/repositories/threat_intel_reference_data_repository.py` | SQLAlchemy implementations of additive catalog reads. |
| `backend/tests/unit/test_startup_validator.py` | Head pin `0038`. |
| `backend/tests/unit/test_sprint29_replay_pipeline.py` | Head pin `0038`. |
| `backend/tests/integration/test_m22_feed_sync_pg.py` | Head pin `0038`. |
| `backend/tests/integration/test_m22_reference_data_pg.py` | Head pin `0038`. |
| `docs/PROJECT_CONTEXT.md` | Milestone row + header baseline for Phases 4–5. |

Phase 1–3 business logic was not rewritten. The only Phase-1-owned functional addition is the
catalog `list_all*` read methods required for fusion to consume normalized outputs.

---

## 9. Test Counts

| Suite | Count | Result |
|---|---|---|
| Fusion domain unit | 9 | passed |
| Attack Path domain unit | 9 | passed |
| PostgreSQL integration (E2E + migration head + weight override) | 3 | passed |
| **Total Phase 4/5 new tests** | **21** | **all passed** |

Coverage highlights:

- IOC normalization / canonical keys / STIX-ref → type mapping
- Dedup + merge lifecycle, revoke terminal
- Conflict policy: NO_EVIDENCE, weight win, group corroboration floor, invalid weights
- Path confidence weakest-link, risk/exposure (KEV boost), inference gate, BFS + cycles, missing seed
- PG: reference seed → fusion → compute path → persist; migration head `0038`; weight override persistence

---

## 10. Quality Gates

| Gate | Status |
|---|---|
| Ruff (all Phase 4/5 source + tests) | Clean |
| Mypy (24 Phase 4/5 modules) | Clean — 0 errors |
| Domain unit tests | 18/18 passed |
| PostgreSQL integration | 3/3 passed |
| Migration verification | Clean empty DB: upgrade → `0038`; downgrade `0038→0037→0036`; upgrade → `0038`; `alembic heads` = `0038` |

---

## 11. Security Notes

- All fusion/attack-path write APIs require platform manage permissions; reads require read.
- Fusion batch capped (`_MAX_FUSION_INDICATORS = 20_000`); attack-path BFS budgeted.
- Inference hops gated on observed predecessors.
- Audit coverage on fuse, weight update, path compute, contain/archive.
- Actor IDs truncated to 26 chars for `platform_audit_log.actor_id` (VARCHAR(26) — Phase 3 lesson).
- Input validation via Pydantic Field constraints on org/seed ULIDs and weight ranges.

---

## 12. Out of Scope / Deferred

- Investigation Integration (M22 later phase)
- Frontend
- Additional feed connectors / STIX types beyond Phase 3
- Full security-graph ThreatIntel projector (ontology ready; projector not required for path compute)

---

## 13. Stop Condition

Phases 4 and 5 are complete per the approved brief. **No commit. No push.** Awaiting ChatGPT review.
