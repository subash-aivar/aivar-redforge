# M32 Phase 3 + Phase 4 Implementation Report

**Status:** COMPLETE — awaiting architecture review  
**Date:** 2026-07-21  
**Scope:** Phase 3 (Threat Intelligence & Exposure Correlation) + Phase 4 (Exposure Simulation & Campaign Integration)  
**Explicitly excluded:** Phase 5 (`exposure_reporting`, `BusinessImpactMapping` CRUD, Security Graph writes)

---

## 1. Executive Summary

Phase 3 and Phase 4 of M32 CTEM are implemented against the frozen architecture (Review APPROVED + Finalization COMPLETE). Hybrid M21 threat-actor integration is live via `ThreatActorMatchCache` (event primary + poll fallback), with ThreatActorMatch / ConfirmedExploitation amplifiers feeding the existing four-stage score pipeline. Phase 4 adds the `remediation_impact` bounded context with deterministic `GreedyMarginalContribution` simulation, `ExposureReductionPlan` aggregate, and the M30-owned `IExposureScopeQueryPort` contract with M32 service + adapter. Alembic head is **0083**. Quality gates pass: **ruff**, **mypy --strict**, **47** tests.

**STOP:** No Phase 5. No commit. No push.

---

## 2. Features Implemented

### Phase 3
- `ThreatActorMatchCache` projection (CVE / asset-class / technique / IOC indexes, 48h staleness)
- Hybrid M21 integration (`IThreatIntelligenceQueryPort` + seedable adapter)
- Event subscriber for `ThreatActorAssetClassTargetingUpdated`
- Daily poll scheduler stub + bootstrap-on-cold
- Cache refresh / invalidation via event + poll paths
- ThreatActorMatch RiskAmplifier attachment + pending recomputation
- KEV correlation (existing Phase 1 amplifier path retained)
- ConfirmedExploitation amplifier ingest (M29 correlation)
- IOC / TTP / ATT&CK technique entries in cache
- Threat intelligence CQRS read model + REST APIs
- Migration `0082`

### Phase 4
- `ExposureReductionPlan` aggregate (Generated → Committed)
- `GreedyMarginalContribution` (Top-K, portfolio-weighted sampling, deterministic seed)
- Business impact estimation (projected score delta × factor; not Phase 5 BIM)
- `ExposureScopeService` + M30 port/DTOs + `ExposureScopeM32Adapter`
- Simulation / prioritization / ranking APIs
- Background simulation worker helper
- Domain events + handlers (structlog publisher)
- Migration `0083`

---

## 3. Files Created

### Exposure (Phase 3 / 4 additions)
- `backend/src/exposure/domain/ports/i_threat_intelligence_query_port.py`
- `backend/src/exposure/infrastructure/projections/threat_actor_match_cache.py`
- `backend/src/exposure/infrastructure/repositories/threat_actor_match_cache_repository.py`
- `backend/src/exposure/infrastructure/acl/threat_intelligence_m21_adapter.py`
- `backend/src/exposure/infrastructure/events/threat_actor_targeting_subscriber.py`
- `backend/src/exposure/infrastructure/scheduler/threat_actor_poll_scheduler.py`
- `backend/src/exposure/application/services/threat_actor_match_sync_service.py`
- `backend/src/exposure/application/services/threat_intelligence_query_service.py`
- `backend/src/exposure/application/services/exposure_scope_service.py`
- `backend/src/redforge/infrastructure/database/migrations/versions/0082_exposure_phase3_threat_actor_match_cache.py`

### Remediation Impact (Phase 4 BC)
- Full tree under `backend/src/remediation_impact/` (domain / application / infrastructure / api)
- `backend/src/redforge/infrastructure/database/migrations/versions/0083_remediation_impact_phase4_plans.py`

### Campaign (M30 port ownership)
- `backend/src/campaign/domain/ports/i_exposure_scope_query_port.py`
- `backend/src/campaign/infrastructure/acl/exposure_scope_m32_adapter.py`

### Tests
- `backend/tests/exposure/phase3/*`
- `backend/tests/remediation_impact/**`

### Docs
- `docs/architecture/m32/M32_PHASE3_PHASE4_IMPLEMENTATION_REPORT.md`

---

## 4. Files Modified

- `backend/src/exposure/domain/aggregates/exposure_record.py` (cve_ids / asset_classes)
- `backend/src/exposure/domain/value_objects/enums.py` (`exposure:simulation_reader`)
- `backend/src/exposure/application/commands/exposure_commands.py`
- `backend/src/exposure/application/services/ingestion_app_service.py`
- `backend/src/exposure/infrastructure/container.py`
- `backend/src/exposure/infrastructure/persistence/models/exposure_models.py`
- `backend/src/exposure/api/schemas/exposure_schemas.py`
- `backend/src/exposure/api/v1/routes.py`
- `backend/src/redforge/api/v1/__init__.py`
- `backend/pyproject.toml`
- `backend/tests/exposure/test_architecture_invariants.py`
- `backend/tests/exposure/test_migration_chain.py`

---

## 5. Aggregates Added

| Aggregate | BC | Notes |
|---|---|---|
| `ExposureReductionPlan` | `remediation_impact` | Immutable simulation output; commit is human gate only |
| *(projection)* `ThreatActorMatchCache` | `exposure` | Read model, not aggregate root |

Phase 1 aggregates unchanged: `ExposureRecord`, `ExposureScoreSnapshot`, `AmplifierWeightConfiguration`.

---

## 6. Domain Services

| Service | Phase |
|---|---|
| `ThreatActorMatchSyncService` | 3 |
| `ThreatIntelligenceQueryService` | 3 |
| `ExposureScopeService` | 4 |
| `GreedyMarginalContribution` (`run_greedy_marginal_contribution`) | 4 |
| `ExposureReductionPlanService` | 4 |

---

## 7. Commands

| Command | Auth |
|---|---|
| `ThreatActorTargetingUpdatedCommand` (via subscriber API) | bus / internal |
| `IngestConfirmedExploitationCommand` | analyst+ |
| `GenerateExposureReductionPlanCommand` | `exposure:analyst` |
| `CommitExposureReductionPlanCommand` | `exposure:analyst` |

---

## 8. Queries

| Query | Auth |
|---|---|
| Threat actor targeting cache read | `exposure:viewer`+ |
| `QueryExposureScope` | `exposure:viewer`+ |
| `GetExposureReductionPlan` / `ListExposureReductionPlans` | `exposure:simulation_reader` **or** analyst+ |

---

## 9. APIs

### Exposure
- `POST /api/v1/exposure/internal/events/threat-actor-targeting`
- `POST /api/v1/exposure/admin/threat-intel/poll`
- `POST /api/v1/exposure/admin/threat-intel/bootstrap`
- `GET /api/v1/exposure/threat-intel/targeting`
- `POST /api/v1/exposure/internal/signals/confirmed-exploitation`
- `POST /api/v1/exposure/scope/query`
- Vulnerability ingest extended with `cve_ids` / `asset_classes`

### Remediation Impact
- `POST /api/v1/remediation-impact/plans`
- `POST /api/v1/remediation-impact/plans/{plan_id}/commit`
- `GET /api/v1/remediation-impact/plans/{plan_id}`
- `GET /api/v1/remediation-impact/plans`
- `GET /api/v1/remediation-impact/health`

---

## 10. Event Subscribers

- `ThreatActorTargetingSubscriber.on_threat_actor_asset_class_targeting_updated`
- Domain event publication via structlog publishers (exposure + remediation_impact)
- Produced: `ExposureReductionPlanGenerated`, `ExposureReductionPlanCommitted`
- Consumed (M21): ThreatActorAssetClassTargetingUpdated (REST/internal bus ingress)

---

## 11. Threat Intelligence Integration

| Element | Implementation |
|---|---|
| Port | `IThreatIntelligenceQueryPort` (exposure domain) |
| Adapter | `ThreatIntelligenceM21Adapter` (seedable; production-injectable) |
| Cache | Per-tenant projection; CVE + asset class + technique + IOC maps |
| Primary path | Event → cache update → amplifier attach → pending recompute |
| Fallback | Daily poll scheduler + admin poll endpoint |
| Staleness | `is_stale` when no event/poll success in 48h |
| Failure | Amplifiers retained; poll failure returns `ok=False` |

---

## 12. Exposure Simulation

| Element | Implementation |
|---|---|
| Algorithm | `GreedyMarginalContribution` only |
| Top-K | Default 200 |
| Sampling | Portfolio-weighted 60/30/10 when `sample_size` set or estate > 100k |
| Determinism | Seed = `int(plan_generated_at.timestamp()) % 2**32` |
| Business impact | `projected_delta × factor` on `SimulationResult` (advisory) |
| Human gate | `CommitExposureReductionPlan` required; no auto-remediation |

---

## 13. Database Migrations

| Revision | Maps frozen | Content |
|---|---|---|
| `0082` | 0046 | `threat_actor_match_cache`; `cve_ids_json` / `asset_classes_json` on records |
| `0083` | 0047 | `remediation_impact` schema + `exposure_reduction_plans` |

**Alembic head:** `0083` (single head verified).

---

## 14. Tests Added

- Unit: ThreatActorMatchCache staleness; GreedyMarginalContribution exact/sampled determinism
- Domain: plan commit transitions; empty candidate rejection
- Application: generate/commit/list; RBAC for viewer vs analyst vs simulation_reader
- API: exposure threat-intel + remediation-impact plan flow
- Integration: event path, poll path, M21 unavailable retention, M30 scope adapter contract
- Architecture: no foreign domain imports outside ACL; Phase 5 package absent; Phase 4 present
- Migration: 0081→0082→0083 chain + single head

---

## 15. Test Summary

```
pytest tests/exposure tests/remediation_impact
47 passed
```

(Includes Phase 1 + Phase 2 regression suite.)

---

## 16. Ruff Summary

```
ruff check  → All checks passed
ruff format --check → 150 files already formatted
```

---

## 17. MyPy Summary

```
mypy --strict src/exposure src/remediation_impact \
  src/campaign/domain/ports/i_exposure_scope_query_port.py \
  src/campaign/infrastructure/acl/exposure_scope_m32_adapter.py
Success: no issues found in 123 source files
```

---

## 18. Architectural Observations

1. **Frozen decisions honored** — ExposureRecord identity, DetectionGap as amplifier-only, four-stage pipeline, hybrid M21, GreedyMarginalContribution, M30-owned scope port, CQRS/DDD/Clean Architecture, tenant isolation.
2. **ACL boundaries** — M21 types never enter exposure domain; M30 DTOs owned by campaign; remediation_impact talks to exposure scores only via ACL port.
3. **No Phase 5 leakage** — `exposure_reporting` / `BusinessImpactMapping` aggregate not created; `business_criticality` in scope response is intentionally `None` until Phase 5.
4. **Simulation reader** — Review I06 role enforced for plan reads; generate/commit remain analyst+ per Finalization.
5. **In-memory default** — Composition roots use process-local InMemory stores (M29–M31 pattern); SQLAlchemy models + migrations ready for PG wiring.

---

## 19. Remaining Scope for Phase 5

| Item | Notes |
|---|---|
| `exposure_reporting` BC | Board / remediation / compliance report variants |
| `BusinessImpactMapping` aggregate | Criticality + impact domain; populate scope `business_criticality` |
| Template-driven narrative | Report generation service |
| Security Graph writes | Cross-BC graph projection |
| ThresholdTarget algorithm | Explicitly deferred post-M32 / Phase 5+ |
| Live M21 / M30 HTTP adapters | Replace in-process seedable adapters in deployment |

**Do not begin Phase 5 until architecture review of Phase 3 + Phase 4.**  
**Do not commit. Do not push.**
