# M32 Phase 1 + Phase 2 Implementation Report

**Date:** 2026-07-21  
**Milestone:** M32 — Continuous Threat Exposure Management (CTEM)  
**Phases Delivered:** Phase 1 (Exposure Foundation) + Phase 2 (Multi-Source Amplification)  
**Status:** COMPLETE — Quality gates passed  
**Commit / Push:** NOT performed (awaiting architecture review)

---

## 1. Executive Summary

M32 Phases 1 and 2 deliver the `exposure` bounded context exactly as frozen in `M32_ARCHITECTURE_FINALIZATION.md`:

- **Phase 1:** `ExposureRecord` / `ExposureScoreSnapshot` / `AmplifierWeightConfiguration`, M27 vulnerability ingestion, four-stage score pipeline (Ingestion → Debounce → Dispatch → Computation), weight governance, suppress API, `TenantExposureProfile` read model, Alembic **`0081`**.
- **Phase 2:** `CloudSecurity` signal domain, M26/M28/M31 amplifier ingestion, ACL ports (`ICloudExposureQueryPort`, `IDetectionCoverageQueryPort`, `IAIRiskQueryPort`), DetectionGap as amplifier-only (never a SignalDomain).

Frozen decisions honored as constraints (not implemented ahead of phase): ExposureRecord identity, Signal Domains, DetectionGap = RiskAmplifier only, four-stage pipeline. **Hybrid M21**, **ExposureScopePort**, **Greedy Marginal Contribution**, and **BusinessImpactMapping** remain Phase 3–5 respectively.

---

## 2. Features Implemented

| Feature | Phase | Status |
|---------|-------|--------|
| ExposureRecord identity `(TenantId × AssetRefId × SignalDomain × SignalSourceRefId)` | 1 | Done |
| RiskAmplifier entities + closed type taxonomy | 1 | Done |
| ExposureScoreSnapshot (append-only) | 1 | Done |
| AmplifierWeightConfiguration (versioned, audited) | 1 | Done |
| M27 ingest / resolve / KEV amplifier | 1 | Done |
| Four-stage score pipeline + job idempotency | 1 | Done |
| Score formula `base × Π(1+weight)` clamped `[0,10]` | 1 | Done |
| SuppressExposureRecord (`exposure:analyst`) | 1 | Done |
| ConfigureAmplifierWeights (`exposure:admin`) | 1 | Done |
| TenantExposureProfile read model | 1 | Done |
| Idempotent `processed_exposure_signals` | 1 | Done |
| CloudSecurity standalone records | 2 | Done |
| InternetExposure / CloudMisconfiguration amplifiers | 2 | Done |
| DetectionGap amplifier (+ technique index) | 2 | Done |
| AISystemRisk amplifier | 2 | Done |
| REST APIs + RBAC | 1–2 | Done |
| Migration `0081` (maps frozen 0041–0045 onto live chain after 0080) | 1 | Done |

---

## 3. Files Created

### Package root
- `backend/src/exposure/` (+ `py.typed`)

### Domain
- Aggregates: `exposure_record.py`, `exposure_score_snapshot.py`, `amplifier_weight_configuration.py`
- Entity: `risk_amplifier.py`
- Events: `base.py`, `exposure_events.py`
- Exceptions, enums, identifiers, VOs
- Repositories (interfaces): record / snapshot / weights
- Ports: vulnerability, cloud, detection, AI risk
- Services: `exposure_score_formula.py`, `job_idempotency.py`

### Application
- Commands, DTOs, mappers, `_auth`, exceptions
- `ExposureSignalIngestionService` (P1+P2)
- `ExposureApplicationService` (queries + suppress + weights)
- `RecomputationDebouncerService`, `RecomputationDispatcherService`, `ExposureScoreComputationWorker`
- Pipeline store ports (`pending`, `processed_signals`, `profiles`)

### Infrastructure
- `ExposureContainer`
- In-memory UoW + repos + pipeline stores
- SQLAlchemy models (`exposure` schema)
- Seedable ACL stubs
- Structlog event publisher

### API
- `/api/v1/exposure/*` routes, schemas, dependencies

### Migrations / tests / docs
- `0081_exposure_phase1_foundation.py`
- `backend/tests/exposure/**`
- `docs/architecture/m32/*` (architecture + this report)

---

## 4. Files Modified

| File | Change |
|------|--------|
| `backend/src/redforge/api/v1/__init__.py` | Register `exposure_router` |
| `backend/pyproject.toml` | `exposure` first-party, `py.typed`, ruff per-file ignores |

---

## 5. Aggregates Added

1. **ExposureRecord** — signal-scoped root; amplifiers; lifecycle Active/Resolved/Suppressed  
2. **ExposureScoreSnapshot** — append-only immutable score history  
3. **AmplifierWeightConfiguration** — per-tenant append-only version history  

---

## 6. Domain Services

| Service | Role |
|---------|------|
| `compute_record_score` / asset / tenant helpers | Frozen score formula |
| `derive_job_id` / `dispatch_window_bucket` | Job idempotency |
| `ExposureSignalIngestionService` | Ingestion stage (+ P2 sources) |
| `RecomputationDebouncerService` | Debounce stage |
| `RecomputationDispatcherService` | Dispatch stage + back-pressure |
| `ExposureScoreComputationWorker` | Computation stage |

---

## 7. Commands

**Phase 1:** `IngestVulnerabilitySignal`, `ResolveVulnerabilitySignal`, `VulnerabilityKevStatusChanged`, `SuppressExposureRecord`, `ConfigureAmplifierWeights`, `FlushPendingRecomputations`  

**Phase 2:** `IngestCloudSecuritySignal`, `RemediateCloudSecuritySignal`, `IngestDetectionGapSignal`, `IngestAISystemRiskSignal`

---

## 8. Queries

- `GetExposureRecord`
- `ListExposureRecordsByAsset` (+ status filter)
- `GetLatestExposureScore` (snapshot / never sync recompute)
- `GetAmplifierWeightConfiguration`
- `GetTenantExposureProfile`

---

## 9. APIs

Prefix: `/api/v1/exposure`

| Method | Path | Auth |
|--------|------|------|
| GET | `/records/{id}` | viewer+ |
| GET | `/assets/{asset}/records` | viewer+ |
| GET | `/assets/{asset}/score` | viewer+ |
| GET/PUT | `/weights` | viewer / admin |
| POST | `/records/{id}/suppress` | analyst+ |
| GET | `/profile` | viewer+ |
| POST | `/internal/signals/*` | internal ingest (P1+P2) |
| POST | `/admin/pending/flush` | admin |
| POST | `/admin/pipeline/run` | admin (zero-debounce ops) |
| GET | `/health` | open |

Headers: `X-Tenant-Id`, `X-Exposure-Roles`.

---

## 10. Database Migrations

| Revision | Purpose |
|----------|---------|
| **0081** | Exposure schema + all Phase 1 tables (frozen plan 0041–0045 mapped to live head after **0080**) |

Phase 2: **no additional migration** (signal domains / amplifier types are data-level).

Single Alembic head: **`0081`**.

---

## 11. Tests Added

| Area | Files |
|------|-------|
| Domain | `test_exposure_record.py`, `test_score_formula.py` |
| Application P1 | `test_phase1_pipeline.py` |
| Application P2 | `test_phase2_multisource.py` |
| Pipeline | `test_thundering_herd.py` (10K marks → 1 pending → 1 compute) |
| API / auth | `test_exposure_api.py` |
| Migration | `test_migration_chain.py` |
| Architecture | `test_architecture_invariants.py` |

---

## 12. Test Summary

| Metric | Count |
|--------|------:|
| Total | **27** |
| Passed | **27** |
| Failed | **0** |
| Skipped | **0** |

---

## 13. Ruff Summary

```
ruff check src/exposure tests/exposure  → All checks passed
ruff format --check src/exposure tests/exposure → 81 files already formatted
```

---

## 14. MyPy Summary

```
mypy --strict src/exposure tests/exposure
Success: no issues found in 81 source files
```

---

## 15. Architectural Observations

1. **Identity / domains** — Unique `(tenant, asset, signal_domain, signal_source_ref)`; only `VulnerabilityManagement` + `CloudSecurity`.
2. **Detection gaps** — Amplifiers only; technique index supports fan-out without per-record M28 calls.
3. **Pipeline** — Debounce upsert collapses thundering herd; job_id SHA-256 window prevents duplicate snapshots.
4. **ACL** — Foreign types stay behind ports; domain does not import M26/M27/M28/M31 packages.
5. **DI** — In-memory UoW default (platform pattern); ACL stubs intentional until live adapters injected.
6. **Migration numbering** — Frozen doc listed 0041–0045; live chain uses **0081** after M31 `0080` (documented mapping).
7. **Phase boundary** — No `remediation_impact`, `exposure_reporting`, ThreatActorMatchCache, ExposureScopeService, or GreedyMarginalContribution.

---

## 16. Remaining Scope for Phase 3+

| Phase | Scope (do not implement now) |
|-------|------------------------------|
| **3** | Hybrid M21, `ThreatActorMatchCache`, `IThreatIntelligenceQueryPort`, ThreatActorMatch amplifier |
| **4** | `remediation_impact`, GreedyMarginalContribution, ExposureScopeService / M30 port |
| **5** | `exposure_reporting`, BusinessImpactMapping, Security Graph writes, template narratives |

---

## STOP

Phase 1 + Phase 2 implementation is complete.

**Do not commit. Do not push. Do not begin Phase 3.**  
Await architecture review.
