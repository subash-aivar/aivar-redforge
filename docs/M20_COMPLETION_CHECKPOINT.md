# M20 Completion Checkpoint

**Milestone:** M20 — Advanced Network Detection & Response (NDR), UEBA, and Behavioral Threat Detection  
**Checkpoint Date:** 2026-07-15  
**Status:** COMPLETE — awaiting commit authorization

---

## Verification Summary

| Gate | Result | Evidence |
|---|---|---|
| ruff | PASS | `ruff check .` — clean |
| mypy | PASS | `Success: no issues found in 10 source files` |
| Domain unit tests | PASS | 36/36 |
| Backend tests (non-integration) | PASS | 3,762/3,762 (unit 3,098 + domain 184 + api/application 480; no M20-introduced regressions) |
| PostgreSQL integration tests | PASS | 26/26 |
| TypeScript | PASS | `tsc --noEmit` clean |
| Vitest | PASS | 131/131 |
| Production build | PASS | `next build` — clean |
| npm audit | PASS* | 2 pre-existing moderate vulns only (not M20-introduced) |
| Browser acceptance | PASS | All 4 `/behavior/*` routes load with real data (64 detections, 5 entities, 48 network relationships); honest empty states; zero console errors |

*The 2 npm vulnerabilities in `next/postcss` were present before M20 and have no available fix without a breaking upgrade.

---

## Tests Introduced (62 total)

### Domain Unit (36)
- `TestIsRfc1918` — 5 tests
- `TestBaselineComputation` — 4 tests
- `TestFanOutDetection` — 5 tests
- `TestPortScanDetection` — 3 tests
- `TestDestinationDetection` — 3 tests
- `TestOutboundTransfer` — 5 tests
- `TestEastWestDetection` — 3 tests
- `TestUnusualServiceAccess` — 2 tests
- `TestBeaconingAnalysis` — 6 tests

### PostgreSQL Integration (26)
- `TestMigrationProof` — 2 tests
- `TestTenantIsolation` — 3 tests
- `TestRbac` — 4 tests
- `TestConcurrencyProof` — 2 tests
- `TestLabANewDestination` — 1 test (E2E: telemetry → detection cycle → API)
- `TestLabBBeaconing` — 1 test
- `TestLabCFanOut` — 2 tests
- `TestLabDAbnormalTransfer` — 1 test
- `TestDuplicateDetectionPrevention` — 1 test
- `TestWorkerStats` — 1 test
- `TestTraceabilityIntegrity` — 5 tests (consistency checks only: unique IDs, valid statuses, distribution arithmetic, required IDs, summary arithmetic)
- `TestWorkerRuntimeProof` — 2 tests (real cycle + duplicate lock)
- `TestOperationalStreamIntegration` — 1 test (behavior events in merged stream)

---

## Adversarial Traceability

35 PROVEN scenarios, 4 NOT_APPLICABLE, 0 NOT_PROVEN.  
See [M20_ADVERSARIAL_TRACEABILITY_MATRIX.md](M20_ADVERSARIAL_TRACEABILITY_MATRIX.md).

---

## Files Created / Modified

### New Files (backend)
- `backend/src/redforge/domain/behavior/value_objects.py`
- `backend/src/redforge/domain/behavior/detection.py`
- `backend/src/redforge/application/behavior/detection_service.py`
- `backend/src/redforge/application/behavior/detection_worker.py`
- `backend/src/redforge/api/v1/behavior.py`
- `backend/src/redforge/infrastructure/database/models/behavior.py`
- `backend/src/redforge/infrastructure/database/repositories/behavior/detection_repository.py`
- `backend/src/redforge/infrastructure/database/migrations/versions/0033_behavioral_ndr.py`
- `backend/tests/domain/test_behavior_detection.py`
- `backend/tests/integration/test_behavior_m20.py`

### New Files (frontend)
- `frontend/src/app/behavior/page.tsx`
- `frontend/src/app/behavior/detections/page.tsx`
- `frontend/src/app/behavior/detections/[id]/page.tsx`
- `frontend/src/app/behavior/entities/page.tsx`
- `frontend/src/app/behavior/network/page.tsx`

### New Files (docs)
- `docs/M20_ADVANCED_NDR_UEBA_BEHAVIORAL_SECURITY_REPORT.md`
- `docs/M20_ADVERSARIAL_TRACEABILITY_MATRIX.md`
- `docs/M20_COMPLETION_CHECKPOINT.md` (this file)

### Modified Files
- `backend/src/redforge/api/v1/__init__.py` — registered behavior router
- `backend/src/redforge/shared/permissions.py` — added BEHAVIOR_READ, BEHAVIOR_MANAGE
- `backend/src/redforge/domain/behavior/__init__.py` (new package)
- `backend/src/redforge/application/behavior/__init__.py` (new package)
- `backend/src/redforge/infrastructure/database/repositories/behavior/__init__.py` (new package)
- `docs/PROJECT_CONTEXT.md` — added M20
- `backend/src/redforge/application/platform/startup_validator.py` — bumped `_EXPECTED_MIGRATION_HEAD` to "0033" (G1)
- `backend/src/redforge/domain/security_operations/value_objects.py` — added `SourceDomain.BEHAVIOR` (G2a)
- `backend/src/redforge/infrastructure/database/repositories/behavior/detection_repository.py` — added `list_detection_events_since` (G2b)
- `backend/src/redforge/application/security_operations/stream_service.py` — wired M20 "W" source tag into `fetch_merged_candidates` (G2c)
- `backend/src/redforge/application/behavior/detection_worker.py` — fixed `pg_try_advisory_xact_lock` return value check (G4)
- `backend/tests/unit/test_sprint29_replay_pipeline.py` — updated migration head mocks to "0033"
- `backend/tests/unit/test_startup_validator.py` — updated migration head mock to "0033"

---

## Migration

- **Head:** `0033_behavioral_ndr`
- **Tables added:** `behavior_entity_baselines`, `behavior_observations`, `behavior_detections`, `behavior_detection_events`
- **Key constraint:** partial unique index `ux_bd_org_corr_active` on `behavior_detections (organization_id, correlation_key) WHERE status NOT IN ('RESOLVED', 'CLOSED')`

---

## Debt Carried Forward

None. All M20 requirements are either implemented with full test coverage, or explicitly documented as NOT_APPLICABLE due to canonical data constraints.

---

## DO NOT

- DO NOT commit without explicit authorization
- DO NOT push to remote
- DO NOT start M21
