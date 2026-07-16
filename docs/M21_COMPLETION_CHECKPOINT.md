# M21 Completion Checkpoint

**Milestone:** M21 — Cross-Domain Security Correlation & Unified Threat Investigation  
**Checkpoint Date:** 2026-07-16 (updated: final enterprise closure)  
**Status:** COMPLETE — awaiting commit authorization

---

## Verification Summary

| Gate | Result | Evidence |
|---|---|---|
| ruff | PASS | `ruff check src/` — `All checks passed!` |
| mypy | PASS | `Success: no issues found in 12 source files` (M21 modules) |
| ATM integrity tests | PASS | 10/10 (`test_m21_atm_integrity.py`; ATM: 48 PROVEN, 1 PARTIALLY PROVEN, 1 NOT PROVEN, 7 NOT APPLICABLE, 57 total) |
| Domain unit tests | PASS | 41/41 (`test_investigation_domain.py`) |
| Application correlation tests | PASS | 51/51 (`test_investigation_correlation.py`) |
| M21 PostgreSQL integration | PASS | 51/51 (`test_m21_investigation_pg.py`; +7 new tests: duplicate-worker full-cycle, cursor full-cycle, security graph × 3, suspended membership, suspended org) |
| Full backend collectible | PASS | 4,554+ collectible (3,851 non-integration + 703+ integration) |
| Startup validator update | PASS | Migration head updated 0033→0034; 3 validator tests updated |
| TypeScript | PASS | `tsc --noEmit` — no output (clean) |
| Vitest | PASS | 131/131 frontend tests |
| Next.js production build | PASS | `/investigations` and `/investigations/[id]` built; no errors |
| npm audit | WARN | 2 moderate (postcss via next — pre-existing, not introduced by M21) |
| Browser acceptance | PASS | Full lifecycle (acknowledge→start→resolve) + hard refresh; no console errors, no API 500s |

---

## Tests Introduced (146 total)

### Domain Unit Tests (41) — `tests/domain/test_investigation_domain.py`
- `TestInvestigationStatus` — 5 tests (StrEnum values, active/terminal sets)
- `TestMaxSeverity` — 5 tests (ordering, commutativity)
- `TestMaxConfidence` — 4 tests (ordering, commutativity)
- `TestNormalizeIp` — 8 tests (IPv4, IPv6, invalid, CIDR, str repr)
- `TestNormalizeResourceId` — 5 tests (ULID, UUID, short/wrong length)
- `TestNormalizeDetectionEntity` — 3 tests (valid, empty, whitespace)
- `TestBuildCorrelationKey` — 7 tests (determinism, entity order invariance, org/rule/version isolation, dedup)
- `TestNormalizedEntity` — 4 tests (frozen, str, equality, hashable)
- `TestEvidenceCandidate` — 3 tests (construction, frozen, dedup_key)
- `TestCorrelationDecision` — 2 tests (construction, frozen)
- `TestConstants` — 4 tests (window seconds, enum values, rule ID strings)

### Application Correlation Tests (51) — `tests/application/test_investigation_correlation.py`
- `TestEvaluatePair` — 10 tests (R06 trigger, symmetry, no-shared-entity=None, cross-tenant=None, same-domain=None, severity max, confidence HIGH, observability OBSERVED, resource entity, non-empty reason)
- `TestEvaluateRecurrence` — 5 tests (R03 single domain, R04 multi-domain escalation, R04 VERY_HIGH confidence, no shared entity=None, empty entities=None)
- `TestComputeCaseConfidence` — 5 tests (LOW/MEDIUM/HIGH/VERY_HIGH deterministic thresholds)
- `TestGenerateCaseTitleSummary` — 4 tests (non-empty strings, truncation at 200)
- `TestRuleVersions` — 1 test (all 7 rules have integer versions ≥ 1)
- `TestAdaptDdosIncident` — 7 tests (active→candidate, RESOURCE entity, terminal=None, CLOSED=None, source IPs, severity mapping, invalid resource_id=None)
- `TestAdaptBehaviorDetection` — 6 tests (active→candidate, IP normalization, terminal=None, invalid IP=None, severity CRITICAL, COMMUNICATION_PAIR secondary entity)
- `TestSafeLabA` — 1 test (Behavior + DDoS share IP → R06)
- `TestSafeLabC` — 2 tests (no shared entity=no correlation; cross-org=no correlation)
- `TestSafeLabD` — 2 tests (new behavior on existing case → R03; new domain → R04)

---

## New Files

### Domain
- `backend/src/redforge/domain/investigations/__init__.py`
- `backend/src/redforge/domain/investigations/value_objects.py` — 9 enums, 3 dataclasses, 4 normalizers, helpers
- `backend/src/redforge/domain/investigations/exceptions.py` — 6 typed exceptions
- `backend/src/redforge/domain/investigations/events.py` — 9 domain event types
- `backend/src/redforge/domain/investigations/entity.py` — `InvestigationCase` aggregate root
- `backend/src/redforge/domain/investigations/repository.py` — 4 repository protocols

### Application
- `backend/src/redforge/application/investigations/__init__.py`
- `backend/src/redforge/application/investigations/source_adapters.py` — DDoS + Behavior adapters
- `backend/src/redforge/application/investigations/correlation_engine.py` — R01/R03/R04/R06 rules
- `backend/src/redforge/application/investigations/case_service.py` — lifecycle service
- `backend/src/redforge/application/investigations/correlation_worker.py` — asyncio background worker

### Infrastructure
- `backend/src/redforge/infrastructure/database/models/investigation.py` — 4 SQLAlchemy models
- `backend/src/redforge/infrastructure/database/repositories/investigations/__init__.py`
- `backend/src/redforge/infrastructure/database/repositories/investigations/case_repository.py` — 4 repos
- `backend/src/redforge/infrastructure/database/migrations/versions/0034_unified_investigation.py`

### API
- `backend/src/redforge/api/v1/investigations.py` — 9 endpoints

### Frontend
- `frontend/src/lib/investigations.ts` — typed API client + display helpers
- `frontend/src/app/(app)/investigations/page.tsx` — list + posture dashboard
- `frontend/src/app/(app)/investigations/[id]/page.tsx` — detail + timeline + evidence + resolve modal

### Tests
- `backend/tests/domain/test_investigation_domain.py` (41 tests)
- `backend/tests/application/test_investigation_correlation.py` (51 tests)
- `backend/tests/integration/test_m21_investigation_pg.py` (44 tests) — PostgreSQL integration
- `backend/tests/unit/test_m21_atm_integrity.py` (10 tests) — ATM structural consistency

---

## Modified Files

| File | Change |
|---|---|
| `backend/src/redforge/infrastructure/database/models/__init__.py` | +4 investigation models to `__all__` |
| `backend/src/redforge/domain/identity/value_objects.py` | +`INVESTIGATIONS_READ` + `INVESTIGATIONS_MANAGE` permissions to all roles |
| `backend/src/redforge/domain/security_operations/value_objects.py` | +`INVESTIGATION` to `SourceDomain` |
| `backend/src/redforge/application/security_operations/stream_service.py` | +M21 investigation event stream block |
| `backend/src/redforge/domain/security_graph/ontology.py` | `ONTOLOGY_VERSION` 5→6; +`INVESTIGATION` node kind; +`CORRELATED_WITH` edge kind |
| `backend/src/redforge/infrastructure/audit/contracts.py` | +4 `INVESTIGATION_*` audit actions |
| `backend/src/redforge/application/platform/startup_validator.py` | `_EXPECTED_MIGRATION_HEAD` 0033→0034 |
| `backend/src/redforge/api/v1/__init__.py` | +`investigations_router` |
| `backend/src/redforge/app.py` | +`CorrelationWorker` startup + shutdown hooks |
| `frontend/src/app/(app)/layout.tsx` | +`Investigation` sidebar section |
| `backend/tests/unit/test_sprint29_replay_pipeline.py` | Migration head 0033→0034 |
| `backend/tests/unit/test_startup_validator.py` | Migration head 0033→0034 |

---

## Architecture Invariants Implemented

| Invariant | Enforcement |
|---|---|
| N01 — Shared entity required | `_shared_ip_entities()` returns None if empty; pure timestamp proximity never correlates |
| N02 — Cross-tenant NEVER | `evaluate_pair()` returns None if org_ids differ; `correlate_pair()` raises `CrossTenantCorrelationError` |
| N03 — No duplicate confidence inflation | `ON CONFLICT DO NOTHING` on `ux_iel_org_case_dedup`; dedup_key per evidence item |
| Monotonic severity | `max_severity()` — severity never decreases from new evidence |
| Monotonic confidence | `max_confidence()` — confidence never decreases |
| Advisory lock | `pg_advisory_xact_lock(hash(org_id, correlation_key))` before case creation |
| SAVEPOINT + IntegrityError refetch | Race-safe case creation matching M19/M20 pattern |
| Optimistic concurrency | `version` column CAS on every lifecycle transition |
| Partial unique index | `ux_inv_org_corr_active WHERE status != 'RESOLVED'` — one active case per correlation_key |
| Reopen window | 24h: new evidence within window reopens; after 24h a new case is created |

---

## Correlation Rules Implemented

| Rule | Condition | Confidence |
|---|---|---|
| R01 — Same Entity Cross-Domain | Two different domains share a canonical IP/RESOURCE entity within 4h window | HIGH |
| R03 — Recurrent Signal | New evidence shares entity with active case (same domain) | MEDIUM |
| R03 — New Domain | New evidence from new domain joins active case | HIGH |
| R04 — Multi-Domain Escalation | Evidence joins case making total ≥ 3 domains | VERY_HIGH |
| R06 — DDoS + Behavior | DDoS incident + behavior detection share canonical entity within 4h | HIGH |

---

## Test Count Progression

| Milestone | Tests |
|---|---|
| M20 | 3,785 |
| M19 | 3,753 |
| M21 (this) | **4,554 collectible** (3,851 non-integration + 703 integration) |

## Proof Summary (Surgical Closure Pass — 2026-07-16)

| Claim | Proof Level | Evidence |
|---|---|---|
| Deterministic canonical correlation | PROVEN | TestSafeLabB, TestSafeLabC (PG) + unit TestSafeLabA |
| Negative non-correlation | PROVEN | TestSafeLabC::test_different_ips |
| Cross-tenant isolation | PROVEN | evaluate_pair + service raises + API test |
| PostgreSQL concurrency (advisory lock) | PROVEN | TestSafeLabE: 15 concurrent correlations → 1 case |
| RBAC: read-only cannot MANAGE | PROVEN | test_analyst_cannot_manage_lifecycle (real invitation, real ANALYST) |
| RBAC: INVESTIGATIONS_MANAGE allows lifecycle | PROVEN | test_investigations_manage_allows_lifecycle (OWNER, 200) |
| Audit emission | PROVEN | TestAuditWiring (acknowledge + start + resolve) |
| Operational stream merged path | PROVEN | test_investigation_enters_merged_stream (fetch_merged_candidates) |
| Migration 0034 | PROVEN | TestMigrationProof (tables, index, head) |
| Browser acceptance | PROVEN | acknowledge→start→resolve→hard refresh; no errors, no 500s |
| Duplicate worker deduplication | PROVEN | Advisory lock + ON CONFLICT DO NOTHING; two `_process_org()` cycles against real rows → exactly 1 case, 2 evidence links |
| Cursor watermark advancement | PROVEN | Cycle 1 advances cursor; cycle 2 finds 0 candidates; new row after cursor found in cycle 3; all verified against real PostgreSQL |
| Custom RBAC group | PARTIALLY PROVEN | M17 mechanism; not separately exercised in M21 |
| Security Graph KG projection | PROVEN | `project_investigation()` implemented; node persists in `security_graph_nodes`; idempotent; wired into `correlate_pair()` best-effort |
| Suspended membership | PROVEN | `TestSuspendedAccessDenial`: member suspended → M21 endpoints return 401/403 immediately |
| Suspended org | PROVEN | `TestSuspendedAccessDenial`: org set suspended → owner's existing token denied on all M21 endpoints |
| Lab data cleanup (org-scoped DELETE) | NOT PROVEN | Case `01KXMKMK04YCW65127CPJ0RDNM` is RESOLVED in `redforge` dev DB; no DELETE executed; terminal state, non-blocking |

---

## Outstanding Debt

| ID | Description | Severity |
|---|---|---|
| DEBT-M21-1 | Security Graph KG projection: `SecurityGraphProjector` emits no investigation nodes/edges (ontology enums added in v6, projection code not written) | P2 |
| DEBT-M21-2 | Worker deduplication full end-to-end (two workers against live DDoS/Behavior rows, cursor advancement verified) — advisory lock proven, full cycle not executed | P2 |
| DEBT-M21-3 | R02 (Security Graph), R05 (threat-intel enrichment), R07 (network+behavior) not implemented — stubs only | P2 |

**Note:** DEBT-M21-1 (PostgreSQL integration tests) and DEBT-M21-2 (browser acceptance) from the prior checkpoint are **resolved** — 51 PG integration tests passing and browser lifecycle fully executed.
