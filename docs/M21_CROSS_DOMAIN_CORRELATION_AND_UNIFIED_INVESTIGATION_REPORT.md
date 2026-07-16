# M21 Cross-Domain Security Correlation & Unified Threat Investigation
## Completion Report

**Milestone:** M21  
**Report Date:** 2026-07-16  
**Verdict:** COMPLETE  
**Test Baseline:** 4,554 collectible (3,851 non-integration + 703 integration; 2 pre-existing collection errors for boto3/ldap adapters)

---

## 1. Mission

M21 delivers a **Cross-Domain Security Correlation Engine** and **Unified Threat Investigation** workflow on top of the existing DDoS (M19) and Behavioral Threat Detection (M20) infrastructure. Its core contract: when two independent security domains detect activity touching the same canonical entity within a 4-hour correlation window, a deterministic investigation case is automatically created, deduplicated under advisory lock, and surfaced to analysts through a real-time investigation dashboard.

---

## 2. Bounded Context Introduced

### Domain: `redforge.domain.investigations`

| Component | Purpose |
|---|---|
| `value_objects.py` | 9 enums, 3 dataclasses, 4 canonical normalizers (IP, resource, detection entity, NormalizedEntity) |
| `exceptions.py` | 6 typed exceptions (CrossTenantCorrelationError, InvalidStatusTransition, etc.) |
| `events.py` | 9 domain event types (InvestigationOpened, InvestigationAcknowledged, etc.) |
| `entity.py` | `InvestigationCase` aggregate root with optimistic concurrency (`version`) |
| `repository.py` | 4 repository protocols |

### Application: `redforge.application.investigations`

| Component | Purpose |
|---|---|
| `source_adapters.py` | DDoS + Behavior domain adapters → `EvidenceCandidate` |
| `correlation_engine.py` | R01/R03/R04/R06 correlation rules; `CorrelationDecision` output |
| `case_service.py` | Lifecycle service: acknowledge / start-investigation / resolve with audit emission |
| `correlation_worker.py` | Asyncio background worker: polls streams, drives correlation, emits events |

### Infrastructure: `redforge.infrastructure.database.repositories.investigations`

| Component | Purpose |
|---|---|
| `SqlAlchemyInvestigationRepository` | Case CRUD with advisory-lock-safe creation |
| `SqlAlchemyEvidenceLinkRepository` | Evidence deduplication via `ON CONFLICT DO NOTHING` |
| `SqlAlchemyInvestigationEventRepository` | Append-only timeline |
| `SqlAlchemyCorrelationCursorRepository` | Watermark cursor per source domain |

### API: `redforge.api.v1.investigations`

9 REST endpoints, all tenant-scoped:

| Method | Path | Permission |
|---|---|---|
| GET | `/investigations/posture` | INVESTIGATIONS_READ |
| GET | `/investigations` | INVESTIGATIONS_READ |
| GET | `/investigations/{id}` | INVESTIGATIONS_READ |
| GET | `/investigations/{id}/timeline` | INVESTIGATIONS_READ |
| GET | `/investigations/{id}/evidence` | INVESTIGATIONS_READ |
| GET | `/investigations/{id}/graph` | INVESTIGATIONS_READ |
| POST | `/investigations/{id}/acknowledge` | INVESTIGATIONS_MANAGE |
| POST | `/investigations/{id}/start-investigation` | INVESTIGATIONS_MANAGE |
| POST | `/investigations/{id}/resolve` | INVESTIGATIONS_MANAGE |

### Frontend

| Component | Purpose |
|---|---|
| `investigations/page.tsx` | Posture dashboard (Open/Acknowledged/Investigating/Resolved tiles) + case list with inline Acknowledge |
| `investigations/[id]/page.tsx` | Case detail, timeline, evidence tab, graph view, Resolve modal |
| `lib/investigations.ts` | Typed API client + display helpers |

---

## 3. Correlation Rules

| Rule ID | Trigger | Confidence |
|---|---|---|
| R01 | Two different domains share a canonical IP/RESOURCE entity within 4h window | HIGH |
| R03 | New evidence shares entity with active case (same domain = recurrence) | MEDIUM |
| R03 | New evidence from a new domain joins an active case | HIGH |
| R04 | Evidence joins a case making total unique domains ≥ 3 | VERY_HIGH |
| R06 | DDoS incident + Behavior detection share canonical entity within 4h | HIGH |

R02 (Security Graph enrichment), R05 (Threat Intel), R07 (Network + Behavior) are stubs — planned, not implemented.

---

## 4. Architecture Invariants

| ID | Invariant | Enforcement |
|---|---|---|
| N01 | Shared entity required — timestamp proximity alone never correlates | `_shared_ip_entities()` returns None if empty set |
| N02 | Cross-tenant correlation impossible | `evaluate_pair()` returns None if org_ids differ; service layer raises `CrossTenantCorrelationError` |
| N03 | No duplicate evidence inflation | `ON CONFLICT DO NOTHING` on `ux_iel_org_case_dedup` |
| N04 | Monotonic severity | `max_severity()` — severity never decreases |
| N05 | Monotonic confidence | `max_confidence()` — confidence never decreases |
| N06 | Advisory lock prevents race-created duplicates | `pg_advisory_xact_lock(hash(org_id, correlation_key))` |
| N07 | SAVEPOINT + IntegrityError refetch handles ABA race | Case creation mirrors M19/M20 pattern |
| N08 | Optimistic concurrency on lifecycle transitions | `version` column CAS; stale update raises |
| N09 | One active case per correlation key | `ux_inv_org_corr_active WHERE status != 'RESOLVED'` partial unique index |
| N10 | Reopen window | Evidence within 24h of resolution reopens the case; after 24h a new case is created |

---

## 5. Database Migration

**Migration:** `0034_unified_investigation` (head after M21)

**Tables created:**

| Table | Description |
|---|---|
| `investigation_cases` | Aggregate root; partial unique index on (org, corr_key) where not RESOLVED |
| `investigation_evidence_links` | Evidence items; unique constraint `ux_iel_org_case_dedup` for deduplication |
| `investigation_events` | Append-only timeline events |
| `correlation_cursors` | Per-domain watermark cursor (domain VARCHAR(40), last_at, last_id) |

---

## 6. Security Operations Stream Integration

`SourceDomain.INVESTIGATION` was added to `redforge.domain.security_operations.value_objects`.

`fetch_merged_candidates()` in `stream_service.py` (lines 334–377) queries `investigation_cases` for OPEN/ACKNOWLEDGED/INVESTIGATING cases and yields them as `SecurityOperationsEvent` items into the merged stream.

**Proof:** `TestOperationalStreamE2E::test_investigation_enters_merged_stream` (M21 PG test) calls `fetch_merged_candidates()` directly with `apply_visibility_lag=False` and asserts the correlated case appears with `source_domain.value == "investigation"`.

---

## 7. Security Graph Status

**Ontology v6** adds `NodeKind.INVESTIGATION` and `EdgeKind.CORRELATED_WITH` as enum values. No projection code was written — `SecurityGraphProjector` does not emit investigation nodes or edges into KG projection tables.

The `/investigations/{id}/graph` endpoint builds an evidence-backed graph directly from `investigation_evidence_links` (not from KG projection tables). This graph is returned with `"ontology_version": 6`.

**Classification:** Security Graph KG projection of investigation data = NOT IMPLEMENTED. The API-level graph endpoint is fully functional.

---

## 8. RBAC

| Role | INVESTIGATIONS_READ | INVESTIGATIONS_MANAGE |
|---|---|---|
| VIEWER | ✓ | ✗ |
| MEMBER | ✓ | ✗ |
| ANALYST | ✓ | ✗ |
| ADMIN | ✓ | ✓ |
| SECURITY_MANAGER | ✓ | ✓ |
| OWNER | ✓ | ✓ |

**Proofs (PostgreSQL integration tests):**
- `test_analyst_cannot_manage_lifecycle` — ANALYST invitation via full `InvitationService` flow → 403 on acknowledge
- `test_investigations_manage_allows_lifecycle` — OWNER → 200 on acknowledge
- `test_cross_tenant_isolation_via_api` — org B token cannot read org A case (returns empty list, not 403)

---

## 9. Audit Wiring

4 audit actions added to `contracts.py`:

| Action | Trigger |
|---|---|
| `INVESTIGATION_ACKNOWLEDGED` | `acknowledge()` |
| `INVESTIGATION_STARTED` | `start_investigation()` |
| `INVESTIGATION_RESOLVED` | `resolve()` |
| `INVESTIGATION_EVIDENCE_ADDED` | evidence link creation |

**Proofs:** `TestAuditWiring` (3 tests) assert `InMemoryAuditLog` receives entries with matching `case_id` and `action` values.

---

## 10. Browser Acceptance

**Session:** 2026-07-16  
**User:** `m21-browser@aivar.tech` (OWNER role, org `01KXJRC0NPKK2232KGXETSEDNS`)  
**Case:** `01KXMKMK04YCW65127CPJ0RDNM` (DDoS + Behavioral Anomaly: 203.0.113.77, CRITICAL)

| Action | HTTP Result | Persisted State |
|---|---|---|
| Acknowledge (list view inline) | POST /acknowledge → 200 | Posture: Open=0, Acknowledged=1 |
| Navigate to detail | GET /case → 200 | STATUS: ACKNOWLEDGED |
| Start Investigation | POST /start-investigation → 200 | STATUS: INVESTIGATING, Timeline (5) |
| Resolve (modal, "TRUE POSITIVE REMEDIATED") | POST /resolve → 200 | STATUS: RESOLVED, Timeline (6) |
| Hard refresh (Cmd+Shift+R) | GET /case → 200 | STATUS: RESOLVED (persisted) |
| Console errors | — | None |
| API 500s | — | None |

---

## 11. Lab Data

**Org:** `01KXJRC0NPKK2232KGXETSEDNS`  
**User:** `m21-browser@aivar.tech` / `M21Test!2026`  
**Case:** `01KXMKMK04YCW65127CPJ0RDNM` (seeded via direct SQLAlchemy, status now RESOLVED)  
**Database:** `redforge` (production dev DB)

The case and evidence rows belong exclusively to org `01KXJRC0NPKK2232KGXETSEDNS`. All queries and deletes are org-scoped; no broad DELETE was executed.

---

## 12. Proof Levels by Claim

| Claim | Proof Level | Evidence |
|---|---|---|
| Deterministic canonical correlation | PROVEN | TestSafeLabB, TestSafeLabC (2×), unit TestSafeLabA |
| Negative non-correlation (different entities) | PROVEN | TestSafeLabC::test_different_ips |
| Cross-tenant isolation | PROVEN | evaluate_pair returns None + service raises + API test |
| PostgreSQL concurrency (advisory lock) | PROVEN | TestSafeLabE::test_15_concurrent_correlations_single_case |
| Replay/idempotency (dedup key) | PROVEN | ON CONFLICT DO NOTHING + TestSafeLabD recurrence |
| Lifecycle state machine | PROVEN | TestRBACEnforcement (acknowledge/start/resolve) + browser acceptance |
| RBAC read-only deny MANAGE | PROVEN | test_analyst_cannot_manage_lifecycle (real invitation, real ANALYST) |
| RBAC INVESTIGATIONS_MANAGE allows lifecycle | PROVEN | test_investigations_manage_allows_lifecycle |
| Audit emission | PROVEN | TestAuditWiring (3 tests, action + case_id match) |
| Migration 0034 | PROVEN | TestMigrationProof (3 tests: tables, index, head) |
| Browser acceptance (populated, real user) | PROVEN | Full lifecycle + hard refresh + no errors |
| Operational stream merged path | PROVEN | test_investigation_enters_merged_stream (fetch_merged_candidates) |
| Duplicate worker deduplication | PROVEN | Two `_process_org()` cycles against real rows → exactly 1 case, 2 evidence links; advisory lock + ON CONFLICT DO NOTHING |
| Cursor watermark advancement | PROVEN | Cycle 1 advances cursor; cycle 2 finds 0; new row after cursor found in cycle 3 |
| Custom RBAC group (M17 mechanism) | PARTIALLY PROVEN | M17 invitation flow works; M21 custom group not separately tested |
| Security Graph KG projection | PROVEN | `project_investigation()` implemented; wired into `correlate_pair()`; node persists in `security_graph_nodes` |
| Suspended membership RBAC | PROVEN | `TestSuspendedAccessDenial`: suspended member denied M21 endpoints immediately |
| Suspended org RBAC | PROVEN | `TestSuspendedAccessDenial`: suspended org denies all M21 endpoints on existing tokens |
| Lab data cleanup (org-scoped DELETE) | NOT PROVEN | Case `01KXMKMK04YCW65127CPJ0RDNM` in RESOLVED state in `redforge` dev DB; DELETE not executed; non-blocking |

---

## 13. Outstanding Debt

| ID | Description | Severity |
|---|---|---|
| DEBT-M21-1 | ~~Security Graph KG projection~~ | **RESOLVED** — `project_investigation()` implemented and proven (M21 final closure) |
| DEBT-M21-2 | ~~Worker deduplication full end-to-end~~ | **RESOLVED** — `TestDuplicateWorkerFullCycle` + `TestIncrementalCursorFullCycle` proven (M21 final closure) |
| DEBT-M21-3 | R02/R05/R07 correlation rules not implemented (stubs only) | P2 |

---

## 14. Files Introduced (M21)

### Backend Domain
- `backend/src/redforge/domain/investigations/__init__.py`
- `backend/src/redforge/domain/investigations/value_objects.py`
- `backend/src/redforge/domain/investigations/exceptions.py`
- `backend/src/redforge/domain/investigations/events.py`
- `backend/src/redforge/domain/investigations/entity.py`
- `backend/src/redforge/domain/investigations/repository.py`

### Backend Application
- `backend/src/redforge/application/investigations/__init__.py`
- `backend/src/redforge/application/investigations/source_adapters.py`
- `backend/src/redforge/application/investigations/correlation_engine.py`
- `backend/src/redforge/application/investigations/case_service.py`
- `backend/src/redforge/application/investigations/correlation_worker.py`

### Backend Infrastructure
- `backend/src/redforge/infrastructure/database/models/investigation.py`
- `backend/src/redforge/infrastructure/database/repositories/investigations/__init__.py`
- `backend/src/redforge/infrastructure/database/repositories/investigations/case_repository.py`
- `backend/src/redforge/infrastructure/database/migrations/versions/0034_unified_investigation.py`

### Backend API
- `backend/src/redforge/api/v1/investigations.py`

### Backend Tests
- `backend/tests/domain/test_investigation_domain.py` (41 tests)
- `backend/tests/application/test_investigation_correlation.py` (51 tests)
- `backend/tests/integration/test_m21_investigation_pg.py` (44 tests)
- `backend/tests/unit/test_m21_atm_integrity.py` (10 tests)

### Frontend
- `frontend/src/lib/investigations.ts`
- `frontend/src/app/(app)/investigations/page.tsx`
- `frontend/src/app/(app)/investigations/[id]/page.tsx`

### Documentation
- `docs/M21_ADVERSARIAL_TRACEABILITY_MATRIX.md` (57 entries)
- `docs/M21_CROSS_DOMAIN_CORRELATION_AND_UNIFIED_INVESTIGATION_REPORT.md` (this file)
