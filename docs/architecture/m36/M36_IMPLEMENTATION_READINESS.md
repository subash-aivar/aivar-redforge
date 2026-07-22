# M36 Implementation Readiness Assessment
## Enterprise AI-Native Autonomous Security Operations

**Date:** 2026-07-22
**Status:** APPROVED FOR IMPLEMENTATION

---

## Architecture Completeness Check

| Document | Status |
|---|---|
| M36_ARCHITECTURE_REVIEW.md | COMPLETE |
| M36_ARCHITECTURE_FINALIZATION.md | COMPLETE — All C1–C10 resolved |
| M36_ADR_001_through_008.md | COMPLETE — 8 ADRs produced |
| M36_RISK_REGISTER.md | COMPLETE — 10 risks disposed |
| M36_IMPLEMENTATION_READINESS.md | COMPLETE (this document) |

---

## Pre-Implementation Checklist

### Repository Baseline

| Check | Status |
|---|---|
| Migration head confirmed: `0130_m35_analytics_projection` | CONFIRMED |
| M35 bounded contexts (`playbook`, `automated_action`, `integration_hub`) complete | CONFIRMED |
| M33 analytics and ML pipeline infrastructure available | CONFIRMED |
| M28 detection context with `DetectionRulePerformanceReported` event available | CONFIRMED |
| M34 `lessons_learned` bounded context with `IncidentLessonsLearned` event available | CONFIRMED |
| M32 exposure context with `ExposureScoreUpdated` event available | CONFIRMED |
| M30 campaign context with `ScenarioTemplate` aggregate available | CONFIRMED |
| EventPublisher protocol available in shared kernel | CONFIRMED |
| Security Graph node/edge extension pattern established (M35 precedent: 0129) | CONFIRMED |
| `ICredentialVaultPort`-style port naming convention established | CONFIRMED |
| `__slots__`, `pop_events()`, `_emit()`, `_assert_tenant()` patterns established | CONFIRMED |

### Architecture Decisions Frozen

| Decision | ADR | Frozen in Finalization |
|---|---|---|
| AI autonomy boundary — domain invariant | ADR-M36-001 | C6 |
| LLM tenant isolation at port level | ADR-M36-002 | C7 |
| Confidence threshold policy per type | ADR-M36-003 | C4 |
| Feedback loop and retraining trigger | ADR-M36-004 | C5 |
| OptimizationModel version lifecycle | ADR-M36-005 | C3 |
| Human-in-the-loop governance gate | ADR-M36-006 | C1 |
| Cross-context proposal via event bus | ADR-M36-007 | C10 |
| EU AI Act conformity architecture | ADR-M36-008 | (Risk R08) |
| SuggestionStatus lifecycle states | (Finalization §1) | C1 |
| SuggestionTargetType closed enum | (Finalization §1) | C2 |
| SuggestionEvidence value object | (Finalization §1) | C4 |
| PostureForecast input snapshot | (Finalization §1) | C8 |
| ThreatHuntCandidate evidence tracing | (Finalization §1) | C9 |

### Bounded Context Readiness

| Bounded Context | Role | Aggregates | Repositories | Commands | Events | Phase |
|---|---|---|---|---|---|---|
| `autonomous_intelligence` | Core | 4 defined | 3 defined | 10 defined | 10 defined | 1 |
| `posture_forecasting` | Supporting | 2 defined | 1 defined | 2 defined | 2 defined | 2 |
| `threat_hunt` | Supporting | 2 defined | 1 defined | 2 defined | 3 defined | 2 |

### Migration Readiness

| Migration Range | Context | Tables | Phase |
|---|---|---|---|
| 0131–0137 | `autonomous_intelligence` | 7 tables | 1 |
| 0138–0142 | `posture_forecasting` | 5 tables | 2 |
| 0143–0147 | `threat_hunt` | 5 tables | 2 |
| 0148–0149 | Security Graph + Analytics | 2 extensions | 4 |

**Terminal head after M36:** `0149` (no migration has `down_revision = "0149"`).

---

## Phase Execution Summary

### Phase 1 — `autonomous_intelligence` Domain Foundation
**Start condition:** M36 architecture approved (this document)
**Deliverables:** `autonomous_intelligence` bounded context: all aggregates (`IntelligenceSuggestion`, `OptimizationModel`, `AutonomousOperationsPolicy`, `SuggestionOutcome`), domain services, ports (`ILLMInferencePort`, `IOptimizationModelRepository`, `IIntelligenceSuggestionRepository`, `ISuggestionOutcomeRepository`), domain events, value objects (`SuggestionEvidence`, `SuggestionTargetRef`, `LLMPrompt`, `TenantScopedDocument`); migrations `0131–0137`
**Test target:** ≥ 90 unit tests (domain + application layer)
**Exit criteria:**
- All `SuggestionStatus` lifecycle transitions tested (including invalid transitions that raise `InvalidSuggestionTransition`)
- `TenantIsolationViolation` raised on mismatched `TenantScopedDocument.tenant_id` (test: `test_llm_prompt_tenant_isolation_enforced.py`)
- `AutonBoundaryViolation` raised when any direct cross-context mutation is attempted (test: `test_autonomy_boundary_raises_on_direct_mutation.py`)
- `test_no_cross_context_domain_import_in_autonomous_intelligence.py` passing in CI
- Confidence threshold gate tested for all 4 target types
- `ModelStatus` lifecycle transitions tested including accuracy threshold enforcement

### Phase 2 — `posture_forecasting` and `threat_hunt` Domain Foundation
**Start condition:** Phase 1 exit criteria met
**Deliverables:** Both supporting bounded contexts; migrations `0138–0147`; `PostureForecastWorker`; `ForecastAccuracyWorker`; `ThreatHuntCandidateWorker`; `py.typed` markers for both packages; registration in `pyproject.toml`
**Test target:** ≥ 50 unit tests each context; ≥ 20 integration tests
**Exit criteria:**
- `PostureForecast` created with `ForecastInputSnapshot` (non-nullable); tested
- `ForecastAccuracyRecord` appended at T+30/60/90 measurement windows; tested
- `ThreatHuntCandidate` carries `anomaly_signal_refs` and `technique_coverage`; tested
- `ThreatHuntCandidate.PROMOTED` requires `reviewed_by` non-null and `soc:detection_engineer` role; tested
- `ILLMInferencePort` tenant isolation tested for `threat_hunt` context as well

### Phase 3 — ACL Translators and Cross-Context Integration
**Start condition:** Phase 2 exit criteria met; M33/M28/M34/M32/M30/M35 event schemas confirmed
**Deliverables:** All 10 ACL translators (7 inbound + 3 outbound target-context subscribers); `SuggestionGenerationWorker`; `SuggestionApplicationWorker`; `SuggestionExpiryWorker`; full event bus wiring
**Test target:** ≥ 50 integration tests across ACL boundary
**Exit criteria:**
- `test_suggestion_proposal_never_mutates_target_context_directly.py` passing
- Cross-tenant isolation: passing `tenant_id = "A"` never produces suggestions using data from `tenant_id = "B"`
- ACL translation errors produce `acl.translation.error` metric and do not raise unhandled exceptions
- `SuggestionExpiryWorker` transitions expired suggestions to `EXPIRED` with correct `expired_at`
- Outbound proposal events received and work items created in target contexts (integration test)

### Phase 4 — Security Graph, Read Models, Analytics
**Start condition:** Phase 3 exit criteria met
**Deliverables:** Migrations `0148–0149`; `M36SecurityGraphWorker`; `M36AnalyticsProjector`; all 6 read models implemented; all API routes for 3 bounded contexts registered in `src/redforge/api/v1/__init__.py`
**Test target:** ≥ 40 API tests; ≥ 20 projection tests
**Exit criteria:**
- `IntelligenceSuggestionNode` and `OptimizationModelNode` upsert by stable ID verified
- All 4 Security Graph edge types (`SUGGESTED_MODIFICATION`, `APPROVED_SUGGESTION`, `OUTCOME_FEEDBACK`, `GENERATED_DETECTION`) tested
- `SuggestionQueueReadModel` returns suggestions sorted by confidence score DESC
- Migration chain head is `0149` (verified by `test_single_head` in `tests/analytics/test_migration_chain.py`)

### Phase 5 — Workers, Observability, EU AI Act Artifacts
**Start condition:** Phase 4 exit criteria met
**Deliverables:** `OutcomeMeasurementWorker`; `ModelRetrainingWorker`; EU AI Act template document (`autonomous_intelligence/docs/eu_ai_act_conformity_template.md`); metrics/health endpoints; `llm_inference_audit_log` query endpoint; operations runbook
**Test target:** ≥ 30 integration tests (worker reliability, feedback loop)
**Final milestone exit criteria:**
- Suggestion generation P95 latency ≤ 30 seconds (measured under load test)
- `SuggestionOutcome` written correctly for at least one complete feedback cycle (integration test)
- `ModelRetrainingWorker` successfully triggers M33 training job when `feedback_sample_count >= retraining_threshold`
- `llm_inference_audit_log` records every LLM call with `tenant_id`, `model_id`, `prompt_token_count` (no content)
- EU AI Act conformity template complete and reviewed by product/legal

---

## Implementation Anti-Patterns (Prohibited)

1. **No `autonomous_intelligence.domain.*` or `autonomous_intelligence.application.*` import from `detection`, `campaign`, `playbook`, or `vulnerability`** — architecture test enforces at CI time
2. **No `LLMPrompt` construction with context documents from multiple tenants** — `LLMPrompt.__post_init__` raises `TenantIsolationViolation`
3. **No multi-tenant batching in any `ILLMInferencePort` implementation** — architecture test verifies
4. **No `IntelligenceSuggestion` with `confidence_score < min_confidence`** — rejected at `SuggestionGenerationService`; never persisted
5. **No direct call from `autonomous_intelligence` application service to M28/M30/M35 application service** — only event bus proposal mechanism permitted
6. **No `OptimizationModel` deployed without `conformity_assessment_ref`** — `ModelGovernanceService.deploy()` enforces
7. **No `OptimizationModel` deployed below accuracy threshold** — `ModelGovernanceService.deploy()` raises `AccuracyThresholdNotMet`
8. **No `ThreatHuntCandidate.PROMOTED` without `reviewed_by` and `soc:detection_engineer` role** — domain invariant
9. **No plaintext security data (credentials, exploit code, PII) in `TenantScopedDocument.content`** — content sanitization required before `LLMPrompt` construction
10. **No `SuggestionOutcome` written by `autonomous_intelligence` directly** — written only by `OutcomeMeasurementWorker` after querying target contexts via their read APIs

---

## Migration Chain Validation (Pre-Implementation)

The test `tests/analytics/test_migration_chain.py::test_single_head_0113` has been updated through M35 to assert `heads == ["0130"]`. After M36 implementation, this test MUST be updated to assert `heads == ["0149"]`.

This update is an **M36 Phase 4 exit criterion** — the migration chain test must be updated and passing before Phase 4 is declared complete.

---

## Package Registration (Required in Phase 1)

The following must be added to `backend/pyproject.toml` before Phase 1 implementation:

**`[tool.setuptools.packages.find]` includes:**
```
"autonomous_intelligence",
"posture_forecasting",
"threat_hunt",
```

**`[tool.ruff.lint.isort]` known-first-party:**
```
"autonomous_intelligence",
"posture_forecasting",
"threat_hunt",
```

**`[tool.ruff.lint.per-file-ignores]`** — same pattern as `incident`, `regulatory_notification`, `playbook` contexts.

**`py.typed` marker files required in:**
- `backend/src/autonomous_intelligence/py.typed`
- `backend/src/posture_forecasting/py.typed`
- `backend/src/threat_hunt/py.typed`

---

## Readiness Verdict

**ALL PRECONDITIONS MET.**

**Implementation approved to begin at Phase 1.**

The M36 architecture is production-grade, Fortune 100, mission-critical, and designed for 10+ years of operation. The three-bounded-context decomposition (`autonomous_intelligence` / `posture_forecasting` / `threat_hunt`) cleanly separates the AI suggestion lifecycle, trajectory forecasting, and proactive threat detection functions.

The AI autonomy boundary (ADR-M36-001) and LLM tenant isolation (ADR-M36-002) are the two CRITICAL invariants that define M36's compliance posture. Both are enforced at the domain layer and cannot be eroded by application-layer development. The human-in-the-loop governance gate (ADR-M36-006) satisfies EU AI Act Article 14 structurally.

The platform's self-improving loop — suggestion generation → human review → application → outcome measurement → model retraining — is architecturally complete. M36 is the milestone that transforms RedForge from an excellent security platform into a compounding competitive advantage.

**M36 Architecture Freeze Complete / STOP.**
