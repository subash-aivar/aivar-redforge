# Sprint 40 Report — Close the Evaluation Control Loop

**Status**: Complete (2026-07-11)
**Tests**: 3,284 passing (30 new; 0 regressions)
**Quality gates**: ruff clean (2 pre-existing in knowledge_graph.py) · mypy --strict clean (446 files) · pytest 3,284/3,284

---

## 1. Mission

Close the two production integration debts discovered by the Sprint 38/39 Integration Audit:

- **DEBT-S3839-IA-1** (P2): `EvaluationPipeline` did not pass `proposed_severity` to `EvaluationPolicyEnforcer.check()` — the critical finding safety gate never fired end-to-end.
- **DEBT-S3839-IA-2** (P3): `RuleBasedCampaignIntelligenceService.decide()` did not read `CampaignIntelligenceContext.metadata["eval_*"]` keys — evaluation quality signals arrived at the boundary but were completely ignored.

Additionally: prove production composition root wiring (PART 5), assess typed vs string transport (PART 4), preserve recommendation ≠ applied action invariant (PART 3).

---

## 2. Changes

### 2.1 EvaluationPipeline step reorder (DEBT-S3839-IA-1)

**File**: `src/redforge/application/runtime/evaluation/pipeline.py`

**Root cause**: `EvaluationPolicyEnforcer.check()` only enters the critical finding safety gate (check 8) when `proposed_severity == "critical"`. The pipeline previously called `check()` with no `proposed_severity`, then generated the finding. `override_severity` was always `None`; `_apply_policy_severity` was a permanent no-op.

**Fix**: Reorder steps 4 and 5 in `evaluate()`:

```
Before (broken):
  3. Consensus
  4. Policy check (no proposed_severity) ← BUG
  5. Generate candidate → apply policy override

After (fixed):
  3. Consensus
  4. Generate FindingCandidate  ← severity now known
  5. Policy check WITH proposed_severity=candidate.severity
  6. Apply policy severity override to candidate
```

The `EvaluationPolicyEnforcer.check()` already accepted `proposed_severity: str | None = None` — only the call site needed fixing.

### 2.2 Orchestrator metadata extraction corrected

**File**: `src/redforge/application/red_team/orchestrator.py`

**Root cause**: The `_adapt_from_node_result()` method read `evaluation_feedback.consensus_state`, `evaluation_feedback.consensus_confidence`, `evaluation_feedback.evaluator_uncertainty` — none of which exist on `EvaluationFeedback`. These `getattr()` calls returned `None`, so `eval_consensus_state`, `eval_consensus_confidence`, `eval_evaluator_uncertainty` were never populated.

**Fix**: Read the actual `EvaluationFeedback` fields:
- `recommended_campaign_action` → `eval_recommended_action` (was already correct)
- `evaluation_quality` → `eval_evaluation_quality` (new)
- `requires_more_evidence` → `eval_requires_more_evidence` (new, serialized as "true"/"false")

### 2.3 Campaign intelligence consumes eval signals (DEBT-S3839-IA-2)

**File**: `src/redforge/application/red_team/campaign_intelligence.py`

**Root cause**: `RuleBasedCampaignIntelligenceService._evaluate()` never read `context.metadata`. All eval quality signals placed there by the orchestrator were discarded silently.

**Fix**: Added `_modulate_from_eval_signals(action, rationale, metadata)` — called from `decide()` AFTER the rule-based decision, before confidence estimation. Six modulation rules:

| Rule | Signal | Trigger | Applied Action |
|------|--------|---------|----------------|
| 1 | `eval_requires_more_evidence=true` | ESCALATE or BRANCH | RETRY_WITH_VARIANT |
| 2 | `eval_evaluation_quality=low` | ESCALATE | BRANCH |
| 3 | `eval_consensus_state=conflicted` | ESCALATE | RETRY_WITH_VARIANT |
| 4 | `eval_consensus_state=insufficient_evidence` | ESCALATE or BRANCH | RETRY_WITH_VARIANT |
| 5 | `eval_consensus_state=partial_agreement` | ESCALATE | BRANCH |
| 6 | `eval_recommended_action=retry_with_variant/pivot` | ESCALATE | advisory action |

**PART 3 — Recommendation ≠ applied action invariant**:
- `eval_recommended_action` is read as advisory input to Rule 6 only
- Rule 6 NEVER fires when the recommendation is `branch` or `escalate` (conservative-only)
- STOP decisions are not modulated regardless of eval signals
- The `CampaignDecisionRecord.action` is the service's own computed output, not a copy of the recommendation
- Fail-closed on unknown enum values (`contextlib.suppress(ValueError)`)

**PART 4 — Typed vs string transport**:
- `EvaluationFeedback` is typed (application layer)
- `CampaignIntelligenceContext.metadata` is `dict[str, str]` — correct for cross-bounded-context transport (domain layer cannot import application types)
- `_modulate_from_eval_signals` parses strings strictly with fail-closed semantics; no `eval_*` key can cause an exception or unsafe fallback

### 2.4 Production wiring factory functions (PART 5)

**File**: `src/redforge/api/dependencies.py`

Added composition root factory functions:

- `_evaluation_intelligence_adapter()` — `@lru_cache` singleton `EvaluationDrivenIntelligenceAdapter`
- `_campaign_intelligence_service()` — `@lru_cache` singleton `RuleBasedCampaignIntelligenceService`
- `wire_evaluation_into_validation_service(vs)` — attaches the evaluation adapter to any `ValidationService`; safe no-op on objects without `with_evaluation_adapter`
- `build_red_team_orchestrator(vs)` — constructs `RedTeamOrchestrator` with wired knowledge graph and campaign intelligence service

**Documented gap**: `ValidationService` requires deployment-specific infrastructure adapters (`StepExecutor`, `AttackResolverPort`, etc.) that are not wired here. Callers must construct `ValidationService` with their infra adapters and call `wire_evaluation_into_validation_service()` before passing it to `build_red_team_orchestrator()`.

---

## 3. Files Changed

| File | Change |
|------|--------|
| `src/redforge/application/runtime/evaluation/pipeline.py` | Step reorder: finding generation before policy check; pass `proposed_severity` |
| `src/redforge/application/red_team/orchestrator.py` | Corrected metadata extraction: reads actual `EvaluationFeedback` fields |
| `src/redforge/application/red_team/campaign_intelligence.py` | Added `_modulate_from_eval_signals()`; called from `decide()` |
| `src/redforge/api/dependencies.py` | Production wiring factory functions |
| `tests/unit/test_sprint40_evaluation_control_loop.py` | 30 new tests covering all 5 parts |
| `docs/PROJECT_CONTEXT.md` | Debt items resolved; test baseline updated to 3,284 |

---

## 4. Test Coverage (30 new tests)

| Group | Tests |
|-------|-------|
| PART 1: Proposed severity gate (critical blocked, high not blocked, ordering proof, permissive policy, policy attached, no enforcer) | 7 |
| PART 2: Campaign intelligence eval signals (requires_more_evidence, low quality, high quality, empty metadata, conflicted, insufficient_evidence, partial_agreement, unknown state, advisory retry, stop not overridden) | 11 |
| PART 3: Recommendation vs applied invariant (advisory branch doesn't affect CONTINUE, annotation appended not replaced, applied action is computed not copied) | 3 |
| PART 4: Typed vs string transport (malformed action ignored, malformed consensus ignored, false string not triggered, consensus_success unchanged) | 4 |
| PART 5: Production wiring (adapter importable, intelligence service importable, wire fn attaches adapter, wire fn noop on unknown type, orchestrator returned) | 5 |

---

## 5. Technical Debt Status

| ID | Status | Notes |
|----|--------|-------|
| DEBT-S3839-IA-1 | **RESOLVED** | Finding generation reordered; `proposed_severity` passed; critical gate fires end-to-end |
| DEBT-S3839-IA-2 | **RESOLVED** | `_modulate_from_eval_signals()` wired into `decide()`; 6 modulation rules consuming actual metadata keys |
| DEBT-S39-2 | Open (P3) | CalibrationRegistry still in-memory only |
| DEBT-S39-3 | Open (P3) | SecurityJudgeEvaluator still requires manual registration |
| DEBT-S37-2 | Open (P3) | Plugin SDK not consulted during node selection |
| Deferred | Open | No red team API endpoints; ValidationService infra adapters not wired in dependencies.py |

---

## 6. Principal Reviews

### Review 1 — Step Reorder Safety
The pipeline reorder is safe because `EvaluationPipeline` is stateless and the `finding_generator` was already called with `aggregated` and `context` (same inputs). Moving it before policy check does not change the finding generation logic — it only makes the result available to the policy enforcer. The only behavioral change: `proposed_severity` is now non-None when a finding would be generated, enabling check 8 of the policy enforcer.

### Review 2 — Fail-Closed on Unknown Metadata
`_modulate_from_eval_signals` uses `contextlib.suppress(ValueError)` for all three parse paths. An unrecognized enum value (e.g., a future `CampaignDecisionAction` value or `EvaluatorConsensus` state) leaves the local variable as `None`, causing all corresponding rules to skip. The action and rationale are returned unchanged. This is the correct fail-closed behavior: unknown signals are ignored, not panicked on.

### Review 3 — Recommendation ≠ Applied Action
`_modulate_from_eval_signals` reads `eval_recommended_action` but only applies it in Rule 6 (advisory), and only when the base action is ESCALATE and the recommendation is a more conservative action (`RETRY_WITH_VARIANT` or `PIVOT`). This means:
- The adapter can recommend ESCALATE all it wants — `decide()` does its own ESCALATE logic
- The adapter recommending BRANCH does not override ESCALATE (Rule 6 only applies conservative downgrades)
- STOP decisions are never touched by modulation (the STOP check fires before `_modulate_from_eval_signals` is called)

### Review 4 — dict[str, str] as Transport
The `CampaignIntelligenceContext.metadata: dict[str, str]` field is correct. The domain layer (where `CampaignIntelligenceContext` is defined) cannot import application layer types (`EvaluatorConsensus`, `CampaignDecisionAction`). Stringly-typed transport with strict parsing at the consumer boundary is the right pattern. The application layer intelligence service parses the strings into typed values with fail-closed semantics.

### Review 5 — Orchestrator Metadata Correction
The original orchestrator code read `evaluation_feedback.consensus_state`, `consensus_confidence`, `evaluator_uncertainty` — none of which exist on `EvaluationFeedback`. This was a silent data loss bug: all three metadata keys were never populated. The fix reads actual fields (`evaluation_quality`, `requires_more_evidence`). The existing Sprint 38/39 integration audit tests that check `eval_metadata["eval_recommended_action"]` are unaffected (that key was already correctly populated). The nonexistent-attribute reads produced no data, so removing them changes no observable behavior in existing tests.

### Review 6 — Production Wiring Gap
`ValidationService` has 7 required constructor parameters (executor, classifier, attack_resolver, risk_engine, kg_populator, uow_factory, event_publisher). These are deployment-specific infrastructure adapters. The `dependencies.py` factory functions `wire_evaluation_into_validation_service()` and `build_red_team_orchestrator()` correctly document this gap: callers must provide a pre-constructed `ValidationService`. This is honest — pretending we can construct a full `ValidationService` from just `dependencies.py` would require hardcoding infrastructure choices that should be deployment-configurable.

### Review 7 — Adversarial Self-Review
**Could a malicious target response cause modulation to take a wrong path?** No. The `eval_*` metadata keys are populated by the orchestrator from `EvaluationFeedback`, which is the output of `EvaluationDrivenIntelligenceAdapter.derive_feedback()`. The adapter input is the `AggregatedEvaluation` from the evaluators, not the raw target response. The target response cannot inject values into `context.metadata` because that dict is constructed by the orchestrator from the typed `EvaluationFeedback` dataclass, not from any user/target-controlled input. The only attack surface would be if a target could somehow cause the evaluators to produce CONSENSUS_SUCCESS at high confidence on a non-attack response — but that is the evaluator's responsibility to prevent, not the intelligence layer's.
