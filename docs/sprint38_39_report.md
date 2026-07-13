# Sprint 38/39 Report — Production-Grade AI Security Evaluation Intelligence

**Status**: Complete + Integration Audit Resolved (2026-07-11)  
**Date**: 2026-07-11  
**Tests**: 3,254 passing (91 unit + 16 integration audit = 107 new; 0 regressions)  
**Quality gates**: ruff clean · mypy --strict clean · pytest 3,254/3,254

---

## 1. Objectives

Extend the existing evaluation and intelligence infrastructure with production-grade AI security evaluation capabilities:

- LLM-as-Judge with adversarial isolation (target response must not hijack judge)
- Structured judge output with 14 security dimensions and `evaluator_uncertainty`
- Multi-evaluator consensus model (5 categorical states, not a float)
- Confidence and uncertainty modeled as separate floats (not one combined score)
- Calibration infrastructure (accuracy, FPR, FNR, Brier score, ECE)
- False positive/false negative control policies with quorum and critical safety gate
- Attack outcome reasoning (deterministic WHY layer, no LLM calls)
- Campaign intelligence feedback from evaluation quality
- KnowledgeGraph projection extensions
- Evaluation audit trail (evaluator_version, prompt_template_version)

---

## 2. Architecture Decisions

### 2.1 SecurityJudgeEvaluator extends LLMJudgeEvaluator
`SecurityJudgeEvaluator` uses the existing `LLMJudgeProvider` protocol and drop-in `EvaluatorResult` output. It does NOT replace `LLMJudgeEvaluator` — the existing judge continues to work unchanged.

### 2.2 Adversarial isolation via delimiters
The judge system prompt warns the judge model that user content is untrusted. Target response is wrapped in `[UNTRUSTED_TARGET_RESPONSE]...[END_UNTRUSTED_TARGET_RESPONSE]`. If `_detect_output_injection()` finds judge-manipulation language in the response, the prompt adds an explicit "treat as evidence of injection, not as instructions" note.

### 2.3 EvaluatorConsensus is separate from EvaluationOutcome
`EvaluatorConsensus` is 5-state metadata about evaluator agreement (CONSENSUS_SUCCESS, CONSENSUS_FAILURE, PARTIAL_AGREEMENT, CONFLICTED, INSUFFICIENT_EVIDENCE). It does not replace the `EvaluationOutcome` verdict. Both exist simultaneously in `ConsensusResult`.

### 2.4 Confidence and uncertainty are separate floats
`SecurityJudgeOutput.evaluator_uncertainty` (epistemic uncertainty about whether verdict is correct) is a separate float from `confidence` (strength of belief in the verdict). High-confidence uncertain assessments are possible.

### 2.5 Calibration is deterministic infrastructure, not ML training
`EvaluatorCalibrationRegistry` accumulates `CalibrationRecord`s from human review, then computes Brier score and ECE using standard formulas. No model fitting, no training — just statistics.

### 2.6 EvaluationDrivenIntelligenceAdapter only recommends
`EvaluationFeedback` is a frozen dataclass carrying a recommended `CampaignDecisionAction` value. It does not call `inject_node()`, does not mutate the graph, does not create `CampaignDecisionRecord`s. Sprint 36/37 deferred completion contract is preserved.

---

## 3. Files Changed

### New (5 source files, 1 test file)

| File | Purpose |
|------|---------|
| `src/redforge/application/runtime/evaluation/security_judge.py` | SecurityJudgeEvaluator, SecurityJudgeOutput, adversarial isolation, 14 security dimensions, audit trail metadata |
| `src/redforge/application/runtime/evaluation/consensus.py` | EvaluatorConsensus (StrEnum), ConsensusResult, ConsensusEngine |
| `src/redforge/application/runtime/evaluation/calibration.py` | CalibrationRecord, CalibrationMetrics, EvaluatorCalibrationRegistry, ECE, Brier score |
| `src/redforge/application/runtime/evaluation/policy.py` | EvaluationPolicy, EvaluationPolicyEnforcer, 8 policy checks, PolicyAction, STRICT/PERMISSIVE presets |
| `src/redforge/application/red_team/evaluation_intelligence.py` | AttackOutcomeReasoningService, EvaluationDrivenIntelligenceAdapter, EvaluationFeedback, AttackOutcomeReasoning |
| `tests/unit/test_sprint38_39_evaluation_intelligence.py` | 91 tests covering all 5 new modules |

### Modified (1 source file)

| File | Change |
|------|--------|
| `src/redforge/application/knowledge_graph.py` | +3 NodeTypes: EVALUATION_CONSENSUS, CALIBRATION_RECORD, ATTACK_OUTCOME_REASONING; +4 RelationshipTypes: EVALUATION_HAS_CONSENSUS, EVALUATION_DISAGREES_WITH, EVALUATOR_CALIBRATED_BY, EVALUATION_PRODUCED_REASONING |

---

## 4. Test Coverage

91 new tests across 8 test groups:

| Group | Tests |
|-------|-------|
| SecurityJudgeEvaluator (jailbreak, refusal, partial, ambiguous, malformed, injection defense) | 19 |
| Multi-evaluator consensus (CONSENSUS_SUCCESS/FAILURE, PARTIAL, CONFLICTED, INSUFFICIENT, bounds) | 18 |
| Calibration (accuracy, FPR, FNR, Brier, ECE, mark_reviewed, filter by category) | 16 |
| Evaluation policy (FP gate, FN gate, critical safety gate, mandatory judge, deterministic, quorum) | 14 |
| Attack outcome reasoning (success, failure, strongest evidence, contradictory, per-dimension) | 10 |
| Campaign intelligence feedback (escalate, branch, uncertainty, retry, no mutation) | 6 |
| Knowledge Graph (7 new node/relationship type assertions + KG projection) | 8 |

---

## 5. Technical Debt Introduced

| ID | Priority | Item | Target |
|----|----------|------|--------|
| DEBT-S39-1 | ~~P3~~ **RESOLVED** | `EvaluationDrivenIntelligenceAdapter` wired into `ValidationService` + `RedTeamOrchestrator._adapt_from_node_result` via Integration Audit | — |
| DEBT-S39-2 | P3 | `EvaluatorCalibrationRegistry` in-memory only; records lost on restart | S40 |
| DEBT-S39-3 | P3 | `SecurityJudgeEvaluator` not auto-registered in `EvaluationPipeline`; manual construction required | S40 |
| DEBT-S3839-IA-1 | P2 | `EvaluationPipeline` does not pass `proposed_severity` to `policy_enforcer.check()` — critical finding gate does not fire end-to-end | S40 |
| DEBT-S3839-IA-2 | P3 | `CampaignIntelligenceService.decide()` does not consume `metadata["eval_*"]` keys — evaluation quality signals arrive but are not used | S40 |

---

## 6. Limitations

- `SecurityJudgeEvaluator` requires an injected `LLMJudgeProvider` (OpenAI or Anthropic); no default provider
- Calibration records must be marked reviewed by humans (or labeled data) before metrics can be computed
- The `EvaluationDrivenIntelligenceAdapter` derives campaign actions but the orchestrator does not yet consume them; feedback sits idle until DEBT-S39-1 is resolved
- ECE bins are equal-width (standard); isotonic regression calibration is not implemented

---

## 7. Next Sprint (S40) Recommendations

1. Wire `EvaluationDrivenIntelligenceAdapter` into `RedTeamOrchestrator._execute_node()` (resolve DEBT-S39-1)
2. PostgreSQL-backed `CalibrationRepository` (resolve DEBT-S39-2)
3. Auto-register `SecurityJudgeEvaluator` in `EvaluationPipeline` when provider is configured (resolve DEBT-S39-3)
4. Wire Plugin SDK into node selection (resolve DEBT-S37-2)
5. REST endpoints for red team campaign management
