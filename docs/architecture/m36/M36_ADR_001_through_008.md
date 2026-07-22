# M36 Architecture Decision Records
## ADR-M36-001 through ADR-M36-008

**Date:** 2026-07-22
**Status:** FROZEN

---

## ADR-M36-001: AI Autonomy Boundary — Domain Invariant Enforcement

**Status:** ACCEPTED

### Context

M36 introduces AI-generated suggestions that, if acted on autonomously, would modify security controls (detection rules, playbooks, campaign scenarios). The regulatory and security consequence of this boundary being violated is severe: SOX, HIPAA, and PCI-DSS all require human approval for control changes. A compromised LLM provider that generates adversarial suggestions could disable detection rules or approve malicious playbooks if the boundary is enforced only at the application layer.

Application-layer enforcement (a command handler that refuses to call M28 directly) can be bypassed by adding a new command handler, a background worker, or an administrative escape hatch. Domain-layer enforcement cannot be bypassed without modifying the domain model.

### Decision

The AI autonomy boundary is a **domain invariant**, not an application-layer policy.

**Enforcement mechanism:**

1. `IntelligenceSuggestion` aggregate never holds a mutable reference to any aggregate from another bounded context. It holds only `SuggestionTargetRef` — a value object containing an opaque `target_id: UUID` and `target_type: SuggestionTargetType`.

2. `autonomous_intelligence.domain` and `autonomous_intelligence.application` packages contain zero imports from `detection`, `campaign`, `playbook`, `vulnerability`, or any other bounded context's domain packages. Enforced by `test_no_cross_context_domain_import_in_autonomous_intelligence.py` in CI.

3. The only mechanism by which a suggestion affects another context is the `SuggestionProposedForApplication` domain event. The receiving context's ACL subscriber creates its own work item using its own domain logic. `autonomous_intelligence` does not call any method on the target context's aggregates.

4. `AutonomyBoundaryService.assert_suggestion_does_not_directly_apply()` is called in `SuggestionReviewService.approve()`. It raises `AutonBoundaryViolation` (a domain exception) if the suggestion payload contains a direct aggregate mutation. `AutonBoundaryViolation` cannot be caught in application services — it propagates to the infrastructure layer as an unhandled exception.

### Consequences

**Positive:**
- The boundary cannot be eroded by new feature development without explicitly modifying the domain model (which would be visible in code review)
- Compliance posture for SOX/HIPAA/PCI-DSS is structurally satisfied, not just policy-compliant
- A compromised LLM provider can generate suggestions but cannot apply them; a human must explicitly approve and a separate context must create the actual aggregate

**Negative:**
- New suggestion target types require an ADR and a deliberate domain model change (acceptable; intended friction)
- `SuggestionProposedForApplication` event payload must be carefully designed so target contexts can act on it without needing to call back into `autonomous_intelligence`

---

## ADR-M36-002: LLM Tenant Isolation at Port Interface Level

**Status:** ACCEPTED

### Context

M36's suggestion generation invokes LLM APIs with context documents derived from platform security data. If tenant A's detection patterns or incident history appear in a prompt that also processes tenant B's data, cross-tenant leakage occurs. This is a critical security risk: security data from different enterprises must never be co-mingled in a single inference call.

Call-site discipline ("developers remember to filter") fails at scale. Lint rules can be bypassed. The isolation must be enforced by the type system.

### Decision

Tenant isolation is enforced at the `ILLMInferencePort` interface level, not at call sites.

```python
class ILLMInferencePort(Protocol):
    def generate(
        self,
        prompt: LLMPrompt,
        tenant_id: TenantId,   # port validates all context docs match this tenant_id
    ) -> LLMResponse: ...
```

`LLMPrompt.__post_init__` validates:
```python
for doc in self.context_documents:
    if doc.tenant_id != self.tenant_id:
        raise TenantIsolationViolation(
            f"LLMPrompt tenant_id={self.tenant_id} but document tenant_id={doc.tenant_id}"
        )
```

`TenantIsolationViolation` is a domain exception that propagates as an unhandled exception — it is never swallowed.

**Multi-tenant batching prohibition:** No `ILLMInferencePort` implementation may aggregate prompts across tenants in a single API call. This prohibition is documented as a non-functional requirement for all concrete port implementations. Architecture test `test_llm_prompt_tenant_isolation_enforced.py` verifies that constructing an `LLMPrompt` with mismatched document tenants raises `TenantIsolationViolation`.

### Consequences

**Positive:**
- Cross-tenant leakage requires an explicit violation of the `LLMPrompt` constructor, which raises a domain exception immediately
- Type system makes correct usage the path of least resistance
- New LLM provider integrations inherit the constraint without additional review

**Negative:**
- Cannot optimize LLM costs via multi-tenant batching (intentional; the constraint is a security requirement)
- `TenantScopedDocument` wrapping adds overhead for document preparation

---

## ADR-M36-003: Confidence Threshold Policy Per Suggestion Type

**Status:** ACCEPTED

### Context

Not all AI suggestions have equal confidence or equal consequence if wrong. A wrong vulnerability prioritization adjustment is less harmful than a wrong detection rule tuning suggestion that increases false negatives (missed attacks). The confidence threshold for creating a suggestion must reflect the risk profile of the suggestion type.

A global threshold fails in both directions: too high, and low-risk suggestions are unnecessarily suppressed; too low, and high-risk suggestions are generated at inadequate confidence.

### Decision

Per-`SuggestionTargetType` confidence thresholds with per-tenant configurability within floors:

| `SuggestionTargetType` | Default `min_confidence` | Tenant configurable? | Floor |
|---|---|---|---|
| `DETECTION_RULE_TUNING` | 0.75 | Yes | 0.60 |
| `CAMPAIGN_SCENARIO` | 0.65 | Yes | 0.55 |
| `PLAYBOOK_SYNTHESIS` | 0.70 | Yes | 0.60 |
| `VULNERABILITY_PRIORITY_ADJUSTMENT` | 0.60 | Yes | 0.50 |

Thresholds are stored in `AutonomousOperationsPolicy` aggregate. `SuggestionGenerationService` reads the active `AutonomousOperationsPolicy` before creating any `IntelligenceSuggestion` and rejects suggestions below threshold.

Floor values are domain constants (not configurable); they prevent tenants from setting thresholds so low that the human review gate becomes meaningless.

### Consequences

**Positive:**
- High-risk suggestion types have higher confidence gates by default
- Tenants can tune thresholds to their operational context (SOC staffing, risk tolerance)
- Roadmap success criterion (≥60% acceptance rate) is measurable against these thresholds; if acceptance rate drops below 60%, threshold review is indicated

**Negative:**
- Confidence score calibration requires ongoing measurement; initial thresholds are expert estimates, not empirically derived
- Mitigation: `SuggestionOutcome` aggregate provides the data needed to calibrate thresholds retrospectively

---

## ADR-M36-004: Suggestion Feedback Loop and Model Retraining Trigger

**Status:** ACCEPTED

### Context

ML models trained on static historical data degrade in accuracy as the security landscape evolves. M36's value proposition requires that its models improve over time. Without a feedback loop that measures suggestion outcomes and feeds them back to model training, the models stagnate or degrade.

The feedback loop must be closed: outcome measurement → `SuggestionOutcome` aggregate → retraining signal → `ModelRetrainingWorker` → M33 training job → new `OptimizationModel` version.

### Decision

**Feedback loop design:**

1. `SuggestionApplicationWorker` transitions approved suggestions to `APPLIED` when target contexts confirm acceptance.

2. `OutcomeMeasurementWorker` (nightly) measures actual outcomes at T+30 days for each `APPLIED` suggestion:
   - For `DETECTION_RULE_TUNING`: queries M28 for the FP/TP rate delta on the modified rule version
   - For `CAMPAIGN_SCENARIO`: queries M30 for campaign coverage delta (new ATT&CK techniques covered)
   - For `PLAYBOOK_SYNTHESIS`: queries M35 for playbook execution success rate
   - For `VULNERABILITY_PRIORITY_ADJUSTMENT`: queries M27 for remediation timeline delta vs. baseline

3. `OutcomeMeasurementWorker` writes `SuggestionOutcome` aggregate with `delta` field and publishes `SuggestionOutcomeCaptured`.

4. `FeedbackIngestionService` receives `SuggestionOutcomeCaptured`; routes to the `OptimizationModel.record_feedback()` method for the relevant `target_type`.

5. When `OptimizationModel.feedback_sample_count` reaches `retraining_threshold` (default: 50 accepted suggestions with measured outcomes), `ModelRetrainingWorker` triggers a new training job via M33 ML pipeline.

6. New trained model undergoes accuracy validation before deployment (ADR-M36-005). If it passes, it replaces the current `DEPLOYED` version.

**Circular dependency risk:** M36 models are trained on M33 analytics data. M33 analytics data includes M36 suggestion events. This circularity is bounded: the model training data is bounded to a specific window (trailing 12 months of outcomes) and the model is not trained on its own inference outputs (only on measured outcomes in target contexts).

### Consequences

**Positive:**
- Models improve over time without manual ML engineering intervention
- The compounding value proposition of the platform is architecturally realized
- Retraining is demand-triggered (outcome accumulation), not calendar-triggered

**Negative:**
- Outcome measurement depends on target contexts publishing correct outcome data; if M28/M30/M35 do not publish reliable performance metrics, feedback quality degrades
- Cold start: first 50 accepted suggestions have no feedback-driven improvement; initial model quality is critical for adoption

---

## ADR-M36-005: OptimizationModel Version Lifecycle and Accuracy Threshold

**Status:** ACCEPTED

### Context

ML models in production security systems must be governed like software: versioned, validated, deployed through a promotion gate, and deprecated when superseded. Ad-hoc model deployment without accuracy validation could degrade suggestion quality undetected.

### Decision

`OptimizationModel` follows a strict version lifecycle enforced by `ModelGovernanceService`:

```
TRAINING → VALIDATING → DEPLOYED
                    ↓
                  FAILED
DEPLOYED → DEPRECATED
```

**Promotion gate (enforced in `ModelGovernanceService.deploy()`):**

| Model target type | Accuracy metrics required |
|---|---|
| `DETECTION_RULE_TUNING` | `precision >= 0.75` AND `recall >= 0.70` |
| `CAMPAIGN_SCENARIO` | `relevance_score >= 0.65` |
| `PLAYBOOK_SYNTHESIS` | `structure_score >= 0.70` |
| `VULNERABILITY_PRIORITY_ADJUSTMENT` | `rank_correlation >= 0.60` |

If metrics are not met, model transitions to `FAILED`. `ModelGovernanceService` does not retry automatically — retraining requires explicit trigger (new feedback batch or manual intervention).

**One DEPLOYED version per target type per tenant.** Deploying a new version automatically deprecates the previous one. `DEPRECATED` versions are retained for 90 days for retrospective analysis, then eligible for archival.

**EU AI Act traceability:** Each `OptimizationModel` version records: `training_data_window`, `training_dataset_version`, `training_completed_at`, `accuracy_metrics`, `conformity_assessment_ref`. This is the immutable provenance record required for EU AI Act conformity.

### Consequences

**Positive:**
- No model reaches `DEPLOYED` without passing accuracy thresholds
- Version history provides full provenance trail for EU AI Act auditors
- Model degradation is immediately detectable (accuracy metrics tracked per version)

**Negative:**
- First deployment requires sufficient training data; cold start requires manual bootstrapping with curated training samples
- Accuracy thresholds are approximate; production accuracy may differ from validation accuracy (distribution shift)

---

## ADR-M36-006: Human-in-the-Loop Governance Gate

**Status:** ACCEPTED

### Context

M36's roadmap and EU AI Act compliance both require that AI-generated suggestions affecting security controls receive human review before taking effect. This is not a UX convenience — it is a regulatory requirement (EU AI Act Article 14: human oversight for high-risk AI systems) and a security requirement (prevents a compromised AI component from autonomously disabling controls).

The governance gate must be meaningful: rubber-stamp approvals (reviewers approve without examining the suggestion) defeat the purpose. The architecture cannot enforce reviewer diligence, but it can surface the information needed for meaningful review and create accountability through audit trails.

### Decision

**All `IntelligenceSuggestion` aggregates begin in `PENDING_REVIEW` status.** No suggestion is acted on without an explicit `ApproveSuggestion` command from an authorized human reviewer.

**Reviewer role requirements** (enforced by `SuggestionReviewService.assert_reviewer_authorized()`):

| `SuggestionTargetType` | Required role |
|---|---|
| `DETECTION_RULE_TUNING` | `soc:detection_engineer` |
| `CAMPAIGN_SCENARIO` | `red_team:architect` |
| `PLAYBOOK_SYNTHESIS` | `soc:security_engineer` |
| `VULNERABILITY_PRIORITY_ADJUSTMENT` | `vuln:manager` |

**Review information surfaced (mandatory for `SuggestionQueueReadModel`):**
- Confidence score
- Model version and accuracy metrics (so reviewer can assess model quality)
- Rationale summary (what signal drove this suggestion)
- Supporting signal references (links to M33 anomaly records, M28 performance data)
- Proposed change payload (what specifically will change if applied)
- `review_deadline_at` (suggestion expires if not reviewed within TTL)

**Review TTL:** Configurable per tenant (default: 72 hours for rule tuning; 168 hours for playbook synthesis). TTL is designed to prevent suggestion queue accumulation, not to rush review.

**Audit trail:** Every `ApproveSuggestion` and `RejectSuggestion` command records `reviewer_id`, `reviewed_at`, and (for rejections) `rejection_reason`. This trail is immutable and exported to the compliance audit log.

### Consequences

**Positive:**
- EU AI Act Article 14 human oversight requirement is architecturally satisfied
- Reviewer is provided all information needed for meaningful review (not just "approve/reject")
- Rejection reasons create a feedback signal for model improvement
- Accountability trail exists for every approval or rejection

**Negative:**
- Human review is a throughput bottleneck; if suggestion generation rate exceeds reviewer capacity, the queue grows; `AutonomousOperationsPolicy.max_suggestions_per_day` configures a rate limit
- Reviewers who routinely approve without examining suggestions cannot be technically prevented; this is a process/training concern, not an architecture concern

---

## ADR-M36-007: Cross-Context Proposal Protocol via Event Bus

**Status:** ACCEPTED

### Context

When a suggestion is approved, it must notify the target context (M28, M30, or M35) that a proposal is ready for an engineer to act on. Two options:

**Option A: Synchronous RPC call** — `autonomous_intelligence` application service calls a command on the target context's application service at approval time.

**Option B: Event bus proposal** — `autonomous_intelligence` publishes `SuggestionProposedForApplication` event; target context subscribes and creates a work item asynchronously.

Option A introduces runtime coupling: M36 suggestion approval fails if M28 is unavailable. M36's availability becomes dependent on M28/M30/M35 availability. Additionally, it creates an import dependency between application services, which violates bounded context isolation.

### Decision

**Option B (event bus proposal) is the only permitted mechanism.**

`SuggestionReviewService.approve()` publishes `SuggestionProposedForApplication` event to the event bus. Target contexts have dedicated ACL subscribers that run asynchronously:

- `detection/infrastructure/acl/m36_rule_tuning_proposal_subscriber.py` → creates `PendingRuleTuningItem`
- `campaign/infrastructure/acl/m36_scenario_proposal_subscriber.py` → creates `PendingScenarioItem`
- `playbook/infrastructure/acl/m36_playbook_synthesis_subscriber.py` → creates `PendingSynthesisItem`

When the engineer in the target context creates the actual aggregate (new `RuleVersion`, `ScenarioTemplate`, or `PlaybookVersion`) using the proposal as input, THAT context publishes its own event (e.g., `RuleVersionCreatedFromSuggestion`). `autonomous_intelligence` subscribes to that event via its own ACL translator and transitions the suggestion to `APPLIED`.

**`autonomous_intelligence` never directly calls a command on M28, M30, or M35.**

### Consequences

**Positive:**
- M36 approval availability is decoupled from M28/M30/M35 availability
- Bounded context isolation is maintained at runtime and at compile time
- Each target context can independently evolve how it handles proposals without modifying M36

**Negative:**
- Asynchronous proposal delivery means the work item appears in the target context queue with a short delay (typically seconds)
- If the event bus is unavailable, proposals are delayed (not lost; event bus provides at-least-once delivery with dead letter queue)
- `autonomous_intelligence` must handle the case where a target context never confirms acceptance (e.g., engineer deletes the work item without confirming); suggestions in `APPROVED` status with no `APPLIED` transition within 30 days are expired

---

## ADR-M36-008: EU AI Act Conformity Architecture

**Status:** ACCEPTED

### Context

M36's `OptimizationModel` instances are high-risk AI systems under EU AI Act Article 6: they affect decisions in security-critical contexts. High-risk AI systems require conformity assessment, transparency, human oversight, and accuracy/robustness documentation before market placement.

The EU AI Act became applicable to high-risk AI systems from August 2026. M36 must be compliant at release.

### Decision

**Conformity documentation artifacts (stored per `OptimizationModel` version, not just per application):**

| Artifact | Where Stored | Updated When |
|---|---|---|
| Training data lineage | `OptimizationModel.training_data_window` + `training_dataset_version` | At training time |
| Accuracy metrics (validation set) | `OptimizationModel.accuracy_metrics` | At VALIDATING → DEPLOYED |
| Conformity assessment ref | `OptimizationModel.conformity_assessment_ref` (opaque doc ID) | Before DEPLOYED |
| Human oversight mechanism description | `autonomous_intelligence/docs/eu_ai_act_oversight.md` | At M36 release |
| Model change log | `model_training_jobs` table (all training runs, outcomes) | Continuously |
| Incident/malfunction log | M36 suggestion outcomes with negative delta | Continuously |

**Transparency requirement:** `SuggestionQueueReadModel` exposes model version and accuracy metrics to human reviewers. Reviewers can see the quality characteristics of the model that generated a given suggestion before approving.

**Human oversight (Article 14):** Satisfied by ADR-M36-006 (all suggestions require human review before application).

**Accuracy and robustness (Article 15):** Satisfied by ADR-M36-005 (accuracy threshold gate at deployment) and ADR-M36-004 (feedback loop and retraining).

**Post-market monitoring (Article 72):** `SuggestionOutcome` aggregate provides continuous accuracy measurement after deployment. Aggregate negative delta trend (suggestion quality degrading) triggers `ModelRetrainingWorker`.

### Consequences

**Positive:**
- M36 can be placed in regulated industry environments (EU-based enterprises) at release
- Conformity documentation is machine-generated from domain data, not manual
- Human oversight and transparency requirements are structurally satisfied by the existing architecture

**Negative:**
- `conformity_assessment_ref` requires an external document management system to hold the full conformity assessment document; the domain stores only the reference
- Each new `SuggestionTargetType` (new ADR) requires a new conformity assessment
