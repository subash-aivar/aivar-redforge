# M36 Risk Register
## Enterprise AI-Native Autonomous Security Operations

**Date:** 2026-07-22
**Status:** FINAL — All risks disposed

---

## Risk Disposition Legend

| Disposition | Meaning |
|---|---|
| MITIGATE | Risk accepted with specific mitigation controls that reduce likelihood or impact |
| ACCEPT | Risk accepted without mitigation; impact is tolerable or mitigation cost exceeds benefit |
| DEFER | Risk deferred to a future milestone; not blocking M36 |
| REJECT | Risk determined to be non-existent or misidentified after analysis |

---

## R01 — AI Autonomy Boundary Violation

**Category:** Security Risk / Compliance Risk
**Severity:** CRITICAL
**Likelihood:** LOW (with controls applied)
**Impact:** CRITICAL (AI autonomously modifies active detection rules or playbooks; SOX/HIPAA/PCI-DSS violation; potential security control degradation)

**Root Cause:** A developer adds a new command handler or background worker that calls a M28/M30/M35 application service directly, bypassing the event-bus proposal protocol.

**Disposition:** MITIGATE

**Mitigations:**
1. **Domain invariant enforcement (ADR-M36-001):** `AutonomyBoundaryService.assert_suggestion_does_not_directly_apply()` is a domain-layer check that raises `AutonBoundaryViolation` — uncatchable at application layer.
2. **Zero cross-context imports (architecture test):** `test_no_cross_context_domain_import_in_autonomous_intelligence.py` fails CI if any import from `detection`, `campaign`, `playbook`, or `vulnerability` appears in `autonomous_intelligence.domain.*` or `autonomous_intelligence.application.*`. This prevents even compile-time coupling.
3. **Event-bus-only protocol (ADR-M36-007):** `SuggestionProposedForApplication` event is the only mechanism. No synchronous RPC method exists between `autonomous_intelligence` and target contexts.
4. **Code review policy:** Architecture decision is documented; PRs that introduce direct cross-context calls are blocked by policy.

**Residual Risk:** A deliberate, coordinated bypass by multiple developers with write access to both `autonomous_intelligence` and `detection` packages. This is a threat actor model outside the domain's trust boundary (assumes compromised development team).

---

## R02 — LLM Provider Compromise — Adversarial Suggestion Generation

**Category:** Security Risk
**Severity:** CRITICAL
**Likelihood:** LOW
**Impact:** HIGH (adversarial LLM response generates suggestions that, if approved, would weaken security controls)

**Root Cause:** M36 relies on LLM APIs (external providers) for suggestion generation. If the LLM provider is compromised (supply chain attack, model poisoning, prompt injection), the generated suggestions may be adversarial — designed to degrade security controls or create exploitable gaps.

**Disposition:** MITIGATE

**Mitigations:**
1. **Human review gate (ADR-M36-006):** All suggestions require human review by a qualified security professional before application. An adversarial suggestion that proposes disabling detection rules would be recognized by a detection engineer reviewing it.
2. **Confidence threshold gate (ADR-M36-003):** Adversarial suggestions that are internally inconsistent with the training signal will receive low confidence scores and be rejected before reaching the review queue.
3. **Suggestion payload validation:** `AutonomyBoundaryService` validates that `proposed_change_payload` contains only the expected fields for the given `SuggestionTargetType`; unknown fields or payloads that reference system-level operations are rejected.
4. **Prompt injection mitigation:** `TenantScopedDocument.content` is sanitized before inclusion in `LLMPrompt`; content containing LLM instruction-override patterns is flagged and excluded.
5. **Acceptance rate monitoring:** If acceptance rate drops below 30% or spikes above 95%, the `ModelGovernanceService` flags an anomaly for security review.

**Residual Risk:** A sophisticated adversarial suggestion that appears legitimate to a human reviewer cannot be detected by architecture controls. This is a threat actor model that requires SOC analyst training and review procedures as the primary control.

---

## R03 — Cross-Tenant LLM Data Leakage

**Category:** Security Risk / Privacy Risk
**Severity:** CRITICAL
**Likelihood:** LOW (with controls applied)
**Impact:** CRITICAL (security data from Tenant A appears in Tenant B's suggestion generation; enterprise data leakage)

**Root Cause:** LLM prompt construction inadvertently includes documents from multiple tenants in a single API call.

**Disposition:** MITIGATE

**Mitigations:**
1. **Port interface enforcement (ADR-M36-002):** `ILLMInferencePort.generate()` takes `tenant_id` as a non-nullable parameter. `LLMPrompt.__post_init__` raises `TenantIsolationViolation` if any `TenantScopedDocument.tenant_id` does not match `LLMPrompt.tenant_id`. This validation occurs before any data reaches the LLM provider.
2. **Multi-tenant batching prohibition:** No `ILLMInferencePort` implementation may batch prompts across tenants. Architecture test enforces this at the port contract level.
3. **Data lineage audit:** `llm_inference_audit_log` table records every LLM call with `tenant_id`, `model_id`, `prompt_document_count`, and `prompt_token_count` (not the content). An audit of this table can verify that no call processed cross-tenant data.

**Residual Risk:** A bug in `TenantScopedDocument` tagging (a document tagged with the wrong `tenant_id`) could allow leakage that passes the tenant isolation check. Mitigation: `TenantScopedDocument.tenant_id` is set at query time (not at indexing time) by the application service that retrieves the document; the application service always queries with `tenant_id` as a first-class parameter.

---

## R04 — Cold Start — ML Model Quality Below Acceptance Threshold

**Category:** Operational Risk / Product Risk
**Severity:** HIGH
**Likelihood:** MEDIUM (all tenants begin with zero feedback history)
**Impact:** MEDIUM (first-generation suggestions have low acceptance rates; erodes user trust in AI suggestions)

**Root Cause:** `OptimizationModel` first deployment uses historical M33 platform data as training corpus. For tenants with limited M33 history (new deployments, or tenants who activated M33 recently), training data may be insufficient to produce high-quality suggestions.

**Disposition:** MITIGATE

**Mitigations:**
1. **Accuracy threshold gate (ADR-M36-005):** Models with below-threshold accuracy are not deployed. If training data is insufficient, model remains in `FAILED` status and no low-quality suggestions are generated.
2. **Cross-tenant anonymized bootstrap model:** For the initial M36 release, a cross-tenant anonymized model (trained on aggregate anonymized signal patterns, not tenant-specific data) can provide bootstrap suggestions until tenant-specific models have sufficient training data. This model requires explicit CISO consent and is documented in `AutonomousOperationsPolicy.bootstrap_model_enabled`.
3. **Minimum training data gate:** `ModelGovernanceService` enforces a minimum `training_sample_count` before training begins (default: 200 signal records per target type). Tenants below this threshold are shown "Insufficient data for AI suggestions" rather than low-quality suggestions.
4. **Roadmap success criterion monitoring:** Acceptance rate ≥60% is monitored per tenant. Tenants below 60% after 30 days of M36 operation trigger a model quality review.

**Residual Risk:** Bootstrap cross-tenant model may not reflect a specific tenant's threat landscape. This is an accepted limitation of the cold-start period; tenant-specific model quality improves as feedback accumulates.

---

## R05 — Suggestion Quality Degradation Without Feedback Signal

**Category:** Operational Risk
**Severity:** HIGH
**Likelihood:** MEDIUM (requires sustained reviewer behavior of approving without outcome tracking)
**Impact:** HIGH (model retraining without signal degrades quality; ADR-M36-004 feedback loop breaks)

**Root Cause:** The feedback loop (ADR-M36-004) requires that `OutcomeMeasurementWorker` successfully measures outcomes in target contexts. If target contexts (M28, M30, M35) do not publish reliable performance metrics after suggestion application, outcome measurement fails and retraining receives no signal.

**Disposition:** MITIGATE

**Mitigations:**
1. **Outcome measurement monitoring:** `OutcomeMeasurementWorker` emits `m36.outcome.measurement.success` and `m36.outcome.measurement.failed` metrics per target type. Alert triggers if `measurement.failed / (measurement.success + measurement.failed) > 0.30` (>30% outcome measurement failure rate).
2. **`NOT_APPLICABLE` outcome type:** If a target context cannot provide outcome metrics for a suggestion type, `SuggestionOutcome.outcome_type = NOT_APPLICABLE` is recorded rather than silently failing. `NOT_APPLICABLE` outcomes are excluded from retraining signal but counted to detect systematic measurement gaps.
3. **Manual feedback injection:** Authorized `ai:model_operator` role can inject manual `SuggestionOutcome` records for suggestions where automated measurement is not possible (e.g., a campaign scenario that was run and measured offline).

**Residual Risk:** If all target contexts fail to provide outcome metrics for an extended period (>90 days), the retraining signal is insufficient and the model stagnates. Alert thresholds ensure this is detected before it causes material quality degradation.

---

## R06 — Suggestion Proposal Queue Overflow (Human Review Bottleneck)

**Category:** Operational Risk / Scalability Risk
**Severity:** MEDIUM
**Likelihood:** MEDIUM (demand scales with platform adoption; reviewer headcount does not automatically scale)
**Impact:** MEDIUM (suggestions expire without review; model feedback is lost; user trust degrades)

**Root Cause:** `SuggestionGenerationWorker` generates suggestions at a rate determined by incoming signal events. Human reviewers have fixed throughput. If generation rate exceeds review rate, the `PENDING_REVIEW` queue grows and suggestions expire before review.

**Disposition:** MITIGATE

**Mitigations:**
1. **Per-tenant suggestion rate limit:** `AutonomousOperationsPolicy.max_suggestions_per_day` (default: 10 per target type per tenant) limits suggestion generation rate. Signals that would generate more suggestions than the limit are queued for next-day processing.
2. **Confidence-ranked queue:** `SuggestionQueueReadModel` sorts suggestions by `confidence_score DESC`. Reviewers process highest-confidence suggestions first, ensuring that if queue depth grows, the highest-value suggestions are reviewed before expiry.
3. **Review deadline alert:** 24 hours before `review_deadline_at`, a notification is sent to the authorized reviewer role. 4 hours before, a `P3` escalation is created.
4. **Configurable TTL:** Tenants with lower reviewer throughput can extend `review_deadline_hours` (default: 72 hours) up to 168 hours (7 days) to allow asynchronous review.

**Residual Risk:** Structural reviewer capacity shortage cannot be resolved by architecture controls. This is a staffing concern; the architecture surfaces it as a metric (`pending_review_count`, `avg_time_to_review`) on the operations dashboard.

---

## R07 — OptimizationModel Training Data Circular Dependency

**Category:** Architectural Risk
**Severity:** MEDIUM
**Likelihood:** LOW
**Impact:** MEDIUM (model trains on its own inference artifacts; circular reinforcement degrades quality in unpredictable ways)

**Root Cause:** M36 suggestion events are recorded in M33 analytics. M33 analytics data is used as training signal for M36 models. This creates a potential circular dependency: the model trains on data that includes artifacts of its own previous suggestions.

**Disposition:** MITIGATE

**Mitigations:**
1. **Training data scope restriction:** `ModelTrainingJob` specifies `training_data_window` that explicitly excludes M36 suggestion event tables from training features. Training features are bounded to: M28 rule performance data, M30 campaign outcomes, M34 incident patterns, M32 exposure trends. M36 suggestion events are NEVER training features.
2. **Training data lineage enforcement (ADR-M36-008):** `training_dataset_version` is recorded on each model version, allowing auditors to verify that no M36 suggestion artifacts were included in training features.
3. **Periodic independent validation:** `ModelGovernanceService` runs an independent validation pass on held-out data monthly. If validation accuracy diverges significantly from training accuracy, a data quality review is triggered.

**Residual Risk:** Indirect circularity (M36 suggestions improve M28 rules → improved M28 rule data is used in next training cycle) cannot be fully eliminated. This is the intended feedback loop design — M36 suggestions improving security controls should produce better training signals. The risk of unintended circular reinforcement is mitigated by human review gates (humans approve the intermediate changes) which break the circularity at each step.

---

## R08 — EU AI Act Conformity Assessment Operational Gap

**Category:** Compliance Risk
**Severity:** MEDIUM
**Likelihood:** MEDIUM (new regulatory requirement; compliance processes are immature)
**Impact:** MEDIUM (M36 cannot be offered to EU-regulated enterprises without conformity documentation; limits addressable market)

**Root Cause:** EU AI Act requires a conformity assessment document before a high-risk AI system can be placed on the market. This assessment must be maintained per model version. The operational process for producing and maintaining these assessments has not been established.

**Disposition:** MITIGATE

**Mitigations:**
1. **Machine-generated conformity data (ADR-M36-008):** `OptimizationModel` automatically records all machine-readable conformity artifacts (training data lineage, accuracy metrics, model change log). The conformity assessment document is mostly populated from these records.
2. **Template assessment document:** A human-authored template `autonomous_intelligence/docs/eu_ai_act_conformity_template.md` is produced as part of M36 implementation Phase 5. Product/legal team populates the non-machine-generated sections before M36 GA.
3. **`conformity_assessment_ref` gate:** `ModelGovernanceService.deploy()` requires a non-null `conformity_assessment_ref` for deployment. A model cannot be deployed without at least a draft conformity assessment reference.

**Residual Risk:** The conformity assessment process depends on product/legal team capacity. Architecture provides the data; the process gap is a product operations concern.

---

## R09 — Posture Forecast Accuracy Below 20% Error Target

**Category:** Product Risk
**Severity:** MEDIUM
**Likelihood:** MEDIUM (forecasting is inherently probabilistic; remediation velocity is variable)
**Impact:** LOW-MEDIUM (forecast shown to users is inaccurate; erodes trust in posture forecasting feature)

**Root Cause:** The roadmap success criterion is ≤20% absolute error on 30-day forecast. This requires accurate input signals (remediation velocity, exposure score baseline) and a model tuned to each tenant's specific remediation patterns.

**Disposition:** ACCEPT

**Justification:** Forecasting accuracy at the 20% target is plausible but not guaranteed on first deployment. The `ForecastAccuracyRecord` mechanism (ADR C8) provides continuous measurement of forecast accuracy. If accuracy consistently exceeds 20%, the model parameters can be tuned without architectural change. The architecture is correct; the risk is in model tuning, which is an operational concern.

**Mitigations applied:**
1. `ForecastAccuracyWorker` measures accuracy at T+30/60/90 and surfaces results on the `PostureForecastReadModel`. Inaccurate forecasts are visible.
2. `ForecastInputSnapshot` captures the baseline state that the forecast was derived from, enabling post-hoc analysis of why a forecast was inaccurate.
3. Confidence interval surfaced in `PostureForecastReadModel`: forecast is expressed as a range, not a point estimate, managing user expectations about forecast precision.

---

## R10 — Threat Hunt Candidate Promotion Without Detection Engineer Review

**Category:** Security Risk
**Severity:** MEDIUM
**Likelihood:** LOW
**Impact:** MEDIUM (unreviewed detection rule candidate promoted to production; may cause FP storm or miss true positive patterns)

**Root Cause:** `ThreatHuntCandidate.PROMOTED` transition requires a `soc:detection_engineer` review. If role enforcement fails, a candidate could be promoted without review.

**Disposition:** MITIGATE

**Mitigations:**
1. **Role enforcement in `CandidateReviewService.promote()`:** Raises `InsufficientRole` if `promoted_by` actor does not hold `soc:detection_engineer` role. Domain service check, not application-layer check.
2. **`PROMOTED` requires `reviewed_at` and `reviewed_by` to be non-null:** Domain invariant enforced in `ThreatHuntCandidate.promote()` aggregate method.
3. **M28 as the actual gate:** `ThreatHuntCandidatePromoted` event only indicates that the detection engineer found the candidate worth pursuing. The actual detection rule creation happens in M28 through M28's own authorization gates (design-time approval). M36 promotion is a statement of intent, not an automatic M28 write.

**Residual Risk:** The M28 authorization gate is the final safety control. Even if M36's promotion gate is bypassed, M28 requires its own design-time approval before a rule version is published.
