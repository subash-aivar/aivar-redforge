# M36 Architecture Review
## Enterprise AI-Native Autonomous Security Operations

**Date:** 2026-07-22
**Reviewer Role:** Chief Software Architect / Distinguished Engineer / Principal AI Security Architect / Principal Red Team Architect / Enterprise Platform Architect
**Repository Status:** M30–M35 Released; Migration Head: `0130`
**Status:** APPROVED WITH CONDITIONS (C1–C10)

---

## Section 1: Repository State at Review Point

| Metric | Value |
|---|---|
| Migration head | `0130_m35_analytics_projection` |
| Bounded contexts (existing) | 29 (detection, campaign, engagement, playbook, automated_action, integration_hub, incident, analytics, ml_pipeline, reporting, exposure, posture, intelligence, inventory, connector, platform, remediation_impact, evaluation, scenario, vulnerability, operation, red_team_operator, taskgraph, payload, credential_vault, lessons_learned, regulatory_notification, ai_posture, ai_supply_chain) |
| New bounded contexts (M36) | 3 (`autonomous_intelligence`, `posture_forecasting`, `threat_hunt`) |
| Migration range (M36) | `0131` → `0149` (estimated) |
| Hard dependencies | M33 (analytics/ML infrastructure), M28 (detection), M30 (campaign), M35 (automation) |

---

## Section 2: M36 Scope Validation

**Source:** `docs/roadmap/REDFORGE_ENTERPRISE_ROADMAP_M31_M36.md`, Section M36.

### In-Scope (confirmed from roadmap)

| Capability | Bounded Context | Status |
|---|---|---|
| Autonomous detection rule tuning suggestions | `autonomous_intelligence` | IN SCOPE |
| AI campaign scenario suggestion | `autonomous_intelligence` | IN SCOPE |
| Autonomous vulnerability prioritization enhancement | `autonomous_intelligence` | IN SCOPE |
| AI playbook synthesis from M34 incident patterns | `autonomous_intelligence` | IN SCOPE |
| Human-in-the-loop governance for all suggestions | `autonomous_intelligence` | IN SCOPE |
| Posture forecast (30/60/90-day trajectory) | `posture_forecasting` | IN SCOPE |
| Autonomous threat hunt candidate generation | `threat_hunt` | IN SCOPE |
| Suggestion feedback loop / model retraining signal | `autonomous_intelligence` | IN SCOPE |
| Per-tenant autonomous operations policy | `autonomous_intelligence` | IN SCOPE |
| Security Graph: suggestion nodes and edges | `autonomous_intelligence` | IN SCOPE |
| EU AI Act documentation artifacts | `autonomous_intelligence` | IN SCOPE |

### Out-of-Scope (confirmed from roadmap)

| Capability | Reason |
|---|---|
| Autonomous incident response without human authorization | Explicitly excluded in roadmap §7 |
| Autonomous deployment of detection rules to production | Explicitly excluded; M36 proposes, engineer approves |
| Autonomous red team execution without M29 governance | M29 offensive governance is immutable boundary |
| General AI assistant / chatbot | Not a security operations function |
| Autonomous remediation execution | M35 executes; M36 can only suggest playbooks |

---

## Section 3: DDD Compliance Review — `autonomous_intelligence` Bounded Context

### 3.1 Aggregate Design

**Candidate aggregates from roadmap §9:**
- `IntelligenceSuggestion` — core aggregate; AI-generated recommendation
- `OptimizationModel` — versioned ML model; training + inference lifecycle
- `AutonomousOperationsPolicy` — per-tenant policy; which tasks are autonomous vs. gated

**Issues identified:**

**C1 — `IntelligenceSuggestion` lifecycle states must be explicitly modeled as an enum**
The roadmap describes a "SuggestionLifecycle" but does not enumerate all states. Without explicit lifecycle modeling, application services will contain ad-hoc string comparisons and the transition graph will be implicit.
- **Required:** `SuggestionStatus` enum: `PENDING_REVIEW | APPROVED | REJECTED | APPLIED | EXPIRED | WITHDRAWN`
- **Required:** State transition invariants enforced in domain (e.g., `APPLIED` is terminal; only `soc:security_engineer` can APPLY; only `autonomous_intelligence` service can create)

**C2 — Suggestion target type must be an enum, not a free-form string**
M36 suggests modifications to DetectionRule (M28), ScenarioTemplate (M30), and PlaybookVersion (M35). The target context and target type must be a closed enum, not an open string. Open strings allow M36 to suggest modifications to contexts not architecturally sanctioned.
- **Required:** `SuggestionTargetType` enum: `DETECTION_RULE_TUNING | CAMPAIGN_SCENARIO | PLAYBOOK_SYNTHESIS | VULNERABILITY_PRIORITY_ADJUSTMENT`
- **Required:** `autonomous_intelligence` domain service rejects any target type not in this enum at suggestion creation time

**C3 — `OptimizationModel` version lifecycle requires explicit states**
ML models have training, validation, deployment, and deprecation states. Without explicit state modeling, the domain cannot enforce that only a DEPLOYED model generates suggestions, or that model evaluation artifacts are preserved.
- **Required:** `ModelStatus` enum: `TRAINING | VALIDATING | DEPLOYED | DEPRECATED | FAILED`
- **Required:** `OptimizationModel.deploy()` only transitions from `VALIDATING`; requires accuracy metric threshold to be met

**C4 — `SuggestionEvidence` must be a value object, not a raw string**
AI suggestions must carry structured evidence: training data provenance, confidence score, model version reference, and supporting data points. A raw `rationale: str` field cannot be queried, audited, or validated by the feedback loop.
- **Required:** `SuggestionEvidence` value object with: `model_id: str`, `model_version: int`, `confidence_score: float` (0.0–1.0), `supporting_signal_refs: list[str]`, `rationale_summary: str`
- **Required:** `confidence_score >= confidence_threshold` checked at suggestion creation; configurable per `SuggestionTargetType` via `AutonomousOperationsPolicy`

**C5 — `FeedbackLoop` must be an explicit aggregate, not a property**
The roadmap describes `FeedbackLoop` as a mechanism. Without explicit domain modeling, feedback capture is an afterthought and the retraining signal cannot be queried, audited, or traced to specific suggestions.
- **Required:** `SuggestionOutcome` aggregate (append-only): records what happened to each suggestion after APPLIED — measured effectiveness (FP rate delta, campaign coverage delta, etc.)
- **Required:** `SuggestionOutcome` is written by domain services in M28/M28/M35 ACL translators (outcome events from those contexts are translated to `SuggestionOutcomeCaptured` events consumed by `autonomous_intelligence`)

### 3.2 AI Autonomy Boundary — Critical Invariant

**Severity: CRITICAL. This is the defining constraint of M36.**

From `docs/roadmap/REDFORGE_STRATEGIC_DEPENDENCIES.md` §7:

> M36 can generate, but never directly apply:
> - New `DetectionRule` versions (M28 aggregate)
> - New `ScenarioTemplate` records (M30 aggregate)
> - New `PlaybookVersion` records (M35 aggregate)

**C6 — AI Autonomy Boundary must be enforced at the domain layer, not the application layer**

If the boundary is enforced only in application services (command handlers), a future developer adding a new command handler could inadvertently violate it. The boundary must be a domain invariant.

- **Required:** `IntelligenceSuggestion` aggregate must NEVER hold a reference to a mutable aggregate from another bounded context. It holds only `SuggestionTargetRef` (a value object: `target_context: str`, `target_id: UUID`, `target_type: SuggestionTargetType`).
- **Required:** `autonomous_intelligence` domain contains NO import from `detection`, `campaign`, `playbook`, or any other bounded context's domain layer.
- **Required:** Architecture test `test_no_cross_context_domain_import_in_autonomous_intelligence.py` enforces at CI time.
- **Required:** `SuggestionProposedForApplication` domain event is the ONLY mechanism by which a suggestion reaches another context — it carries a `SuggestionProposal` value object, not a mutable aggregate reference. The receiving context's application service creates its own aggregate from the proposal.

### 3.3 LLM Tenant Isolation — Critical Security Requirement

From `docs/roadmap/REDFORGE_STRATEGIC_DEPENDENCIES.md` §8 (Risk 2):

> M36 must enforce that each LLM inference call operates only on data scoped to a single tenant. Multi-tenant LLM batching is prohibited.

**C7 — `ILLMInferencePort` must enforce tenant scoping at the port interface level**
If tenant isolation is left to call-site discipline, any single call-site mistake causes cross-tenant leakage.

- **Required:** `ILLMInferencePort.generate(prompt: LLMPrompt, tenant_id: TenantId) -> LLMResponse`
- **Required:** `LLMPrompt` value object carries `tenant_id: TenantId` as a non-nullable field
- **Required:** `LLMPrompt.context_documents` list MUST be pre-filtered to the specified `tenant_id` before construction; the port implementation validates that all documents carry matching `tenant_id`
- **Required:** Architecture test verifies that `ILLMInferencePort.generate()` is never called without `tenant_id` parameter

---

## Section 4: DDD Compliance Review — `posture_forecasting` Bounded Context

### 4.1 Aggregate Design

**C8 — `PostureForecast` must record its input snapshot to enable retrospective accuracy measurement**

A forecast is only useful if its accuracy can be measured. Without capturing the input state (current exposure score, remediation velocity) at forecast time, the roadmap success criterion (30-day forecast within 20% of actual outcome) cannot be measured.

- **Required:** `PostureForecast` aggregate carries: `input_snapshot: ForecastInputSnapshot` (value object: `baseline_exposure_score: float`, `remediation_velocity_per_day: float`, `open_critical_count: int`, `snapshot_at: datetime`)
- **Required:** `ForecastAccuracyRecord` (append-only entity within `PostureForecast`): written 30/60/90 days after forecast generation with actual vs. predicted score

---

## Section 5: DDD Compliance Review — `threat_hunt` Bounded Context

### 5.1 Aggregate Design

**C9 — `ThreatHuntCandidate` must have explicit evidence traceability to anomaly signals**

A detection rule candidate without evidence traceability cannot be reviewed by a detection engineer. The engineer needs to understand what anomaly pattern the rule targets.

- **Required:** `ThreatHuntCandidate` aggregate carries: `anomaly_signal_refs: list[AnomalySignalRef]` (value objects referencing M33 anomaly records), `technique_coverage: list[AttckTechniqueRef]` (ATT&CK technique references), `detection_logic_draft: str` (proposed rule logic in detection context's DSL), `confidence_score: float`
- **Required:** Candidate moves through: `CANDIDATE | UNDER_REVIEW | ACCEPTED | REJECTED | PROMOTED`; `PROMOTED` means the detection engineer created a new `DetectionRule` version (M28) using this candidate as input

---

## Section 6: Cross-Context Integration Review

### 6.1 ACL Translator Requirements

M36 consumes events from 5 external contexts and produces proposals consumed by 3 external contexts. Each crossing requires an ACL translator.

**Inbound (events consumed by M36):**

| Source Context | Event | M36 Internal Type | Translator |
|---|---|---|---|
| M33 (analytics/ml_pipeline) | `MLModelTrainingCompleted` | `ModelTrainingSignal` | `m33_ml_signal_translator.py` |
| M33 (analytics) | `AnomalySignalDetected` | `AnomalySignalRef` | `m33_anomaly_translator.py` |
| M28 (detection) | `DetectionRulePerformanceReported` | `DetectionPerformanceSignal` | `m28_performance_translator.py` |
| M34 (incident) | `IncidentLessonsLearned` (from M34 `lessons_learned`) | `IncidentPatternSignal` | `m34_lesson_translator.py` |
| M32 (exposure) | `ExposureScoreUpdated` | `ExposureTrendSignal` | `m32_exposure_translator.py` |

**Outbound (proposals published by M36):**

**C10 — Outbound proposals must be consumed asynchronously; M36 must not call M28/M30/M35 synchronously**

Synchronous cross-context calls couple M36's availability to M28/M30/M35's availability. If M28 is unavailable, M36 suggestion creation would fail.

- **Required:** `SuggestionProposedForApplication` event published to event bus when a suggestion reaches `APPROVED` status
- **Required:** Each target context (M28, M30, M35) has its own ACL subscriber that receives the proposal and creates a work item in that context's domain (a `PendingRuleTuningProposal` in M28, a `PendingScenarioProposal` in M30, a `PendingPlaybookSynthesisProposal` in M35)
- **Required:** M36 has NO synchronous dependency on M28, M30, or M35 at runtime

---

## Section 7: Security Graph Extension Review

**From roadmap §11:**
- `IntelligenceSuggestionNode` (linked to target node it suggests modifying)
- `OptimizationModelNode` (linked to training data sources)
- Edges: `SUGGESTED_MODIFICATION`, `APPROVED_SUGGESTION`, `OUTCOME_FEEDBACK`

**Review result:** Extensions are well-specified. `autonomous_intelligence` owns all M36 graph writes. Graph write idempotency must use stable `suggestion_id` and `model_id` as stable node identifiers. No cross-context node ownership violations identified.

---

## Section 8: Migration Boundary Review

Current head: `0130`. M36 migrations begin at `0131`.

**Estimated migration range:** `0131–0149` (19 migrations):
- `0131–0137`: `autonomous_intelligence` schema (7 tables)
- `0138–0142`: `posture_forecasting` schema (5 tables)
- `0143–0146`: `threat_hunt` schema (4 tables)
- `0147–0148`: Security Graph M36 extensions (2 tables)
- `0149`: Analytics projection for M36 events (1 table)

---

## Section 9: Compliance Review — EU AI Act

M36's optimization models are high-risk AI systems under EU AI Act Article 6 (they affect security control decisions). Compliance requires:
- Documented conformity assessment per model
- Human oversight (suggestion-plus-human-review model satisfies this)
- Transparency (suggestion rationale, model version, confidence score — all captured in `SuggestionEvidence`)
- Accuracy and robustness monitoring (FeedbackLoop → SuggestionOutcome → retraining signal)

Architecture satisfies EU AI Act structural requirements when conditions C4 and C5 are resolved.

---

## Section 10: Issue Register

| Issue | Severity | Condition | Section |
|---|---|---|---|
| `SuggestionStatus` lifecycle enum required | HIGH | C1 | §3.1 |
| `SuggestionTargetType` closed enum required | HIGH | C2 | §3.1 |
| `ModelStatus` lifecycle enum required | MEDIUM | C3 | §3.1 |
| `SuggestionEvidence` value object required | HIGH | C4 | §3.1 |
| `SuggestionOutcome` aggregate required | HIGH | C5 | §3.1 |
| AI autonomy boundary — domain-layer enforcement | CRITICAL | C6 | §3.2 |
| `ILLMInferencePort` tenant isolation at interface | CRITICAL | C7 | §3.3 |
| `PostureForecast` input snapshot + accuracy tracking | MEDIUM | C8 | §4.1 |
| `ThreatHuntCandidate` evidence traceability | MEDIUM | C9 | §5.1 |
| Outbound proposals via event bus, not sync calls | HIGH | C10 | §6.1 |

---

## Section 11: Verdict

**APPROVED WITH CONDITIONS C1–C10.**

All conditions are resolvable in architecture finalization. No condition requires scope change. The AI autonomy boundary (C6) and LLM tenant isolation (C7) are CRITICAL and must be frozen before any implementation begins. Conditions C1–C5, C8–C10 are HIGH/MEDIUM and are resolved in the Architecture Finalization document.

M36 Architecture Review Complete.
