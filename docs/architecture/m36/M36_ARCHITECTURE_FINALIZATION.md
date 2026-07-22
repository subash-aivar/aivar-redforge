# M36 Architecture Finalization
## Enterprise AI-Native Autonomous Security Operations

**Date:** 2026-07-22
**Status:** FROZEN — All C1–C10 conditions resolved
**Migration Head (input):** `0130`
**Migration Head (M36 output):** `0149`

---

## Section 1: Condition Resolutions

### C1 — SuggestionStatus Lifecycle (RESOLVED)

**Decision:** `SuggestionStatus` enum frozen as:

```python
class SuggestionStatus(str, Enum):
    PENDING_REVIEW = "pending_review"
    APPROVED       = "approved"
    REJECTED       = "rejected"
    APPLIED        = "applied"    # terminal: suggestion consumed by target context
    EXPIRED        = "expired"    # terminal: TTL elapsed before review
    WITHDRAWN      = "withdrawn"  # terminal: retracted by autonomous_intelligence (model retrained)
```

**Permitted transitions:**
- `PENDING_REVIEW → APPROVED` (by authorized reviewer)
- `PENDING_REVIEW → REJECTED` (by authorized reviewer)
- `PENDING_REVIEW → EXPIRED` (by system after `review_deadline_at` passes)
- `PENDING_REVIEW → WITHDRAWN` (by `autonomous_intelligence` service on model retrain)
- `APPROVED → APPLIED` (by authorized actor when target context accepts proposal)
- `APPROVED → WITHDRAWN` (by `autonomous_intelligence` service)
- All other transitions raise `InvalidSuggestionTransition`

**Review roles by target type:**

| `SuggestionTargetType` | Minimum reviewer role |
|---|---|
| `DETECTION_RULE_TUNING` | `soc:detection_engineer` |
| `CAMPAIGN_SCENARIO` | `red_team:architect` |
| `PLAYBOOK_SYNTHESIS` | `soc:security_engineer` |
| `VULNERABILITY_PRIORITY_ADJUSTMENT` | `vuln:manager` |

---

### C2 — SuggestionTargetType Closed Enum (RESOLVED)

**Decision:** `SuggestionTargetType` enum frozen as:

```python
class SuggestionTargetType(str, Enum):
    DETECTION_RULE_TUNING             = "detection_rule_tuning"
    CAMPAIGN_SCENARIO                 = "campaign_scenario"
    PLAYBOOK_SYNTHESIS                = "playbook_synthesis"
    VULNERABILITY_PRIORITY_ADJUSTMENT = "vulnerability_priority_adjustment"
```

This enum is the ONLY mechanism by which M36 identifies what it is suggesting. `autonomous_intelligence` application service rejects any `SuggestionTargetType` not in this enum at suggestion creation. Adding a new target type requires an ADR.

---

### C3 — ModelStatus Lifecycle (RESOLVED)

**Decision:** `ModelStatus` enum frozen as:

```python
class ModelStatus(str, Enum):
    TRAINING    = "training"
    VALIDATING  = "validating"
    DEPLOYED    = "deployed"
    DEPRECATED  = "deprecated"
    FAILED      = "failed"
```

**Permitted transitions:**
- `TRAINING → VALIDATING` (training job completed)
- `TRAINING → FAILED` (training job failed)
- `VALIDATING → DEPLOYED` (accuracy threshold met; requires explicit `deploy()` call)
- `VALIDATING → FAILED` (accuracy below threshold)
- `DEPLOYED → DEPRECATED` (superseded by newer version)
- `DEPRECATED` and `FAILED` are terminal

**Accuracy threshold enforcement (frozen):**

| Optimization task | Minimum accuracy for DEPLOYED |
|---|---|
| Detection rule tuning | `precision >= 0.75` AND `recall >= 0.70` |
| Campaign scenario suggestion | `relevance_score >= 0.65` |
| Playbook synthesis | `structure_score >= 0.70` |
| Vulnerability prioritization | `rank_correlation >= 0.60` |

---

### C4 — SuggestionEvidence Value Object (RESOLVED)

**Decision:** `SuggestionEvidence` frozen as a value object:

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionEvidence:
    model_id: str
    model_version: int
    confidence_score: float          # 0.0–1.0; validated: 0.0 <= x <= 1.0
    supporting_signal_refs: tuple[str, ...]   # references to M33 records
    rationale_summary: str           # max 2000 chars; plain text, no PII
    generated_at: datetime
```

**Confidence threshold policy (frozen per target type):**

| `SuggestionTargetType` | Default `min_confidence` | Configurable per tenant? |
|---|---|---|
| `DETECTION_RULE_TUNING` | 0.75 | Yes (min floor: 0.60) |
| `CAMPAIGN_SCENARIO` | 0.65 | Yes (min floor: 0.55) |
| `PLAYBOOK_SYNTHESIS` | 0.70 | Yes (min floor: 0.60) |
| `VULNERABILITY_PRIORITY_ADJUSTMENT` | 0.60 | Yes (min floor: 0.50) |

Suggestions with `confidence_score < min_confidence` are rejected at domain service level, never written to `intelligence_suggestions` table.

---

### C5 — SuggestionOutcome Aggregate (RESOLVED)

**Decision:** `SuggestionOutcome` is an append-only aggregate in `autonomous_intelligence`:

```python
# autonomous_intelligence/domain/aggregates/suggestion_outcome.py
class SuggestionOutcome:
    __slots__ = (...)
    suggestion_id: UUID
    tenant_id: TenantId
    target_type: SuggestionTargetType
    outcome_type: OutcomeType         # MEASURABLE | NOT_APPLICABLE | PENDING
    measurement_window_days: int      # 30, 60, or 90
    baseline_metric: float            # e.g., FP rate before suggestion applied
    observed_metric: float | None     # metric after measurement window
    delta: float | None               # observed - baseline
    measured_at: datetime | None
    # No update() or delete() methods — append-only
```

`OutcomeType` enum: `MEASURABLE | NOT_APPLICABLE | PENDING`

`SuggestionOutcomeCaptured` domain event is published when `observed_metric` is first recorded. This event is the retraining signal consumed by `OptimizationModel.record_feedback()`.

---

### C6 — AI Autonomy Boundary (RESOLVED — CRITICAL)

**Decision: The AI autonomy boundary is a domain invariant, not an application-layer policy.**

**Frozen contract:**

1. `IntelligenceSuggestion` aggregate contains ONLY `SuggestionTargetRef` (value object):
   ```python
   @dataclass(frozen=True, slots=True, kw_only=True)
   class SuggestionTargetRef:
       target_context: str          # e.g., "detection", "campaign", "playbook"
       target_id: UUID              # ID of the existing record to modify (or None for create)
       target_type: SuggestionTargetType
       proposed_change_payload: dict[str, object]   # opaque; interpreted by target context ACL
   ```

2. `autonomous_intelligence` domain layer contains **zero imports** from `detection`, `campaign`, `playbook`, `vulnerability`, or any other bounded context domain. Enforced by `test_no_cross_context_domain_import_in_autonomous_intelligence.py`.

3. `SuggestionProposedForApplication` event is the ONLY mechanism for cross-context suggestion propagation. It carries `SuggestionProposal` (value object) — not a mutable aggregate reference.

4. When an engineer in the target context accepts a proposal and creates the target aggregate (new `RuleVersion`, new `ScenarioTemplate`, new `PlaybookVersion`), THAT context publishes its own domain event. M36 subscribes to that event via ACL translator to transition the suggestion to `APPLIED`.

5. `autonomous_intelligence` application service enforces: **any command that would directly mutate a DetectionRule, ScenarioTemplate, or PlaybookVersion raises `AutonBoundaryViolation`** — a domain exception that cannot be caught at application layer.

---

### C7 — ILLMInferencePort Tenant Isolation (RESOLVED — CRITICAL)

**Decision:** LLM tenant isolation enforced at the port interface level:

```python
# autonomous_intelligence/application/ports/i_llm_inference_port.py
class ILLMInferencePort(Protocol):
    def generate(
        self,
        prompt: LLMPrompt,
        tenant_id: TenantId,    # non-nullable; port validates all context docs match this tenant
    ) -> LLMResponse: ...
```

**`LLMPrompt` value object:**
```python
@dataclass(frozen=True, slots=True, kw_only=True)
class LLMPrompt:
    tenant_id: TenantId          # validated non-null at construction
    system_instruction: str
    context_documents: tuple[TenantScopedDocument, ...]   # each carries tenant_id
    task_instruction: str
    max_tokens: int

@dataclass(frozen=True, slots=True, kw_only=True)
class TenantScopedDocument:
    tenant_id: TenantId   # must match LLMPrompt.tenant_id; validated at LLMPrompt construction
    content: str
    source_ref: str
```

**Invariant enforced in `LLMPrompt.__post_init__`:** All `context_documents[i].tenant_id == self.tenant_id`. Raises `TenantIsolationViolation` if any document has a mismatched tenant.

**Multi-tenant batching is prohibited:** No implementation of `ILLMInferencePort` may batch prompts across tenants in a single API call. Architecture test enforces this at the port contract level.

---

### C8 — PostureForecast Input Snapshot and Accuracy Tracking (RESOLVED)

**Decision:**

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class ForecastInputSnapshot:
    baseline_exposure_score: float
    remediation_velocity_per_day: float    # average remediations per day over trailing 30 days
    open_critical_count: int
    open_high_count: int
    snapshot_at: datetime
    tenant_id: TenantId

class PostureForecast:
    __slots__ = (...)
    forecast_id: UUID
    tenant_id: TenantId
    input_snapshot: ForecastInputSnapshot
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float
    model_id: str
    model_version: int
    generated_at: datetime
    accuracy_records: list[ForecastAccuracyRecord]   # appended at T+30, T+60, T+90
```

`ForecastAccuracyRecord` entity: `horizon_days: int`, `actual_score: float`, `predicted_score: float`, `absolute_error: float`, `recorded_at: datetime`. Written by `PostureForecastAccuracyWorker` that runs daily.

---

### C9 — ThreatHuntCandidate Evidence Traceability (RESOLVED)

**Decision:**

```python
class ThreatHuntCandidate:
    __slots__ = (...)
    candidate_id: UUID
    tenant_id: TenantId
    anomaly_signal_refs: tuple[AnomalySignalRef, ...]   # M33 anomaly record references
    technique_coverage: tuple[AttckTechniqueRef, ...]   # ATT&CK technique IDs
    detection_logic_draft: str    # proposed rule logic; provided as reference to detection engineer
    detection_rule_format: DetectionRuleFormat   # SIGMA | KQL | SPL (enum)
    confidence_score: float
    candidate_status: ThreatHuntCandidateStatus   # CANDIDATE|UNDER_REVIEW|ACCEPTED|REJECTED|PROMOTED
    promoted_rule_version_id: UUID | None   # set when PROMOTED; reference to M28 rule version
    review_notes: str | None
    generated_at: datetime
    reviewed_at: datetime | None
    reviewed_by: str | None
```

`PROMOTED` transition records `promoted_rule_version_id` and publishes `ThreatHuntCandidatePromoted` event. This event is consumed by the Security Graph worker to create the `GENERATED_DETECTION` edge.

---

### C10 — Outbound Proposals via Event Bus (RESOLVED)

**Decision:** `autonomous_intelligence` publishes `SuggestionProposedForApplication` to event bus. Target contexts have dedicated ACL subscribers:

| Target Context | ACL Subscriber | Internal Work Item Created |
|---|---|---|
| `detection` (M28) | `m36_rule_tuning_proposal_subscriber.py` | `PendingRuleTuningItem` (new domain entity) |
| `campaign` (M30) | `m36_scenario_proposal_subscriber.py` | `PendingScenarioItem` (new domain entity) |
| `playbook` (M35) | `m36_playbook_synthesis_subscriber.py` | `PendingSynthesisItem` (new domain entity) |

These work items are surfaced in each context's human review UI. Engineers in each context see their own queue of pending AI proposals without any coupling to `autonomous_intelligence` internals.

---

## Section 2: Frozen DDD Model — `autonomous_intelligence`

### Aggregates

| Aggregate | Role | Invariants |
|---|---|---|
| `IntelligenceSuggestion` | Core: AI suggestion lifecycle | Status state machine; confidence threshold gate; no direct cross-context mutation |
| `OptimizationModel` | Core: ML model version lifecycle | Deploy requires accuracy threshold; DEPLOYED → DEPRECATED only; immutable training lineage |
| `AutonomousOperationsPolicy` | Core: per-tenant autonomy policy | One per tenant; kill switch; confidence thresholds; per-suggestion-type review gates |
| `SuggestionOutcome` | Supporting: feedback signal | Append-only; written by ACL translators receiving outcome events from target contexts |

### Domain Services

| Service | Responsibility |
|---|---|
| `SuggestionGenerationService` | Orchestrates LLM inference + evidence assembly; enforces confidence threshold; creates `IntelligenceSuggestion` aggregate |
| `SuggestionReviewService` | Validates reviewer role; enforces state transitions; emits `SuggestionProposedForApplication` on APPROVED → APPLIED transition |
| `AutonomyBoundaryService` | Guards the autonomy boundary; raises `AutonBoundaryViolation` on any prohibited direct mutation |
| `FeedbackIngestionService` | Receives `SuggestionOutcomeCaptured` events; routes to correct `OptimizationModel.record_feedback()` call |
| `ModelGovernanceService` | Manages model training triggers; accuracy validation; version promotion and deprecation |

### Repository Interfaces (Ports — append-only where noted)

```python
class IIntelligenceSuggestionRepository(Protocol):
    def save(self, suggestion: IntelligenceSuggestion, tenant_id: TenantId) -> None: ...
    def find_by_id(self, suggestion_id: UUID, tenant_id: TenantId) -> IntelligenceSuggestion | None: ...
    def find_pending_review(self, tenant_id: TenantId, target_type: SuggestionTargetType | None, limit: int) -> list[IntelligenceSuggestion]: ...
    def find_approved_pending_application(self, tenant_id: TenantId) -> list[IntelligenceSuggestion]: ...
    def find_expired_pending(self, cutoff: datetime) -> list[IntelligenceSuggestion]: ...
    # No update() or delete() — all mutations via aggregate methods + re-save

class IOptimizationModelRepository(Protocol):
    def save(self, model: OptimizationModel, tenant_id: TenantId) -> None: ...
    def find_deployed(self, tenant_id: TenantId, target_type: SuggestionTargetType) -> OptimizationModel | None: ...
    def find_by_id(self, model_id: str, tenant_id: TenantId) -> OptimizationModel | None: ...

class ISuggestionOutcomeRepository(Protocol):
    def append(self, outcome: SuggestionOutcome) -> None: ...   # append-only
    def find_for_suggestion(self, suggestion_id: UUID, tenant_id: TenantId) -> list[SuggestionOutcome]: ...
    def find_pending_measurement(self, cutoff: datetime, tenant_id: TenantId) -> list[SuggestionOutcome]: ...
```

---

## Section 3: Frozen DDD Model — `posture_forecasting`

### Aggregates

| Aggregate | Role |
|---|---|
| `PostureForecast` | Per-tenant trajectory prediction with input snapshot and accuracy tracking |
| `ForecastConfiguration` | Per-tenant forecast configuration: which signal sources to weight, forecast frequency |

### Domain Services

| Service | Responsibility |
|---|---|
| `ForecastGenerationService` | Pulls exposure trend data (via M32 ACL); runs forecast model; creates `PostureForecast` |
| `ForecastAccuracyService` | Nightly: compares T+30/60/90 actual exposure scores vs. predictions; appends `ForecastAccuracyRecord` |

### Repository Interfaces

```python
class IPostureForecastRepository(Protocol):
    def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None: ...
    def find_latest(self, tenant_id: TenantId) -> PostureForecast | None: ...
    def find_pending_accuracy_check(self, horizon_days: int, cutoff: datetime) -> list[PostureForecast]: ...
```

---

## Section 4: Frozen DDD Model — `threat_hunt`

### Aggregates

| Aggregate | Role |
|---|---|
| `ThreatHuntCandidate` | AI-generated detection rule candidate from anomaly signals |
| `ThreatHuntConfiguration` | Per-tenant: which anomaly signal types trigger candidate generation, minimum signal strength |

### Domain Services

| Service | Responsibility |
|---|---|
| `CandidateGenerationService` | Receives anomaly signal refs from M33 ACL; invokes LLM via `ILLMInferencePort`; creates `ThreatHuntCandidate` |
| `CandidateReviewService` | Validates reviewer role (`soc:detection_engineer`); manages status transitions; records promotion |

### Repository Interfaces

```python
class IThreatHuntCandidateRepository(Protocol):
    def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None: ...
    def find_pending_review(self, tenant_id: TenantId, limit: int) -> list[ThreatHuntCandidate]: ...
    def find_by_id(self, candidate_id: UUID, tenant_id: TenantId) -> ThreatHuntCandidate | None: ...
```

---

## Section 5: Frozen Event Contracts

All domain events: `frozen=True, slots=True, kw_only=True`. Published via `EventPublisher` protocol.

### `autonomous_intelligence` Events

| Event | Trigger | Key Fields |
|---|---|---|
| `SuggestionCreated` | New suggestion persisted | `suggestion_id`, `tenant_id`, `target_type`, `confidence_score`, `model_id` |
| `SuggestionApproved` | Reviewer approves | `suggestion_id`, `tenant_id`, `approved_by`, `target_type` |
| `SuggestionRejected` | Reviewer rejects | `suggestion_id`, `tenant_id`, `rejected_by`, `rejection_reason` |
| `SuggestionProposedForApplication` | Approved → ready for target context | `suggestion_id`, `tenant_id`, `target_type`, `target_ref: SuggestionTargetRef`, `proposal_payload: dict` |
| `SuggestionApplied` | Target context confirmed acceptance | `suggestion_id`, `tenant_id`, `applied_at`, `target_context_ref` |
| `SuggestionExpired` | TTL elapsed without review | `suggestion_id`, `tenant_id`, `expired_at` |
| `SuggestionWithdrawn` | Model retrained; suggestion stale | `suggestion_id`, `tenant_id`, `withdrawn_at`, `reason` |
| `SuggestionOutcomeCaptured` | Outcome measured in target context | `suggestion_id`, `tenant_id`, `delta`, `horizon_days`, `target_type` |
| `ModelDeployed` | Model passes accuracy threshold | `model_id`, `tenant_id`, `target_type`, `model_version`, `accuracy_metrics` |
| `ModelDeprecated` | Superseded by new version | `model_id`, `tenant_id`, `superseded_by_version` |

### `posture_forecasting` Events

| Event | Trigger | Key Fields |
|---|---|---|
| `PostureForecastGenerated` | Nightly batch | `forecast_id`, `tenant_id`, `predicted_30d`, `predicted_60d`, `predicted_90d` |
| `ForecastAccuracyRecorded` | T+30/60/90 accuracy check | `forecast_id`, `tenant_id`, `horizon_days`, `absolute_error` |

### `threat_hunt` Events

| Event | Trigger | Key Fields |
|---|---|---|
| `ThreatHuntCandidateGenerated` | Anomaly signal processed | `candidate_id`, `tenant_id`, `technique_coverage`, `confidence_score` |
| `ThreatHuntCandidatePromoted` | Detection engineer promotes | `candidate_id`, `tenant_id`, `promoted_rule_version_id`, `promoted_by` |
| `ThreatHuntCandidateRejected` | Reviewer rejects | `candidate_id`, `tenant_id`, `rejected_by`, `rejection_reason` |

---

## Section 6: Frozen Command and Query Model

### Commands

| Command | Handler Context | Effect |
|---|---|---|
| `CreateIntelligenceSuggestion` | `autonomous_intelligence` | Validates confidence; creates `IntelligenceSuggestion` in `PENDING_REVIEW`; emits `SuggestionCreated` |
| `ApproveSuggestion` | `autonomous_intelligence` | Validates reviewer role; transitions to `APPROVED`; emits `SuggestionApproved` |
| `RejectSuggestion` | `autonomous_intelligence` | Validates reviewer role; transitions to `REJECTED`; emits `SuggestionRejected` |
| `MarkSuggestionApplied` | `autonomous_intelligence` | Called by ACL subscriber when target context confirms; transitions to `APPLIED`; emits `SuggestionApplied` |
| `TrainOptimizationModel` | `autonomous_intelligence` | Triggers async training job; creates model in `TRAINING` status |
| `DeployOptimizationModel` | `autonomous_intelligence` | Validates accuracy threshold; transitions to `DEPLOYED`; deprecates prior version |
| `GeneratePostureForecast` | `posture_forecasting` | Batch command run nightly; creates `PostureForecast` aggregate |
| `RecordForecastAccuracy` | `posture_forecasting` | Appends `ForecastAccuracyRecord` to forecast |
| `GenerateThreatHuntCandidate` | `threat_hunt` | Processes anomaly signal; invokes LLM; creates `ThreatHuntCandidate` |
| `PromoteThreatHuntCandidate` | `threat_hunt` | Detection engineer promotes; records `promoted_rule_version_id` |

### Queries (read models — no aggregate side effects)

| Query | Returns |
|---|---|
| `GetSuggestionQueue` | `SuggestionQueueReadModel` — pending suggestions by target type for reviewer |
| `GetSuggestionAcceptanceRate` | `AcceptanceRateReadModel` — approval rate trend by target type and model |
| `GetModelAccuracyDashboard` | `ModelAccuracyReadModel` — accuracy metrics by model and target type |
| `GetPostureForecastView` | `PostureForecastReadModel` — 30/60/90-day trajectory for tenant |
| `GetThreatHuntCandidateQueue` | `ThreatHuntQueueReadModel` — pending candidates for detection engineer review |
| `GetAutonomousOperationsPolicyView` | `PolicyReadModel` — which tasks autonomous vs. gated for tenant |

---

## Section 7: Frozen Read Models

### SuggestionQueueReadModel
Fields: `suggestion_id`, `target_type`, `confidence_score`, `rationale_summary`, `target_context`, `target_id`, `model_id`, `model_version`, `created_at`, `review_deadline_at`

### AcceptanceRateReadModel
Fields: `target_type`, `total_suggestions`, `approved`, `rejected`, `expired`, `acceptance_rate_pct`, `trailing_30d_trend`

### ModelAccuracyReadModel
Fields: `model_id`, `target_type`, `model_version`, `status`, `deployed_at`, `precision`, `recall`, `rank_correlation`, `feedback_sample_count`, `accuracy_trend`

### PostureForecastReadModel
Fields: `forecast_id`, `generated_at`, `baseline_exposure_score`, `predicted_30d`, `predicted_60d`, `predicted_90d`, `remediation_velocity`, `last_30d_accuracy_error`, `last_60d_accuracy_error`

### ThreatHuntQueueReadModel
Fields: `candidate_id`, `technique_coverage`, `confidence_score`, `detection_rule_format`, `detection_logic_draft` (first 500 chars), `anomaly_signal_count`, `generated_at`

---

## Section 8: Frozen Migration Plan

All migrations in `backend/src/redforge/infrastructure/database/migrations/versions/`. Each has `upgrade()` and `downgrade()`. Linear chain: each `down_revision` points to its predecessor.

| Migration | `down_revision` | Schema | Tables/Objects Created |
|---|---|---|---|
| `0131_autonomous_intelligence_schema.py` | `0130` | `autonomous_intelligence` | CREATE SCHEMA |
| `0132_optimization_models.py` | `0131` | `autonomous_intelligence` | `optimization_models` |
| `0133_intelligence_suggestions.py` | `0132` | `autonomous_intelligence` | `intelligence_suggestions` |
| `0134_suggestion_outcomes.py` | `0133` | `autonomous_intelligence` | `suggestion_outcomes` |
| `0135_autonomous_operations_policies.py` | `0134` | `autonomous_intelligence` | `autonomous_operations_policies` |
| `0136_llm_inference_audit_log.py` | `0135` | `autonomous_intelligence` | `llm_inference_audit_log` |
| `0137_model_training_jobs.py` | `0136` | `autonomous_intelligence` | `model_training_jobs` |
| `0138_posture_forecasting_schema.py` | `0137` | `posture_forecasting` | CREATE SCHEMA |
| `0139_posture_forecasts.py` | `0138` | `posture_forecasting` | `posture_forecasts` |
| `0140_forecast_accuracy_records.py` | `0139` | `posture_forecasting` | `forecast_accuracy_records` |
| `0141_forecast_configurations.py` | `0140` | `posture_forecasting` | `forecast_configurations` |
| `0142_posture_forecast_input_snapshots.py` | `0141` | `posture_forecasting` | `forecast_input_snapshots` |
| `0143_threat_hunt_schema.py` | `0142` | `threat_hunt` | CREATE SCHEMA |
| `0144_threat_hunt_candidates.py` | `0143` | `threat_hunt` | `threat_hunt_candidates` |
| `0145_threat_hunt_anomaly_signal_refs.py` | `0144` | `threat_hunt` | `threat_hunt_anomaly_signal_refs` |
| `0146_threat_hunt_configurations.py` | `0145` | `threat_hunt` | `threat_hunt_configurations` |
| `0147_threat_hunt_technique_refs.py` | `0146` | `threat_hunt` | `threat_hunt_technique_refs` |
| `0148_security_graph_m36_nodes.py` | `0147` | `security_graph` | Extend SG: `IntelligenceSuggestionNode`, `OptimizationModelNode`; edges: `SUGGESTED_MODIFICATION`, `APPROVED_SUGGESTION`, `OUTCOME_FEEDBACK`, `GENERATED_DETECTION` |
| `0149_m36_analytics_projection.py` | `0148` | `analytics` | `m36_suggestion_metrics` projection table |

**Terminal head:** `0149` (no migration has `down_revision = "0149"`).

---

## Section 9: Frozen Worker Specifications

| Worker | Context | Trigger | Responsibility |
|---|---|---|---|
| `SuggestionGenerationWorker` | `autonomous_intelligence` | Event-driven: M33/M28/M34/M32 ACL events | Generates new `IntelligenceSuggestion` when sufficient signal arrives |
| `SuggestionExpiryWorker` | `autonomous_intelligence` | Scheduled: every 15 min | Expires `PENDING_REVIEW` suggestions past `review_deadline_at` |
| `SuggestionApplicationWorker` | `autonomous_intelligence` | Event-driven: target context ACL confirms acceptance | Transitions `APPROVED` suggestion to `APPLIED`; emits `SuggestionApplied` |
| `OutcomeMeasurementWorker` | `autonomous_intelligence` | Scheduled: nightly | Queries M32/M28/M34 for outcome metrics; writes `SuggestionOutcome`; triggers model feedback |
| `ModelRetrainingWorker` | `autonomous_intelligence` | Event-driven: sufficient `SuggestionOutcome` records accumulated | Triggers M33 training job; awaits `MLModelTrainingCompleted` event |
| `PostureForecastWorker` | `posture_forecasting` | Scheduled: nightly (02:00 UTC) | Runs forecast computation; creates `PostureForecast` aggregate |
| `ForecastAccuracyWorker` | `posture_forecasting` | Scheduled: nightly | Checks T+30/60/90 windows; writes `ForecastAccuracyRecord` |
| `ThreatHuntCandidateWorker` | `threat_hunt` | Event-driven: `AnomalySignalDetected` (M33 ACL) | Generates `ThreatHuntCandidate` from anomaly signal batch |
| `M36SecurityGraphWorker` | `autonomous_intelligence` | Event-driven: all M36 domain events | Projects suggestion and model nodes/edges into Security Graph |
| `M36AnalyticsProjector` | `autonomous_intelligence` | Event-driven: all M36 domain events | Projects suggestion metrics into analytics read model |

---

## Section 10: Frozen ACL Translator Inventory

**Inbound (events → M36 internal signals):**

| File | Source Context | Translates |
|---|---|---|
| `autonomous_intelligence/infrastructure/acl/m33_ml_signal_translator.py` | ml_pipeline | `MLModelTrainingCompleted` → `ModelTrainingSignal` |
| `autonomous_intelligence/infrastructure/acl/m33_anomaly_translator.py` | analytics | `AnomalySignalDetected` → `AnomalySignalRef` |
| `autonomous_intelligence/infrastructure/acl/m28_performance_translator.py` | detection | `DetectionRulePerformanceReported` → `DetectionPerformanceSignal` |
| `autonomous_intelligence/infrastructure/acl/m34_lesson_translator.py` | lessons_learned | `IncidentLessonsLearned` → `IncidentPatternSignal` |
| `autonomous_intelligence/infrastructure/acl/m32_exposure_translator.py` | exposure | `ExposureScoreUpdated` → `ExposureTrendSignal` |
| `threat_hunt/infrastructure/acl/m33_anomaly_translator.py` | analytics | `AnomalySignalDetected` → `ThreatHuntAnomalySignal` |
| `posture_forecasting/infrastructure/acl/m32_exposure_translator.py` | exposure | `ExposureScoreUpdated` → `ForecastInputSignal` |

**Outbound (target context ACL subscribers receiving M36 proposals):**

| File | Target Context | Creates |
|---|---|---|
| `detection/infrastructure/acl/m36_rule_tuning_proposal_subscriber.py` | detection (M28) | `PendingRuleTuningItem` |
| `campaign/infrastructure/acl/m36_scenario_proposal_subscriber.py` | campaign (M30) | `PendingScenarioItem` |
| `playbook/infrastructure/acl/m36_playbook_synthesis_subscriber.py` | playbook (M35) | `PendingSynthesisItem` |

---

## Section 11: Frozen Security Graph Extensions

**Owned by:** `autonomous_intelligence` bounded context.
**Node IDs are stable:** `suggestion_id` for `IntelligenceSuggestionNode`; `model_id + "_v" + model_version` for `OptimizationModelNode`.
**Upsert pattern:** All graph writes are upsert by stable node ID.

| Node Type | Stable ID | Key Attributes |
|---|---|---|
| `IntelligenceSuggestionNode` | `suggestion_id` | `target_type`, `confidence_score`, `status`, `tenant_id` |
| `OptimizationModelNode` | `model_id + "_v" + version` | `target_type`, `status`, `precision`, `recall`, `tenant_id` |

| Edge Type | Source → Target | Semantics |
|---|---|---|
| `SUGGESTED_MODIFICATION` | `IntelligenceSuggestionNode` → existing target node | M36 proposed a modification to this existing record |
| `APPROVED_SUGGESTION` | `IntelligenceSuggestionNode` → target node | Suggestion was approved for application |
| `OUTCOME_FEEDBACK` | target node → `OptimizationModelNode` | Outcome from this record provided training feedback to this model |
| `GENERATED_DETECTION` | `ThreatHuntCandidateNode` → new detection rule node (M28) | This candidate was promoted and resulted in a new detection rule |

---

## Section 12: Forbidden Anti-Patterns

1. **No direct mutation of M28/M30/M35 aggregates from `autonomous_intelligence`** — only `SuggestionProposedForApplication` event; target context creates its own aggregate.
2. **No multi-tenant LLM batching** — each `ILLMInferencePort.generate()` call is scoped to exactly one `tenant_id`.
3. **No `LLMPrompt.context_documents` containing cross-tenant data** — enforced by `TenantScopedDocument.tenant_id` validation.
4. **No import of `detection.*`, `campaign.*`, `playbook.*` in `autonomous_intelligence.domain.*` or `autonomous_intelligence.application.*`** — architecture test enforces at CI.
5. **No `DEPLOYED` model without passing accuracy threshold** — `ModelGovernanceService.deploy()` raises `AccuracyThresholdNotMet` if below floor.
6. **No `IntelligenceSuggestion` with `confidence_score < min_confidence`** — rejected at `SuggestionGenerationService` before persistence.
7. **No `PostureForecast` without `ForecastInputSnapshot`** — value object is non-nullable on aggregate.
8. **No suggestion marked `APPLIED` by M36 directly** — only via `SuggestionApplicationWorker` receiving confirmed ACL event from target context.
9. **No plaintext security data in LLM prompts** — `TenantScopedDocument.content` must not include credential values, raw CVE exploit code, or PII.
10. **No training of `OptimizationModel` on cross-tenant aggregated data** — each model version is tenant-scoped OR explicitly documented as a multi-tenant anonymized model with CISO approval.

---

## Section 13: ADR Summary

| ADR | Title | Status |
|---|---|---|
| ADR-M36-001 | AI Autonomy Boundary — Domain Invariant Enforcement | ACCEPTED |
| ADR-M36-002 | LLM Tenant Isolation at Port Interface Level | ACCEPTED |
| ADR-M36-003 | Confidence Threshold Policy Per Suggestion Type | ACCEPTED |
| ADR-M36-004 | Suggestion Feedback Loop and Model Retraining Trigger | ACCEPTED |
| ADR-M36-005 | OptimizationModel Version Lifecycle and Accuracy Threshold | ACCEPTED |
| ADR-M36-006 | Human-in-the-Loop Governance Gate | ACCEPTED |
| ADR-M36-007 | Cross-Context Proposal Protocol via Event Bus | ACCEPTED |
| ADR-M36-008 | EU AI Act Conformity Architecture | ACCEPTED |

---

## Section 14: Five-Phase Implementation Plan

### Phase 1 — `autonomous_intelligence` Domain Foundation
**Start condition:** M36 architecture approved (this document)
**Deliverables:** `autonomous_intelligence` bounded context: aggregates, domain services, ports, events; migrations `0131–0137`
**Test target:** ≥ 90 unit tests (domain + application layer)
**Exit criteria:** All C1–C7 invariants covered by unit tests; architecture test `test_no_cross_context_domain_import_in_autonomous_intelligence.py` passing

### Phase 2 — `posture_forecasting` and `threat_hunt` Domain Foundation
**Start condition:** Phase 1 exit criteria met
**Deliverables:** Both supporting contexts; migrations `0138–0147`; `PostureForecastWorker`; `ThreatHuntCandidateWorker`
**Test target:** ≥ 50 unit tests each context; ≥ 20 integration tests
**Exit criteria:** `PostureForecast` input snapshot and accuracy tracking tested; `ThreatHuntCandidate` evidence traceability tested; LLM port tenant isolation test passing for both contexts

### Phase 3 — ACL Translators and Cross-Context Integration
**Start condition:** Phase 2 exit criteria met; M33/M28/M34/M32/M30/M35 event schemas confirmed
**Deliverables:** All 10 ACL translators (7 inbound + 3 outbound); `SuggestionGenerationWorker`; `SuggestionApplicationWorker`; full event bus wiring
**Test target:** ≥ 50 integration tests across ACL boundary; cross-tenant isolation test battery
**Exit criteria:** `test_suggestion_proposal_never_mutates_target_context_directly.py` passing; `test_llm_prompt_tenant_isolation_enforced.py` passing

### Phase 4 — Security Graph, Read Models, Analytics
**Start condition:** Phase 3 exit criteria met
**Deliverables:** Migrations `0148–0149`; `M36SecurityGraphWorker`; `M36AnalyticsProjector`; all 6 read models; all API routes
**Test target:** ≥ 40 API tests; ≥ 20 projection tests
**Exit criteria:** All read models populated in integration test environment; Security Graph nodes/edges verified for all M36 event types

### Phase 5 — Workers, Observability, EU AI Act Artifacts
**Start condition:** Phase 4 exit criteria met
**Deliverables:** `SuggestionExpiryWorker`; `OutcomeMeasurementWorker`; `ModelRetrainingWorker`; `ForecastAccuracyWorker`; EU AI Act documentation artifacts; metrics/health endpoints; runbooks
**Test target:** ≥ 30 integration tests (worker reliability, expiry, feedback loop)
**Final milestone exit:** Suggestion generation P95 latency ≤ 30 seconds for rule-tuning suggestions; posture forecast available daily; threat hunt candidate queue populated within 60 minutes of anomaly signal

---

## Readiness Verdict

**ALL CONDITIONS RESOLVED. IMPLEMENTATION APPROVED TO BEGIN AT PHASE 1.**

M36 Architecture Finalization Complete.
