# M33 Architecture Review
## Enterprise Security Analytics & Intelligence Platform

**Status:** REVIEW — PENDING APPROVAL  
**Date:** 2026-07-21  
**Reviewer:** Architecture Review Process  
**Precondition:** M32 RELEASED (2026-07-21)  
**Constraint:** Documentation only. No code, no migrations, no repository modifications.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Assessment](#2-architecture-assessment)
3. [Bounded Context Review](#3-bounded-context-review)
4. [Integration Review](#4-integration-review)
5. [Risk Assessment](#5-risk-assessment)
6. [Recommended Improvements](#6-recommended-improvements)
7. [Implementation Phase Plan](#7-implementation-phase-plan)
8. [Architecture Verdict](#8-architecture-verdict)

---

## 1. Executive Summary

M33 is the **Enterprise Security Analytics & Intelligence Platform**. Its mission is to transform the structured security data produced by M26–M32 into a cross-domain, queryable, ML-enhanced intelligence layer — making analytical questions answerable in seconds that previously required bespoke data engineering.

M33 introduces three bounded contexts:

| Context | Role | Classification |
|---|---|---|
| `analytics` | Cross-domain query engine, KPI computation, anomaly detection | Core Domain |
| `ml_pipeline` | ML model lifecycle, training, inference serving | Supporting Domain |
| `reporting` | Scheduled reports, executive narratives, BI export | Supporting Domain |

**Key observations from this review:**

1. The bounded context design is sound at the strategic level. The three contexts are well-separated by concern.
2. The `ml_pipeline` scope as described in the roadmap is architecturally overambitious for a single milestone. A scoped-down design is required.
3. The "security data lake" is under-specified. Its physical implementation must be frozen before Phase 1 begins.
4. The analytics query model requires explicit tenant isolation enforcement. This is a critical security constraint (Strategic Dependencies §8, Risk 4).
5. `ml_pipeline` cold start is acknowledged in the roadmap but not architecturally designed. The rule-based fallback path must be a first-class Phase 1 deliverable.
6. MTTR as a KPI requires M34 incident data. It must be deferred or its definition constrained to what M33 data alone can support.
7. The `reporting` context boundary relative to M32's `exposure_reporting` must be made explicit to prevent capability drift.

**Conditions for implementation approval:** Seven conditions (C1–C7) are identified below. All must be resolved in the Architecture Finalization document before Phase 1 begins.

---

## 2. Architecture Assessment

### 2.1 Domain-Driven Design Assessment

**Context Isolation:** All three M33 contexts are internally coherent and correctly separated by domain concern:
- `analytics` = query, KPI, anomaly — operational measurement
- `ml_pipeline` = model lifecycle — AI/ML operational concerns
- `reporting` = report generation, delivery, BI export — external publication

**Domain Purity (Platform Invariant 1):** This is the most critical invariant for M33. Analytics is inherently a cross-domain capability, which creates an unavoidable tension: M33 needs data from all prior bounded contexts but must not import their domain types.

Resolution: M33 must consume upstream events exclusively via the platform event bus. All upstream types are translated to M33-internal types at ACL adapters before entering any M33 aggregate or service. The `analytics` bounded context owns a set of projection tables that are populated from upstream events — it never queries upstream operational databases directly.

This follows the identical pattern used by the Security Graph: append-only event consumption, idempotent projection, never a live cross-context database query.

**Multi-Tenancy (Platform Invariant 2):** Analytics is the highest-risk context for cross-tenant data leakage. The Strategic Dependencies document (§8, Risk 4) explicitly calls this out: "a single M33 analytics query can traverse data from all tenants if tenant filtering is not enforced at the query layer." This is addressed in the design: `TenantId` is a required, non-nullable, non-optional first argument on every analytics query, KPI computation, and report generation. Enforcement must be at the application service layer, not the API layer.

**Aggregate Design:** The roadmap provides a partial aggregate list. The full aggregate model is designed in §3 of this review.

**CQRS:** M33 is a read-heavy context (queries vastly outnumber writes). CQRS is the natural model:
- Command side: `RegisterAnalyticsDataSet`, `DefineSecurityKPI`, `TrainMLModel`, `GenerateReport`
- Query side: all analytics queries, KPI reads, report retrieval — served from pre-computed projection tables, never from command-side aggregates

**Repository Ownership:** Each aggregate has exactly one repository interface, owned by its bounded context. No repository interface spans contexts.

### 2.2 OLTP/OLAP Separation

The roadmap explicitly states: "Separation of operational (OLTP) and analytical (OLAP) data stores is critical; analytics must never query operational databases directly."

This review identifies two viable implementation options:

**Option A — Dedicated Analytics Schema (PostgreSQL):**
- M33 maintains its own analytics projection tables in a dedicated PostgreSQL schema (`analytics_schema`)
- Upstream events are consumed and projected into these tables via the platform's `IdempotentProjectionEngine`
- All M33 queries operate against these local projection tables
- Optional cloud backends (BigQuery, Redshift) are port implementations, not the primary implementation

**Option B — Shared Event Store Read (PostgreSQL):**
- M33 reads directly from the platform `event_store` table
- Filters by event type and tenant_id

**Recommendation: Option A is required.** Option B violates the OLTP/OLAP separation principle. The `event_store` is an operational table; analytics queries against it will degrade operational performance. Option A's projection tables provide query independence, index optimization, and data reshaping for analytics workloads.

This is **Condition C1** — the data lake physical design must be frozen before Phase 1.

### 2.3 ML Pipeline Scope Assessment

The roadmap describes `ml_pipeline` as "model training, deployment, and inference serving." As written, this is a full ML engineering platform — a multi-team, multi-quarter build. Within M33, the `ml_pipeline` scope must be:

**Phase 1-3 (M33):** In-process statistical models using Python's standard scientific stack (numpy, scipy, optionally scikit-learn). Models are:
- Trained as a background worker job against M33's analytics projection tables
- Serialized as model artifacts stored in PostgreSQL (BYTEA column or `analytics_model_artifacts` table)
- Served by the `ml_pipeline` context's in-process inference service
- NOT distributed training, NOT GPU-required, NOT containerized model serving

**External ML Platform Integration (post-M33):** SageMaker, Vertex AI, Azure ML are port implementations behind `IMLTrainingPort`. Not implemented in M33. The port is defined; adapters are future milestones.

This is **Condition C2** — ML pipeline scope must be explicitly frozen before Phase 1.

### 2.4 Reporting Context Boundary

M33's `reporting` context and M32's `exposure_reporting` context both produce reports. The boundary must be explicit:

| Boundary | M32 `exposure_reporting` | M33 `reporting` |
|---|---|---|
| Data source | M32 ExposureRecord, ExposureScoreSnapshot | M33 analytics projection tables (KPIs) |
| Report types | Board Risk Summary, Remediation Roadmap, Compliance Gap | Security Program Dashboard, Executive Security Report, Predictive Threat Forecast |
| Audience focus | CISO: "What is our current exposure?" | CISO: "How is our security program performing over time?" |
| Narrative method | Template-driven (7 templates, ADR-M32-005) | Template-driven (M33 templates); no LLM |
| Security Graph | Exposure nodes | Predictive and anomaly nodes |

These are distinct, non-overlapping capabilities. M33 `reporting` does NOT replace or extend `exposure_reporting`. This boundary is established here and must be enforced throughout implementation.

This is **Condition C3** — reporting context boundary must be explicitly documented in the finalization.

---

## 3. Bounded Context Review

### 3.1 `analytics` — Core Domain

#### Aggregate Roots

**AnalyticsDataSet**
```
AnalyticsDataSet (Aggregate Root)
  id: AnalyticsDataSetId
  tenant_id: TenantId
  name: str                              # e.g., "vulnerability_trend_dataset"
  domain: SecurityDomain                 # VULNERABILITY | DETECTION | RED_TEAM | CAMPAIGN | EXPOSURE | AI_POSTURE | CROSS_DOMAIN
  schema_version: SchemaVersion
  status: DataSetStatus                  # ACTIVE | PAUSED | DEPRECATED
  projection_checkpoint: Optional[str]   # last processed event_id for idempotency
  record_count: int                      # approximate; updated periodically
  created_at: datetime
  last_populated_at: Optional[datetime]
  version: int
```

**SecurityKPI**
```
SecurityKPI (Aggregate Root)
  id: SecurityKPIId
  tenant_id: TenantId
  kpi_type: KPIType                      # MTTD | COVERAGE_PCT | EXPOSURE_TREND | CAMPAIGN_SUCCESS_RATE | AI_RISK_TREND
  definition_version: int                # KPI formula version
  computation_schedule: CronExpression   # e.g., "0 2 * * *" (daily at 02:00 UTC)
  last_computed_at: Optional[datetime]
  last_value: Optional[Decimal]
  last_value_computed_at: Optional[datetime]
  status: KPIStatus                      # ACTIVE | COMPUTING | ERROR | INSUFFICIENT_DATA
  error_reason: Optional[str]
  created_at: datetime
  version: int
```

**AnalyticsQuery**
```
AnalyticsQuery (Aggregate Root)
  id: AnalyticsQueryId
  tenant_id: TenantId
  name: str
  description: str
  query_template: str                    # parameterized SQL template against analytics projection views
  parameters: List[QueryParameter]       # name, type, required flag
  allowed_domains: List[SecurityDomain]  # which dataset domains this query accesses
  owner_role: AnalyticsRole             # minimum role required to execute
  created_by: str
  created_at: datetime
  version: int
```

**AnomalyDetectionBaseline**
```
AnomalyDetectionBaseline (Aggregate Root)
  id: AnomalyBaselineId
  tenant_id: TenantId
  signal_type: AnomalySignalType        # VULNERABILITY_RATE | DETECTION_FP_RATE | CAMPAIGN_EVASION_RATE | EXPOSURE_SCORE_DELTA
  method: DetectionMethod               # ZSCORE | IQR | IQR_ROLLING | ML_ISOLATION_FOREST (phase 3+)
  window_days: int                      # lookback window for baseline computation
  threshold_sigma: Decimal              # deviation threshold (e.g., 2.5 = 2.5 standard deviations)
  last_trained_at: Optional[datetime]
  training_sample_size: Optional[int]
  is_bootstrapped: bool                 # false until sufficient historical data exists
  version: int
```

#### Value Objects

```
SecurityDomain (Enum):
  VULNERABILITY, DETECTION, RED_TEAM, CAMPAIGN, EXPOSURE, AI_POSTURE, CROSS_DOMAIN

KPIType (Enum):
  MTTD                    # Mean Time to Detect (from attack action to detection finding)
  COVERAGE_PCT            # ATT&CK technique coverage %
  EXPOSURE_TREND          # week-over-week exposure score delta
  CAMPAIGN_SUCCESS_RATE   # detection rate per completed campaign
  AI_RISK_TREND           # week-over-week AI risk score delta
  ANOMALY_COUNT           # count of anomalies detected per signal type per period

AnomalySignalType (Enum):
  VULNERABILITY_INGEST_RATE
  DETECTION_FP_RATE
  CAMPAIGN_EVASION_RATE
  EXPOSURE_SCORE_DELTA
  AI_RISK_SCORE_DELTA

DetectionMethod (Enum):
  ZSCORE                  # Phase 1: rule-based statistical
  IQR                     # Phase 1: rule-based statistical
  IQR_ROLLING             # Phase 2: rolling window IQR
  ML_ISOLATION_FOREST     # Phase 3+: ML-based; requires bootstrapped baseline
```

#### Domain Services

```
KPIComputationService
  compute_kpi(tenant_id, kpi_type, time_range) → KPIComputationResult
  schedule_computation(tenant_id, kpi_id) → None

AnomalyDetectionService
  train_baseline(tenant_id, signal_type, window_days) → AnomalyDetectionBaseline
  detect_anomalies(tenant_id, signal_type, current_window) → List[AnomalySignal]
  is_bootstrapped(tenant_id, signal_type) → bool

AnalyticsQueryExecutionService
  execute_query(tenant_id, query_id, parameters) → QueryResult
  validate_query_template(template, parameters) → ValidationResult
```

#### Repository Interfaces

```
IAnalyticsDataSetRepository:
  find_by_id(tenant_id, dataset_id) → Optional[AnalyticsDataSet]
  find_by_domain(tenant_id, domain) → List[AnalyticsDataSet]
  find_all_active(tenant_id) → List[AnalyticsDataSet]
  save(tenant_id, dataset) → None

ISecurityKPIRepository:
  find_by_id(tenant_id, kpi_id) → Optional[SecurityKPI]
  find_by_type(tenant_id, kpi_type) → Optional[SecurityKPI]
  find_due_for_computation(now: datetime) → List[SecurityKPI]  # cross-tenant; admin only
  save(tenant_id, kpi) → None

IAnomalyDetectionBaselineRepository:
  find_by_signal_type(tenant_id, signal_type) → Optional[AnomalyDetectionBaseline]
  find_unbootstrapped() → List[AnomalyDetectionBaseline]  # cross-tenant; admin only
  save(tenant_id, baseline) → None

IAnalyticsQueryRepository:
  find_by_id(tenant_id, query_id) → Optional[AnalyticsQuery]
  find_all(tenant_id) → List[AnalyticsQuery]
  save(tenant_id, query) → None
```

#### Domain Events Produced

```
AnalyticsDataSetRegistered(dataset_id, domain, schema_version)
AnalyticsDataSetPopulated(dataset_id, records_ingested, checkpoint)
KPIComputed(kpi_id, kpi_type, value, computed_at, time_range)
KPIComputationFailed(kpi_id, kpi_type, error_reason)
KPIInsufficientData(kpi_id, kpi_type, minimum_data_days_required, available_days)
AnomalyBaselineBootstrapped(baseline_id, signal_type, method, sample_size)
AnomalyDetected(baseline_id, signal_type, observed_value, threshold, severity)
```

#### Outbound Ports (ACL)

```
IVulnerabilityAnalyticsPort       → adapter to vulnerability BC projection data
IDetectionAnalyticsPort           → adapter to detection BC projection data
ICampaignAnalyticsPort            → adapter to campaign BC projection data
IExposureAnalyticsPort            → adapter to exposure BC projection data
IAIPostureAnalyticsPort           → adapter to ai_posture BC projection data
ISecurityGraphWritePort           → write-only; anomaly and predictive nodes
```

**Critical constraint:** All ports are READ-ONLY from upstream contexts. No analytics port may write to any upstream bounded context.

---

### 3.2 `ml_pipeline` — Supporting Domain

#### Aggregate Roots

**MLModel**
```
MLModel (Aggregate Root)
  id: MLModelId
  tenant_id: TenantId
  model_type: MLModelType               # ANOMALY_DETECTOR | RISK_PREDICTOR | COVERAGE_FORECASTER
  algorithm: MLAlgorithm                # ISOLATION_FOREST | RANDOM_FOREST | LINEAR_REGRESSION | GRADIENT_BOOST
  training_dataset_id: AnalyticsDataSetId  # reference; not imported type
  training_data_range: DateRange
  feature_set: List[FeatureDefinition]
  status: MLModelStatus                 # TRAINING | TRAINED | DEPLOYED | DEPRECATED | FAILED
  accuracy_metrics: Optional[ModelAccuracyMetrics]
  artifact_ref: Optional[str]           # storage reference to serialized model artifact
  trained_at: Optional[datetime]
  deployed_at: Optional[datetime]
  drift_detected_at: Optional[datetime]
  version: int
```

**PredictiveRiskSignal**
```
PredictiveRiskSignal (Aggregate Root)
  id: PredictiveRiskSignalId
  tenant_id: TenantId
  asset_ref_id: str                     # reference; not AssetRef domain type
  model_id: MLModelId
  signal_type: PredictiveSignalType     # TECHNIQUE_EXPLOITATION_PROBABILITY | EXPOSURE_SCORE_FORECAST | COVERAGE_GAP_RISK
  predicted_value: Decimal              # [0.0, 1.0]
  confidence_interval: ConfidenceInterval
  prediction_horizon_days: int          # how far ahead this prediction covers
  computed_at: datetime
  expires_at: datetime                  # predictions have a TTL; stale predictions are not served
  model_version: int
```

#### Value Objects

```
MLModelType (Enum):
  ANOMALY_DETECTOR
  RISK_PREDICTOR
  COVERAGE_FORECASTER

MLAlgorithm (Enum):
  ISOLATION_FOREST      # primary anomaly detection
  RANDOM_FOREST         # risk prediction
  LINEAR_REGRESSION     # trend forecasting
  GRADIENT_BOOST        # complex risk prediction (Phase 3+)

MLModelStatus (Enum):
  TRAINING, TRAINED, DEPLOYED, DEPRECATED, FAILED

PredictiveSignalType (Enum):
  TECHNIQUE_EXPLOITATION_PROBABILITY
  EXPOSURE_SCORE_FORECAST
  COVERAGE_GAP_RISK
```

#### Domain Services

```
MLModelTrainingService
  schedule_training(tenant_id, model_type, dataset_id) → TrainingJob
  execute_training(job: TrainingJob) → MLModel
  evaluate_accuracy(model_id, test_dataset) → ModelAccuracyMetrics

MLInferenceService
  generate_predictions(tenant_id, model_id, asset_refs) → List[PredictiveRiskSignal]
  check_for_drift(model_id) → DriftAssessment
  retire_stale_predictions(tenant_id, before: datetime) → int

ModelGovernanceService
  promote_to_deployed(tenant_id, model_id) → None  # requires analytics:admin
  deprecate_model(tenant_id, model_id) → None
  list_governance_history(tenant_id, model_id) → List[ModelGovernanceEvent]
```

#### Repository Interfaces

```
IMLModelRepository:
  find_by_id(tenant_id, model_id) → Optional[MLModel]
  find_deployed_by_type(tenant_id, model_type) → Optional[MLModel]
  find_models_for_drift_check(last_checked_before: datetime) → List[MLModel]
  save(tenant_id, model) → None

IPredictiveRiskSignalRepository:
  find_by_asset(tenant_id, asset_ref_id) → List[PredictiveRiskSignal]
  find_by_model(tenant_id, model_id) → List[PredictiveRiskSignal]
  find_active_by_type(tenant_id, signal_type) → List[PredictiveRiskSignal]
  save(tenant_id, signal) → None
  delete_expired(tenant_id, before: datetime) → int  # cleanup only; not business logic deletion

IMLModelArtifactStore:
  store_artifact(model_id, artifact_bytes: bytes) → str  # returns artifact_ref
  load_artifact(artifact_ref: str) → bytes
  delete_artifact(artifact_ref: str) → None  # triggered only by deprecation
```

#### Domain Events Produced

```
MLModelTrainingStarted(model_id, model_type, dataset_id)
MLModelTrained(model_id, accuracy_metrics)
MLModelTrainingFailed(model_id, error_reason)
MLModelDeployed(model_id, deployed_by)
MLModelDriftDetected(model_id, drift_metric, threshold)
MLModelDeprecated(model_id, deprecated_by)
PredictiveRiskSignalsGenerated(model_id, asset_count, signal_type)
```

#### Outbound Ports (ACL)

```
IAnalyticsDataQueryPort    → read from analytics projection tables (via analytics BC service)
IMLTrainingPort            → abstract: in-process (default) or external ML platform adapter
ISecurityGraphWritePort    → write predictive risk nodes (append-only)
```

**Cold Start Protocol:** Until an `MLModel` is deployed, `MLInferenceService` returns `PredictiveRiskSignal.status = INSUFFICIENT_TRAINING_DATA`. The API surfaces this clearly. KPI computation and rule-based anomaly detection remain active throughout the cold start period.

---

### 3.3 `reporting` — Supporting Domain

#### Aggregate Roots

**ReportTemplate**
```
ReportTemplate (Aggregate Root)
  id: ReportTemplateId
  tenant_id: Optional[TenantId]         # None = platform-level template; TenantId = tenant-customized
  report_type: ReportType               # SECURITY_PROGRAM_DASHBOARD | EXECUTIVE_SECURITY_REPORT | PREDICTIVE_THREAT_FORECAST | DETECTION_ANALYTICS | CAMPAIGN_EFFECTIVENESS
  template_name: str
  sections: List[ReportSection]         # ordered list of sections with data source bindings
  output_format: ReportFormat           # PDF | HTML | JSON | CSV
  is_active: bool
  version: int
```

**ScheduledReport**
```
ScheduledReport (Aggregate Root)
  id: ScheduledReportId
  tenant_id: TenantId
  template_id: ReportTemplateId
  schedule: CronExpression
  parameters: Dict[str, Any]            # bound to template's parameter definitions
  recipients: List[ReportRecipient]     # email or webhook
  status: ScheduledReportStatus         # ACTIVE | PAUSED | ERROR
  last_run_at: Optional[datetime]
  last_run_result: Optional[ReportRunStatus]
  created_by: str
  version: int
```

**ReportInstance**
```
ReportInstance (Aggregate Root)
  id: ReportInstanceId
  tenant_id: TenantId
  template_id: ReportTemplateId
  triggered_by: ReportTrigger           # SCHEDULED | ON_DEMAND
  status: ReportStatus                  # PENDING | GENERATING | COMPLETE | FAILED
  generated_at: Optional[datetime]
  artifact_ref: Optional[str]           # storage reference to generated report artifact
  parameters_snapshot: Dict[str, Any]   # parameters used at generation time
  error_reason: Optional[str]
  version: int
```

#### Domain Services

```
ReportGenerationService
  generate(tenant_id, template_id, parameters, trigger) → ReportInstance
  render_section(section: ReportSection, data: AnalyticsData) → RenderedSection
  export_to_bi(tenant_id, dataset_id, export_format) → DataExportJob

ScheduledReportService
  create_schedule(tenant_id, template_id, schedule, parameters, recipients) → ScheduledReport
  pause_schedule(tenant_id, schedule_id) → None
  resume_schedule(tenant_id, schedule_id) → None
  invoke_due_schedules(now: datetime) → List[ReportInstance]  # called by scheduler worker
```

#### Domain Events Produced

```
ReportGenerationStarted(instance_id, template_id, triggered_by)
ReportGenerationCompleted(instance_id, template_id, artifact_ref)
ReportGenerationFailed(instance_id, error_reason)
ReportDelivered(instance_id, recipient_count)
ScheduledReportCreated(schedule_id, template_id, schedule)
DataExportStarted(export_job_id, dataset_id, format)
DataExportCompleted(export_job_id, record_count)
```

#### Outbound Ports

```
IAnalyticsKPIQueryPort     → reads KPI values from analytics BC
IMLSignalQueryPort         → reads predictive risk signals from ml_pipeline BC
IReportDeliveryPort        → abstract: email/webhook/storage delivery
IBIExportPort              → abstract: Tableau/Power BI/Looker data connector
```

---

## 4. Integration Review

### 4.1 Events Consumed from M26–M32

M33 is a pure consumer. The following upstream events are subscribed to via the platform event bus and projected into M33's analytics tables. All upstream types are translated at ACL adapters.

| Source BC | Key Events | Analytics Usage |
|---|---|---|
| `vulnerability` | `VulnerabilityInstanceDiscovered`, `VulnerabilityInstancePatched`, `VulnerabilityKevStatusChanged` | Vulnerability ingest rate, KEV trend, remediation lag KPIs |
| `detection` | `DetectionFindingProduced`, `DetectionRuleActivated`, `DetectionRuleDeprecated` | Coverage %, FP rate trend, rule lifecycle KPIs |
| `execution` / `engagement` | `AttackActionExecuted`, `EngagementClosed` | MTTD computation (attack → detection lag) |
| `campaign` / `campaignexecution` | `CampaignCompleted`, `CampaignDetectionCoverageComputed` | Campaign success rate, coverage trend |
| `exposure` | `ExposureScoreComputed`, `ExposureRecordCreated`, `ExposureRecordResolved` | Exposure trend, CTEM KPIs |
| `ai_posture` | `AISystemAssetDiscovered`, `AISystemAssetClassified` | AI asset growth, AI risk trend |
| `exposure_reporting` | `ExposureReportGenerated` | Report generation frequency metric (secondary) |

**Critical design rule:** M33 consumes events only. It never calls upstream application services directly and never queries upstream operational databases. No upstream type is imported into M33's domain — events are translated at the ACL boundary.

### 4.2 MTTD Computation Design

MTTD requires correlating an `AttackActionExecuted` event (from M29/M30) with a `DetectionFindingProduced` event (from M28) for the same technique on the same asset within a bounded time window.

```
MTTD_per_action = detection_finding_created_at - attack_action_executed_at
  where:
    detection_finding.technique_id == attack_action.technique_id
    detection_finding.asset_ref == attack_action.target_ref
    detection_finding.created_at < attack_action.executed_at + 24h  # correlation window

MTTD_tenant = mean(MTTD_per_action) over last 30 days
```

MTTD is only computable for completed M29/M30 campaign executions where detection findings were produced. For tenants without M29/M30 data, `MTTD` KPI status = `INSUFFICIENT_DATA`.

### 4.3 MTTR — Deferred to M34

**MTTR** (Mean Time to Respond) requires M34 incident response data (`IncidentClassified` → `IncidentResolved`). Since M34 is not yet released, MTTR cannot be computed in M33.

This is **Condition C4:** MTTR must NOT be listed as an M33 KPI. It is a future KPI enabled when M34 data exists. The `KPIType` enum must include `MTTR` as a definition-only entry with status `REQUIRES_M34_DATA` for tenants that don't have M34.

### 4.4 Security Graph Integration

M33 writes to the Security Graph via the append-only `ISecurityGraphWritePort`:

| Node/Edge Type | Source | Description |
|---|---|---|
| `PredictiveRiskNode` | `ml_pipeline` | ML-generated risk prediction per asset |
| `AnomalyNode` | `analytics` | Detected anomaly per signal type |
| `PREDICTED_RISK` edge | `ml_pipeline` | PredictiveRiskNode → AssetNode (reference) |
| `ANOMALY_DETECTED` edge | `analytics` | AnomalyNode → relevant operational node |

M33 **never reads** from the Security Graph. It is a write-only consumer of the Security Graph write port.

### 4.5 M32 ExposureScopePort Boundary

M33 does not interact with M32's `IExposureScopeQueryPort`. That port is owned by M30's campaign context. M33 consumes M32's `ExposureScoreComputed` events for analytics purposes only. There is no direct service-to-service call from M33 to M32.

### 4.6 BI Export API Design

The data export API is a REST endpoint that returns pre-computed analytics data in structured formats. It is NOT a live query passthrough against M33's projection tables.

Design:
- Endpoint: `GET /analytics/v1/export/{dataset_id}?format=csv|json&page=N&page_size=N`
- Dataset must be pre-registered via `AnalyticsDataSet`
- Response is paginated; no unbounded result sets
- Rate limited: 10 export requests/hour per tenant (configurable via `analytics:admin`)
- Format options: CSV, JSON, newline-delimited JSON (for BI tool ingestion)
- Tableau/Power BI connectors are `IBIExportPort` implementations: they call this API, not direct DB connections

---

## 5. Risk Assessment

### R01 — Cross-Tenant Leakage in Analytics Query Engine
**Severity:** CRITICAL  
**Description:** The analytics query engine operates against projection tables that contain data from all tenants. If `TenantId` filtering is not enforced at the application service layer (before query execution), a misconfigured query could return cross-tenant data. This is especially dangerous for stored `AnalyticsQuery` templates — a stored query with a missing `WHERE tenant_id = :tenant_id` clause could leak all tenants' data.  
**Mitigation required:** Every stored query template must include `WHERE tenant_id = :tenant_id` as a mandatory, non-removable clause enforced by `AnalyticsQueryExecutionService` at injection into the query template. The service must validate that the `tenant_id` parameter in the executed query matches the authenticated tenant before execution. See **Condition C5**.

### R02 — Analytics Data Volume Exceeds PostgreSQL Query Limits
**Severity:** HIGH  
**Description:** By M32, a large enterprise tenant may have millions of vulnerability instances, hundreds of thousands of detection findings, and thousands of campaign execution records. A na&#239;ve analytics query against projection tables of this volume without proper indexing, partitioning, and pre-computation will exceed interactive latency SLOs (sub-30 seconds).  
**Mitigation required:** Analytics projection tables must be partitioned by `(tenant_id, period_month)`. KPI values must be pre-computed and cached; dashboard queries must read cached KPI values, not recompute on demand. This is a Phase 1 design requirement, not an optimization.

### R03 — ML Model Drift Degrades Analytics Signal Quality
**Severity:** HIGH  
**Description:** ML models trained on historical data produce predictions that degrade as the tenant's security posture evolves. A deployed `MLModel` trained 90 days ago may produce systematically biased predictions for a tenant who completed a major vulnerability remediation campaign. Drift detection is the safeguard, but if drift detection itself is incorrect or too slow, stale predictions are served as authoritative signals.  
**Mitigation required:** (a) All `PredictiveRiskSignal` records carry `expires_at` (maximum 30 days). Expired signals are not served. (b) Model accuracy metrics (`RMSE`, `AUC`) are tracked per deployment and visible to `analytics:admin`. (c) Drift detection runs on a configurable schedule (default weekly). (d) When drift is detected, the model status transitions to `DEPRECATED` automatically and the signal type returns `INSUFFICIENT_TRAINING_DATA` until a retrained model is deployed.

### R04 — Cold Start: No Analytics Value at Initial Deployment
**Severity:** MEDIUM  
**Description:** At first deployment, M33's analytics projection tables are empty. ML models cannot be trained. KPIs cannot be computed. The platform appears to offer no value. This is especially visible for new tenants onboarding after M33 is released.  
**Mitigation required:** Phase 1 must include a "bootstrap projection" worker that ingests the full historical event history from the platform event store into M33's analytics projection tables on initial tenant setup. This is not a cold start that resolves over weeks — it is a one-time historical backfill that completes within hours of tenant onboarding. Rule-based anomaly detection and KPIs are available immediately after backfill completion. ML-based detection activates at 90 days of post-backfill data (per the roadmap's honest sequencing cost acknowledgment).

### R05 — AnalyticsQuery Template Injection Risk
**Severity:** MEDIUM  
**Description:** `AnalyticsQuery.query_template` is a parameterized SQL template. If parameter substitution is done via string interpolation rather than parameterized queries, SQL injection is possible. For analytics templates, this would allow a `analytics:analyst` role holder to inject SQL that extracts data from any table accessible to the database user.  
**Mitigation required:** All parameter substitution in `AnalyticsQueryExecutionService` must use SQL parameter binding (SQLAlchemy's `text()` with `:param` placeholders), never string formatting. This is mandatory and must be enforced as an architecture invariant.

### R06 — ML Model Artifact Security
**Severity:** MEDIUM  
**Description:** ML models trained on a tenant's security data are themselves sensitive artifacts. A model trained on vulnerability distributions reveals which techniques are common in that tenant's environment. If model artifacts are stored in a shared storage location without tenant-scoped access control, cross-tenant model exfiltration is possible.  
**Mitigation required:** Model artifacts are stored in a PostgreSQL `analytics_model_artifacts` table with `(tenant_id, model_id)` as the primary lookup. Repository-level tenant isolation is enforced. No shared storage path is used. The `IMLModelArtifactStore` interface requires `tenant_id` on all artifact operations.

### R07 — Reporting Context LLM Dependency Creep
**Severity:** LOW  
**Description:** The roadmap notes that "executive narrative generation requires careful design." There may be pressure during implementation to use an LLM for natural language generation in reports. Consistent with ADR-M32-005, M33 must use template-driven narrative generation. Introducing an LLM dependency in M33 violates Platform Invariant 7 (AI suggestions read-only at domain boundaries) and creates a non-determinism problem in audit-sensitive reports.  
**Mitigation:** ADR-M33-001 must explicitly freeze report narrative method as template-driven, consistent with ADR-M32-005. No LLM client dependency is permitted in the `reporting` context in M33.

### R08 — MTTR KPI Incorrectly Defined Without M34
**Severity:** LOW  
**Description:** The roadmap lists MTTR as an M33 KPI. MTTR requires incident data from M34, which is not yet implemented. Implementing MTTR in M33 without M34 data means either (a) incorrect computation or (b) a permanently INSUFFICIENT_DATA KPI that confuses operators.  
**Mitigation:** See Condition C4. MTTR is defined in M33 but only computable when M34 data is present. The KPI definition is included in the schema; the computation service returns `KPIStatus.REQUIRES_M34_DATA` until M34 events are present.

### R09 — Reporting Overlap with M32 `exposure_reporting`
**Severity:** LOW  
**Description:** Both M32 `exposure_reporting` and M33 `reporting` produce executive reports. Without explicit boundary enforcement, implementation may duplicate report types, creating competing implementations.  
**Mitigation:** See Condition C3. The boundary is frozen in the finalization document. M33 `reporting` does NOT produce CTEM-specific reports (those remain in M32). API documentation must clearly distinguish both report types.

---

## 6. Recommended Improvements

### I01 — Explicit Analytics Projection Table Schema
**Priority:** High (P0 blocker)  
The analytics projection tables must be explicitly designed before Phase 1 begins. The minimum required:
- `analytics_vulnerability_events` (per-tenant; partitioned by month)
- `analytics_detection_events` (per-tenant; partitioned by month)
- `analytics_campaign_events` (per-tenant; partitioned by month)
- `analytics_exposure_events` (per-tenant; partitioned by month)
- `analytics_kpi_snapshots` (pre-computed KPI values; point-in-time history)
- `analytics_anomaly_detections` (detected anomalies by signal type)

### I02 — Security KPI Formal Definitions
**Priority:** High (P0 blocker)  
Each KPI must have a documented mathematical formula before implementation. Informal descriptions produce non-reproducible results. See §4.2 for MTTD definition. All five initial KPIs must be similarly formalized in the finalization.

### I03 — Analytics Worker Architecture
**Priority:** High  
Three background workers are required:
1. `AnalyticsProjectionWorker` — consumes upstream events and populates projection tables
2. `KPIComputationWorker` — runs on schedule, computes and stores KPI snapshots
3. `MLTrainingWorker` — trains ML models when scheduled; runs asynchronously
4. `MLInferenceWorker` — generates and refreshes PredictiveRiskSignals on schedule

These workers must be explicitly designed in the finalization (schedule, concurrency, failure handling, idempotency).

### I04 — Role Hierarchy for Analytics
**Priority:** Medium  
Roles must follow the `{context}:{function}` platform naming convention:
- `analytics:viewer` — read KPIs, read reports
- `analytics:analyst` — execute queries, generate reports
- `analytics:engineer` — manage datasets, define KPIs
- `analytics:admin` — configure ML models, manage retention, access cross-dataset queries

### I05 — BI Export Rate Limiting and Audit
**Priority:** Medium  
The BI export API must be rate-limited and every export request must produce an `analytics_audit_log` entry (who, when, what dataset, how many records). This satisfies the SOC 2 and data residency requirements mentioned in the roadmap.

### I06 — Model Governance ADR
**Priority:** Medium  
M33 introduces ML models that make security risk predictions. Platform Invariant 7 requires AI suggestions to be read-only at domain boundaries. `PredictiveRiskSignal` is advisory only — it supplements but does not replace rule-based scores. This must be frozen in ADR-M33-002.

### I07 — Analytics Context Security Boundary
**Priority:** High  
M33 contains the most sensitive aggregated view of the security program. The analytics schema must be in a separate PostgreSQL schema (`analytics`) with separate database user grants. The analytics database user must have no write access to any other operational schema. This is the OLTP/OLAP separation at the database permission level.

---

## 7. Implementation Phase Plan

### Phase 1 — Analytics Foundation
**Scope:** `analytics` bounded context core. Analytics projection tables. Event subscription and ingestion. KPI infrastructure (MTTD, Coverage %, Exposure Trend). Rule-based anomaly detection (Z-score/IQR). No ML.

**Bounded Contexts:** `analytics`

**Aggregate Roots:** `AnalyticsDataSet`, `SecurityKPI`, `AnomalyDetectionBaseline`

**Domain Events Consumed:** VulnerabilityInstanceDiscovered, DetectionFindingProduced, AttackActionExecuted, ExposureScoreComputed, AISystemAssetDiscovered, CampaignCompleted

**API Commands:**
- `RegisterAnalyticsDataSet`
- `DefineSecurityKPI`
- `CreateAnomalyBaseline`
- `TriggerKPIComputation` (admin)

**API Queries:**
- `GetSecurityKPI(tenant_id, kpi_type)`
- `GetKPIHistory(tenant_id, kpi_type, date_range)`
- `ListAnomalies(tenant_id, signal_type, date_range)`
- `GetDataSetStatus(tenant_id, dataset_id)`

**Migrations:** 0086–0090 (analytics_* tables, analytics_kpi_snapshots, analytics_anomaly_detections)

**Workers:** AnalyticsProjectionWorker, KPIComputationWorker

**Tests:**
- Unit: KPI formula computation (all 5 KPI types including MTTR stub)
- Unit: Anomaly detection (Z-score, IQR; bootstrapped vs. unbootstrapped state)
- Unit: Tenant isolation enforcement in query execution
- Integration: Event subscription → projection table population
- Integration: KPI computation from projection data
- Architecture: No upstream domain type imports in analytics BC

### Phase 2 — Stored Queries and Analytics API
**Scope:** `AnalyticsQuery` aggregate. Parameterized query execution engine with tenant isolation enforcement. Cross-domain query API. Dashboard read models.

**New Aggregate:** `AnalyticsQuery`

**API Commands:** `CreateAnalyticsQuery`, `UpdateAnalyticsQuery`, `DeprecateAnalyticsQuery`

**API Queries:** `ExecuteAnalyticsQuery(tenant_id, query_id, parameters)`, `ListAnalyticsQueries(tenant_id)`

**Key Tests:**
- Unit: SQL parameter injection prevention (all parameters bound, never string-interpolated)
- Unit: Tenant isolation enforcement (query execution always injects `tenant_id`)
- Integration: Stored query round-trip (create → execute → result pagination)

### Phase 3 — ML Pipeline Foundation
**Scope:** `ml_pipeline` bounded context. `MLModel` and `PredictiveRiskSignal` aggregates. In-process ML training (Isolation Forest for anomaly, Random Forest for risk prediction). Model artifact storage. Drift detection. Security graph write (predictive nodes).

**Bounded Contexts:** `ml_pipeline`

**Migrations:** 0091–0093 (ml_models, ml_model_artifacts, predictive_risk_signals)

**Workers:** MLTrainingWorker, MLInferenceWorker, DriftCheckWorker

**Key Tests:**
- Unit: Cold start protocol (no model deployed → INSUFFICIENT_TRAINING_DATA response)
- Unit: Model drift detection → auto-deprecation
- Integration: Training pipeline end-to-end (dataset → trained model → accuracy metrics → deployed)
- Integration: Prediction generation → PredictiveRiskSignal storage → Security Graph write

### Phase 4 — Reporting and Export
**Scope:** `reporting` bounded context. `ReportTemplate`, `ScheduledReport`, `ReportInstance` aggregates. Security Program Dashboard. Executive Security Report. Predictive Threat Forecast. BI export API.

**Bounded Contexts:** `reporting`

**Migrations:** 0094–0096 (report_templates, scheduled_reports, report_instances)

**Key Tests:**
- Unit: Template-driven narrative selection (no LLM dependency test; architecture invariant)
- Unit: ScheduledReport invocation logic
- Integration: Report generation pipeline end-to-end
- Integration: BI export API (pagination, rate limiting, audit log)

### Phase 5 — Completion, Hardening, and Security Graph
**Scope:** Full Security Graph integration (anomaly and predictive nodes). BI connector framework (IBIExportPort — interface definition; no vendor implementation). Retention management. Model governance UI. Comprehensive test suite.

**Tests:**
- All unit, integration, architecture, authorization, projection, API tests
- Security: SQL injection prevention tests on AnalyticsQuery execution
- Security: Cross-tenant leakage tests (analytics query isolation)
- Security: Model artifact tenant isolation tests
- Performance: KPI computation latency under load (projection table size simulation)

---

## 8. Architecture Verdict

### Conditions to Resolve Before Implementation

| ID | Condition | Section |
|---|---|---|
| C1 | Freeze the analytics data lake physical design (analytics projection tables in PostgreSQL; OLTP/OLAP separation; no direct upstream DB queries) | §2.2 |
| C2 | Freeze the `ml_pipeline` scope: in-process statistical ML only for M33; external ML platforms are port-only (IMLTrainingPort); no distributed training | §2.3 |
| C3 | Freeze the `reporting` / `exposure_reporting` boundary: explicit non-overlapping report type taxonomy | §2.4, §4.0 |
| C4 | Remove MTTR from M33 computable KPIs; retain as schema definition with `REQUIRES_M34_DATA` status | §4.3, §R08 |
| C5 | Freeze AnalyticsQuery tenant isolation enforcement: mandatory `tenant_id` parameter injection at service layer; SQL parameter binding only | §R01, §R05 |
| C6 | Freeze ML model artifact security: artifact storage in PostgreSQL with tenant-scoped repository enforcement; no shared path storage | §R06 |
| C7 | Formal mathematical definition of all five M33 KPIs (MTTD, Coverage %, Exposure Trend, Campaign Success Rate, AI Risk Trend) | §I02 |

### Assessment

The M33 strategic design is sound. The three bounded contexts (`analytics`, `ml_pipeline`, `reporting`) are correctly separated, the integration model is event-driven and read-only, and the platform invariants are respected. Seven architectural conditions require resolution before implementation begins.

**M33 Architecture Approved for Implementation — with Conditions C1 through C7.**

Resolve all seven conditions in M33_ARCHITECTURE_FINALIZATION.md before Phase 1 implementation begins.

STOP. Do NOT implement code. Wait for architecture finalization approval.
