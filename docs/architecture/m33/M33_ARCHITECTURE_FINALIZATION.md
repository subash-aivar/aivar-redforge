# M33 Architecture Finalization
## Enterprise Security Analytics & Intelligence Platform

**Status:** FROZEN FOR IMPLEMENTATION  
**Date:** 2026-07-21  
**Precondition:** M33 Architecture Review APPROVED WITH CONDITIONS (C1–C7)  
**Constraint:** Documentation only. No code, no migrations, no repository modifications.

---

## Table of Contents

1. [Final Decisions (C1–C7)](#1-final-decisions-c1c7)
2. [Frozen DDD Model](#2-frozen-ddd-model)
3. [ADRs (ADR-M33-001 through ADR-M33-006)](#3-adrs-adr-m33-001-through-adr-m33-006)
4. [Architecture Corrections](#4-architecture-corrections)
5. [Risk Dispositions (R01–R09)](#5-risk-dispositions-r01r09)
6. [Frozen Phase Plan](#6-frozen-phase-plan)
7. [Implementation Readiness](#7-implementation-readiness)

---

## 1. Final Decisions (C1–C7)

---

### C1 — Analytics Data Lake Physical Design

**Condition from Review:** The "security data lake" was under-specified. Physical implementation, storage model, partitioning, OLTP/OLAP separation, event ingestion pipeline, projection rebuild, and retention must all be frozen before Phase 1 begins.

#### Decision: PostgreSQL Projection Tables in a Dedicated Analytics Schema

The analytics data lake is implemented as a set of typed, partitioned PostgreSQL tables in a dedicated `analytics` schema. This is the permanent, primary implementation. External cloud analytics backends (BigQuery, Redshift, Snowflake) are port implementations, not the primary store. They are not implemented in M33.

#### Projection Table Architecture

Eight primary projection tables cover all upstream domain signals:

| Table | Domain | Primary Keys | Upstream Events |
|---|---|---|---|
| `analytics.vulnerability_events` | Vulnerability | tenant_id, event_id, event_ts | VulnerabilityInstanceDiscovered, VulnerabilityInstancePatched, VulnerabilityKevStatusChanged |
| `analytics.detection_events` | Detection | tenant_id, event_id, event_ts | DetectionFindingProduced, DetectionRuleActivated, DetectionRuleDeprecated |
| `analytics.execution_events` | Red Team / Execution | tenant_id, event_id, event_ts | AttackActionExecuted, EngagementClosed |
| `analytics.campaign_events` | Campaign | tenant_id, event_id, event_ts | CampaignCompleted, CampaignDetectionCoverageComputed |
| `analytics.exposure_events` | Exposure | tenant_id, event_id, event_ts | ExposureScoreComputed, ExposureRecordCreated, ExposureRecordResolved |
| `analytics.ai_posture_events` | AI Posture | tenant_id, event_id, event_ts | AISystemAssetDiscovered, AISystemAssetClassified, AIRiskScoreComputed |
| `analytics.kpi_snapshots` | KPI Point-in-Time | tenant_id, kpi_type, snapshot_at | Produced by KPIComputationWorker |
| `analytics.anomaly_detections` | Anomaly | tenant_id, baseline_id, detected_at | Produced by AnomalyDetectionService |

Two support tables:

| Table | Purpose |
|---|---|
| `analytics.processed_analytics_events` | Idempotency tracker (event_id → processed_at); prevents duplicate ingestion |
| `analytics.ml_model_artifacts` | Model artifact storage with tenant isolation and integrity hash |

#### Partitioning Strategy

All event projection tables use a two-level partitioning scheme:

**Level 1 — Hash partition by `tenant_id` (16 partitions):**
```sql
CREATE TABLE analytics.vulnerability_events (
    event_id        UUID          NOT NULL,
    tenant_id       UUID          NOT NULL,
    event_type      VARCHAR(100)  NOT NULL,
    technique_id    VARCHAR(50),
    asset_ref_id    UUID,
    severity        DECIMAL(5,2),
    event_ts        TIMESTAMPTZ   NOT NULL,
    payload         JSONB         NOT NULL,
    ingested_at     TIMESTAMPTZ   NOT NULL DEFAULT now()
) PARTITION BY HASH (tenant_id);

CREATE TABLE analytics.vulnerability_events_p0 PARTITION OF analytics.vulnerability_events
    FOR VALUES WITH (MODULUS 16, REMAINDER 0);
-- ... p1 through p15
```

**Level 2 — Range sub-partition by `event_month` (monthly):**
```sql
CREATE TABLE analytics.vulnerability_events_p0 PARTITION BY RANGE (event_ts);

CREATE TABLE analytics.vulnerability_events_p0_2026_07
    PARTITION OF analytics.vulnerability_events_p0
    FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
```

Monthly sub-partitions enable:
- Time-range query pruning (KPI computation over last 30 days does not scan older partitions)
- Efficient retention policy enforcement (archive an entire month partition at once)
- Sub-millisecond tenant-scoped reads on `kpi_snapshots` (hash partition prunes to 1/16 of rows)

#### Event Ingestion Pipeline

```
Platform Event Bus
    |
    | upstream domain events (VulnerabilityInstanceDiscovered, etc.)
    |
    v
AnalyticsProjectionWorker
    ├── IEventBusSubscription (platform-standard event subscription)
    ├── analytics ACL adapters (translate upstream types → analytics-internal types)
    ├── processed_analytics_events deduplication check (event_id lookup)
    ├── if not processed:
    │       INSERT INTO analytics.{domain}_events
    │       INSERT INTO analytics.processed_analytics_events
    │   if already processed: SKIP (idempotent)
    └── checkpoint update: AnalyticsDataSet.projection_checkpoint = event_id
```

The `AnalyticsProjectionWorker` follows the platform `IdempotentProjectionEngine` pattern (Sprint 25). Each upstream event has a stable `event_id`. Duplicate delivery is a no-op. Replay of the full event history produces identical projection tables.

#### OLTP/OLAP Separation

Separation is enforced at three levels:

**Level 1 — PostgreSQL Schema and Role:**
```sql
CREATE SCHEMA analytics;
CREATE ROLE analytics_worker LOGIN;  -- used by AnalyticsProjectionWorker
GRANT USAGE ON SCHEMA analytics TO analytics_worker;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA analytics TO analytics_worker;
-- analytics_worker has NO access to public, redforge, or any operational schema

CREATE ROLE analytics_reader LOGIN;  -- used by API query layer
GRANT USAGE ON SCHEMA analytics TO analytics_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO analytics_reader;
-- analytics_reader has NO write access to analytics schema
-- analytics_reader has NO access to any operational schema
```

**Level 2 — Application Service Layer:**
The `AnalyticsQueryExecutionService` connects to PostgreSQL via a connection pool configured with `analytics_reader` credentials. This pool cannot be used to connect to operational tables — the database role makes it structurally impossible.

**Level 3 — No Direct Cross-Schema Queries:**
Query templates in `AnalyticsQuery` may only reference tables in the `analytics` schema. The template validator (see C5) rejects any reference to other schemas. This is validated statically at template creation time, not only at execution time.

#### Projection Rebuild Protocol

When a tenant first onboards, or when a projection must be rebuilt (data corruption, schema migration):

```
Step 1: AnalyticsDataSet.status → REBUILDING
Step 2: ProjectionRebuildWorker reads events from platform IEventStoreReplayPort
        -- page through event store: SELECT * FROM event_store WHERE tenant_id = :tid ORDER BY sequence
Step 3: DELETE FROM analytics.{domain}_events WHERE tenant_id = :tenant_id
        -- deletes only projection rows (not event store rows; event store is immutable)
Step 4: Replay events via idempotent AnalyticsProjectionWorker
Step 5: On completion: AnalyticsDataSet.status → ACTIVE; projection_checkpoint = latest_event_id
Step 6: KPIComputationWorker triggered to recompute all KPI snapshots for tenant
```

Historical backfill for a new tenant typically completes within 2–4 hours for a large estate (design assumption: platform event store contains up to 50M events per tenant; projection throughput target 5,000 events/second per worker). KPIs are available immediately after backfill completion.

#### Data Retention Policy

| Data Type | Default Retention | Configurable | Archive Behavior |
|---|---|---|---|
| `analytics.*_events` | 2 years | Yes (via `analytics:admin`; min 1 year) | Rows set `archived = true`; never physically deleted in M33 |
| `kpi_snapshots` | 5 years | No | Retained for program effectiveness trending |
| `anomaly_detections` | 1 year | Yes (via `analytics:admin`; min 90 days) | `archived = true` |
| `ml_model_artifacts` | Lifetime of model + 1 year after deprecation | No | `is_active = false`; physical deletion via compliance workflow only |

Retention enforcement is executed by `RetentionPolicyWorker` (daily, 03:00 UTC off-peak). Physical deletion of archived rows is a platform compliance engineering operation, not a feature of M33 business logic. This follows Platform Invariant 3 (Security Graph and analytics data are append-only from the business logic perspective).

---

### C2 — ML Pipeline Scope

**Condition from Review:** The ML pipeline scope as described in the roadmap (train, deploy, serve ML models) is too broad for a single milestone. The exact scope for M33 must be frozen.

#### Decision: In-Process Statistical ML Only; External ML Platforms Are Port-Only

**M33 ML scope is strictly limited to:**

| Capability | In M33? | Notes |
|---|---|---|
| Rule-based anomaly detection (Z-score, IQR) | Yes (Phase 1) | No ML dependency; pure statistical math |
| In-process ML training (scikit-learn) | Yes (Phase 3) | CPU-only; no GPU; no distributed training |
| In-process ML inference | Yes (Phase 3) | Synchronous for small estates; batch for large |
| Model artifact storage (PostgreSQL) | Yes (Phase 3) | BYTEA column; max 500MB per artifact |
| Drift detection | Yes (Phase 3) | Population Stability Index (PSI) on feature distributions |
| External ML platform (SageMaker, Vertex AI, Azure ML) | Port only | `IMLTrainingPort` interface defined; NO adapter implementations in M33 |
| GPU-accelerated training | No | Deferred post-M33 |
| Distributed training | No | Deferred post-M33 |
| Separate model serving process | No | In-process inference only in M33 |
| LLM-based analysis or generation | No | Deferred to M36 per Platform Invariant 7 |

#### Algorithm Set (Frozen)

| Use Case | Phase | Algorithm | Library |
|---|---|---|---|
| Anomaly detection (bootstrap) | Phase 1 | Z-score, IQR | Pure Python / numpy |
| Anomaly detection (ML) | Phase 3 | Isolation Forest | scikit-learn |
| Risk prediction | Phase 3 | Random Forest | scikit-learn |
| Trend forecasting | Phase 3 | Linear Regression | scikit-learn |
| Complex risk prediction (deferred) | Post-M33 | Gradient Boosting | scikit-learn / XGBoost |

#### Training Lifecycle (Frozen)

```
Phase 1: schedule_training command received
  → MLModel created (status: TRAINING)
  → TrainingJob record inserted
  → MLTrainingWorker picks up job

Phase 2: Feature extraction
  → Load training data from analytics projection tables (analytics_reader role)
  → Feature engineering per model type (see feature definitions below)
  → 80/20 train/test split (stratified by tenant sub-population for large estates)

Phase 3: Training (in-process)
  → scikit-learn model.fit(X_train, y_train)
  → Maximum training time: 30 minutes (hard limit; training job fails if exceeded)
  → Evaluate on test set: AUC, RMSE, or precision@K as appropriate to model type

Phase 4: Promotion gate
  → Accuracy threshold check (see thresholds below)
  → If passed: MLModel.status → TRAINED; artifact serialized and stored
  → If failed: MLModel.status → FAILED; failure reason recorded

Phase 5: Deployment (human-gated)
  → `analytics:admin` issues PromoteMLModel command
  → MLModel.status → DEPLOYED
  → MLModelDeployed event published
  → Previous deployed model for same type → DEPRECATED
```

#### Accuracy Thresholds (Frozen)

| Model Type | Metric | Minimum Threshold | Reject Behavior |
|---|---|---|---|
| Anomaly Detector (Isolation Forest) | AUC-PR on labeled anomalies | 0.65 | Status → FAILED; alert `analytics:admin` |
| Risk Predictor (Random Forest) | AUC-ROC | 0.70 | Status → FAILED |
| Coverage Forecaster (Linear Regression) | R² | 0.50 | Status → FAILED |

#### Inference Lifecycle (Frozen)

```
Trigger: MLInferenceWorker (daily, 04:00 UTC per tenant)

Step 1: Load deployed MLModel artifact from analytics.ml_model_artifacts
Step 2: Verify artifact_hash (SHA-256 of stored bytes must match artifact_hash column)
Step 3: Deserialize model (joblib.load from bytes)
Step 4: Load current feature data from analytics projection tables
Step 5: Generate predictions → List[PredictiveRiskSignal]
Step 6: Store predictions in predictive_risk_signals table
Step 7: Set expires_at = now() + 30 days (predictions expire; stale predictions not served)
Step 8: Publish PredictiveRiskSignalsGenerated event
```

For estates > 50,000 assets: inference is batched in groups of 5,000 assets per iteration with a 1-second yield between batches to prevent memory exhaustion.

#### Drift Detection (Frozen)

```
Trigger: DriftCheckWorker (weekly, Sunday 00:00 UTC)

Method: Population Stability Index (PSI) on input feature distributions

PSI formula:
  PSI = Σ[(actual_pct_i - expected_pct_i) × ln(actual_pct_i / expected_pct_i)]
  where buckets are 10 equal-frequency bins from training distribution

Thresholds:
  PSI < 0.10 → Stable (no action)
  0.10 ≤ PSI < 0.20 → Moderate drift (MLModelDriftDetected event; alert analytics:admin)
  PSI ≥ 0.20 → Severe drift (MLModelDriftDetected; model auto-deprecated → DEPRECATED)

When DEPRECATED:
  Inference returns status = INSUFFICIENT_TRAINING_DATA
  MLModelTrainingScheduled event triggers automatic retraining queue
  Human must approve promotion of retrained model (Platform Invariant 6)
```

#### Cold Start Protocol

Until an `MLModel` is in DEPLOYED status for a given `signal_type`:
- `MLInferenceService.generate_predictions()` returns an empty list with `cold_start_reason = AWAITING_DEPLOYED_MODEL`
- API surfaces this as HTTP 200 with `{"status": "AWAITING_MODEL", "available_from": null}`
- KPI computation and rule-based anomaly detection remain fully operational throughout
- Cold start is expected and documented; it is not an error condition

---

### C3 — Reporting Context Boundary

**Condition from Review:** The boundary between M32 `exposure_reporting` and M33 `reporting` must be explicit and non-overlapping.

#### Decision: Strict Non-Overlapping Ownership by Data Source and Time Orientation

The boundary is frozen as follows:

| Dimension | M32 `exposure_reporting` | M33 `reporting` |
|---|---|---|
| **Data source** | ExposureRecord, ExposureScoreSnapshot, BusinessImpactMapping (M32 operational tables) | analytics.kpi_snapshots, analytics.anomaly_detections, predictive_risk_signals (M33 analytics tables) |
| **Time orientation** | Current state ("What is the exposure RIGHT NOW?") | Trend / program ("How is the program performing OVER TIME?") |
| **Report types owned** | Board Risk Summary, Remediation Roadmap, Compliance Gap Report | Security Program Dashboard, Executive Security Report, Predictive Threat Forecast, Detection Analytics Report, Campaign Effectiveness Report |
| **API namespace** | `/api/v1/exposure-reporting/reports/` | `/api/v1/reporting/reports/` |
| **Security Graph writes** | Exposure nodes and exposure edges | Anomaly nodes, predictive risk nodes |
| **Narrative method** | 7 templates by dominant amplifier type (ADR-M32-005) | N templates by dominant KPI pattern (ADR-M33-001) |
| **Audience** | CISO (tactical: "our biggest risk today"), Risk Manager, Remediation Lead | CISO (strategic: "program health"), Security Analytics Engineer, Threat Intel Analyst |

#### Enforcement Rules

1. The `reporting` context in M33 may NEVER generate Board Risk Summary, Remediation Roadmap, or Compliance Gap Report. Those are M32's reports and M32 owns those template definitions.

2. M32 `exposure_reporting` may NEVER generate Security Program Dashboard, Executive Security Report, or Predictive Threat Forecast. Those are M33's.

3. An "Executive Security Report" in M33 is a program-effectiveness narrative: MTTD trend, ATT&CK coverage %, campaign success rate, AI risk trend. It is NOT a synonym for M32's "Board Risk Summary" (which is CTEM-specific and exposure-focused).

4. If a future combined C-suite report needs to merge CTEM exposure data (M32) with program KPI data (M33), it is produced by M33's `reporting` context using M33's `IExposureKPIQueryPort` to read M32's pre-computed KPI values — not by either context directly rendering the other's domain data.

5. `reporting` context does not import any type from `exposure_reporting` or vice versa. Any shared concepts (report artifact storage, delivery mechanism) are handled via the platform-level `IReportDeliveryPort` abstraction, not through shared domain types.

---

### C4 — KPI Mathematical Definitions

**Condition from Review:** Every M33 KPI must have a formally frozen mathematical definition with inputs, formula, aggregation, refresh cadence, historical behavior, and versioning.

#### KPI-1: MTTD — Mean Time to Detect

**Definition:** Average elapsed time between an offensive action being executed (in a campaign or red team exercise) and a corresponding detection finding being produced for the same technique on the same target asset.

**Inputs:**
- `analytics.execution_events`: `(tenant_id, attack_action_id, technique_id, target_asset_ref, executed_at)`
- `analytics.detection_events`: `(tenant_id, finding_id, technique_id, target_asset_ref, finding_created_at)`

**Correlation key:** `(tenant_id, technique_id, target_asset_ref)`

**Correlation window:** 24 hours (configurable via `analytics:admin`; range 1–168 hours)

**Formula (SQL-equivalent):**
```sql
WITH qualified_pairs AS (
  SELECT
    e.attack_action_id,
    d.finding_id,
    EXTRACT(EPOCH FROM (d.finding_created_at - e.executed_at)) AS detection_lag_seconds
  FROM analytics.execution_events e
  JOIN analytics.detection_events d
    ON  e.tenant_id         = d.tenant_id
    AND e.technique_id      = d.technique_id
    AND e.target_asset_ref  = d.target_asset_ref
    AND d.finding_created_at BETWEEN e.executed_at
                                 AND e.executed_at + INTERVAL ':correlation_window_hours hours'
  WHERE e.tenant_id = :tenant_id
    AND e.executed_at >= :period_start
    AND e.executed_at <  :period_end
)
SELECT
  AVG(detection_lag_seconds) / 3600.0          AS mttd_hours,
  PERCENTILE_CONT(0.50) WITHIN GROUP
    (ORDER BY detection_lag_seconds) / 3600.0  AS mttd_p50_hours,
  PERCENTILE_CONT(0.95) WITHIN GROUP
    (ORDER BY detection_lag_seconds) / 3600.0  AS mttd_p95_hours,
  COUNT(*)                                     AS qualified_pair_count
FROM qualified_pairs;
```

**Aggregation:** Mean of detection lags across all qualified (attack, detection) pairs in the period

**Minimum data requirement:** ≥ 10 qualified pairs; otherwise `KPIStatus.INSUFFICIENT_DATA`

**Prerequisite:** Requires M29/M30 execution events with `technique_id` and `target_asset_ref`. Status is `KPIStatus.INSUFFICIENT_DATA` for tenants without completed campaign execution data.

**Refresh cadence:** Daily at 02:00 UTC for last-30-day window

**Historical behavior:** Point-in-time snapshot stored per day. Dashboard displays 90-day rolling trend of daily MTTD values. Historical snapshots are immutable (computed once per day; never retroactively updated).

**Schema version:** `definition_version = 1`. Any formula change increments `definition_version`; historical snapshots retain their formula version for interpretability.

---

#### KPI-2: ATT&CK Coverage Percentage

**Definition:** Percentage of MITRE ATT&CK Enterprise techniques (current version) for which at least one active detection rule is deployed for the tenant.

**Inputs:**
- `analytics.detection_events`: active rules per technique (`event_type = 'detection_rule_activated'`, no subsequent `detection_rule_deprecated`)
- `analytics.attck_technique_reference`: materialized view of MITRE ATT&CK technique taxonomy (refreshed monthly from MITRE STIX data, version-tagged)

**Formula:**
```sql
WITH active_technique_rules AS (
  SELECT DISTINCT technique_id
  FROM analytics.detection_events a
  WHERE tenant_id = :tenant_id
    AND event_type = 'detection_rule_activated'
    AND NOT EXISTS (
      SELECT 1
      FROM analytics.detection_events d
      WHERE d.tenant_id     = a.tenant_id
        AND d.technique_id  = a.technique_id
        AND d.event_type    = 'detection_rule_deprecated'
        AND d.event_ts      > a.event_ts
    )
),
total_techniques AS (
  SELECT COUNT(*) AS cnt FROM analytics.attck_technique_reference
  WHERE attck_version = :current_attck_version
)
SELECT
  CAST(COUNT(atr.technique_id) AS DECIMAL) /
  NULLIF(t.cnt, 0) * 100.0 AS coverage_pct,
  COUNT(atr.technique_id) AS covered_techniques,
  t.cnt AS total_techniques
FROM active_technique_rules atr
CROSS JOIN total_techniques t;
```

**Aggregation:** Single percentage value at point in time

**Minimum data requirement:** None (0% is a valid result for tenants with no detection rules)

**ATT&CK version handling:** The `attck_technique_reference` table is versioned by `attck_version` string (e.g., `"v15.1"`). The current version is set via `analytics:admin` configuration. Historical snapshots record the ATT&CK version in effect at computation time.

**Refresh cadence:** Daily at 02:00 UTC

**Historical behavior:** Point-in-time percentage stored per day. Dashboard displays coverage % trend over 180 days.

**Schema version:** `definition_version = 1`

---

#### KPI-3: Exposure Score Trend

**Definition:** Week-over-week percentage change in the tenant-wide average exposure score. Negative values indicate improving posture (exposure decreasing). Positive values indicate degrading posture (exposure increasing).

**Inputs:**
- `analytics.exposure_events`: `(tenant_id, asset_ref_id, composite_score, event_type = 'exposure_score_computed', computed_at)`

**Formula:**
```sql
WITH current_window AS (
  -- Most recent score snapshot per asset in the current 7-day window
  SELECT asset_ref_id, composite_score
  FROM (
    SELECT asset_ref_id, composite_score,
           ROW_NUMBER() OVER (PARTITION BY asset_ref_id ORDER BY computed_at DESC) AS rn
    FROM analytics.exposure_events
    WHERE tenant_id  = :tenant_id
      AND event_type = 'exposure_score_computed'
      AND computed_at BETWEEN :period_end - INTERVAL '7 days' AND :period_end
  ) t WHERE rn = 1
),
prior_window AS (
  -- Most recent score snapshot per asset in the prior 7-day window
  SELECT asset_ref_id, composite_score
  FROM (
    SELECT asset_ref_id, composite_score,
           ROW_NUMBER() OVER (PARTITION BY asset_ref_id ORDER BY computed_at DESC) AS rn
    FROM analytics.exposure_events
    WHERE tenant_id  = :tenant_id
      AND event_type = 'exposure_score_computed'
      AND computed_at BETWEEN :period_end - INTERVAL '14 days' AND :period_end - INTERVAL '7 days'
  ) t WHERE rn = 1
)
SELECT
  AVG(c.composite_score) AS current_avg,
  AVG(p.composite_score) AS prior_avg,
  CASE WHEN AVG(p.composite_score) = 0 THEN NULL
       ELSE ((AVG(c.composite_score) - AVG(p.composite_score))
              / AVG(p.composite_score)) * 100.0
  END AS exposure_trend_pct
FROM current_window c
JOIN prior_window p ON c.asset_ref_id = p.asset_ref_id;
-- INNER JOIN: only assets with scores in BOTH windows contribute
```

**Minimum data requirement:** ≥ 10 assets with scores in both windows; otherwise `INSUFFICIENT_DATA`

**Requires:** M32 exposure score events. Status is `INSUFFICIENT_DATA` for tenants without M32.

**Refresh cadence:** Daily at 03:00 UTC (after M32 score computation window)

**Historical behavior:** Weekly trend value stored per day. Dashboard displays 52-week rolling trend.

**Schema version:** `definition_version = 1`

---

#### KPI-4: Campaign Success Rate

**Definition:** Percentage of technique-level detection tests executed within M29/M30 campaigns that resulted in a detection finding within the campaign's evaluation window.

**Inputs:**
- `analytics.campaign_events`: `(tenant_id, campaign_id, technique_count, detected_count, campaign_completed_at)` where `event_type = 'campaign_completed'`

**Formula:**
```sql
SELECT
  SUM(detected_count)  AS total_detected,
  SUM(technique_count) AS total_tested,
  CAST(SUM(detected_count) AS DECIMAL) /
  NULLIF(SUM(technique_count), 0) * 100.0 AS campaign_success_rate_pct,
  COUNT(*) AS campaign_count
FROM analytics.campaign_events
WHERE tenant_id         = :tenant_id
  AND event_type        = 'campaign_completed'
  AND campaign_completed_at >= :period_start
  AND campaign_completed_at <  :period_end;
```

**Aggregation:** Aggregated across all campaigns completed in the period (not average-of-averages; weighted by campaign size)

**Minimum data requirement:** ≥ 1 completed campaign; otherwise `INSUFFICIENT_DATA`

**Refresh cadence:** Triggered on each `CampaignCompleted` event (near-real-time); daily snapshot at 04:00 UTC

**Historical behavior:** Point-in-time rate stored per completed campaign and per week. Dashboard shows weekly trend.

**Schema version:** `definition_version = 1`

---

#### KPI-5: AI Risk Trend

**Definition:** Week-over-week percentage change in the tenant-wide average AI system risk score. Parallel structure to Exposure Score Trend (KPI-3) but scoped to AI assets.

**Inputs:**
- `analytics.ai_posture_events`: `(tenant_id, asset_ref_id, risk_score, event_type = 'ai_risk_score_computed', assessed_at)`

**Formula:** Identical structure to KPI-3 formula, substituting `ai_posture_events` for `exposure_events` and `risk_score` for `composite_score`.

**Minimum data requirement:** ≥ 5 AI assets with scores in both windows; otherwise `INSUFFICIENT_DATA`

**Requires:** M31 AI risk assessment events. Status is `INSUFFICIENT_DATA` for tenants without M31.

**Refresh cadence:** Daily at 03:00 UTC

**Historical behavior:** Weekly trend value stored per day.

**Schema version:** `definition_version = 1`

---

#### MTTR — Deferred (Schema Stub Only)

**Status:** Defined in schema; computation deferred to M34.

MTTR requires `IncidentClassified` and `IncidentResolved` events from M34, which is not yet implemented. The `KPIType.MTTR` enum value is present in the schema. `KPIComputationService` returns `KPIStatus.REQUIRES_M34_DATA` for MTTR on all tenants until M34 events populate `analytics.incident_events`. No M33 code change is required to enable MTTR when M34 is released — the `AnalyticsProjectionWorker` will automatically ingest M34 events as a new event type, and the `KPIComputationService` will detect the presence of incident data and compute MTTR.

---

### C5 — Analytics Query Security

**Condition from Review:** The AnalyticsQuery engine must enforce tenant isolation and prevent SQL injection. Every invariant must be frozen.

#### Decision: Mandatory Tenant Injection + Parameterized Binding + Schema Whitelist + Result Limits

The following invariants are frozen and apply to every query execution without exception:

**Invariant QS-1: Mandatory Tenant Parameter Injection**

Every stored `AnalyticsQuery.query_template` must contain the literal placeholder `:tenant_id` in its WHERE clause. This is validated at template creation time by `AnalyticsQueryValidationService`:

```python
def validate_template(template: str, parameters: list[QueryParameter]) -> None:
    # Static validation: reject templates without :tenant_id
    if ":tenant_id" not in template.lower():
        raise AnalyticsQueryValidationError("Template must contain :tenant_id parameter")

    # Execution-time: tenant_id is always injected from authenticated context,
    # never from caller-supplied parameters
    # Caller cannot supply tenant_id in their parameter dict; it is forcibly overwritten
```

At execution time, `AnalyticsQueryExecutionService` always injects `tenant_id` from the authenticated request context:

```python
def execute_query(auth_context: AuthContext, query_id, caller_parameters):
    query = self.repo.find_by_id(auth_context.tenant_id, query_id)
    # Force tenant_id from auth context; caller cannot override
    final_parameters = {**caller_parameters, "tenant_id": str(auth_context.tenant_id)}
    # Execute via parameterized binding (never string format)
    result = self.db.execute(
        sqlalchemy.text(query.query_template),
        final_parameters
    )
    return result
```

**Invariant QS-2: SQLAlchemy Parameterized Binding Only**

All parameter substitution uses SQLAlchemy `text()` with named `:param` placeholders. String interpolation (`f"{value}"`, `% value`, `.format(value)`) is permanently prohibited in query execution. This is enforced by:

1. Code review requirement: any PR touching query execution is reviewed against this invariant
2. Ruff custom rule: a `RUF999` project-local rule that flags string interpolation in `analytics/application/services/` module
3. Unit test: `test_injection_prevention.py` — attempts SQL injection via each parameter type and verifies parameter binding prevents execution of injected SQL

**Invariant QS-3: Schema Whitelist**

Template validation checks all table references in the template using a simple regex pattern for `FROM <schema>.<table>` and `JOIN <schema>.<table>`:

```python
ALLOWED_SCHEMAS = {"analytics"}

def _check_schema_references(template: str) -> None:
    # Match: schema.table or "schema"."table"
    schema_refs = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\.[a-zA-Z_]', template)
    for schema in schema_refs:
        if schema.lower() not in ALLOWED_SCHEMAS:
            raise AnalyticsQueryValidationError(
                f"Query references disallowed schema '{schema}'. "
                f"Only 'analytics' schema is permitted."
            )
```

**Invariant QS-4: Result Set Limits**

The query executor always wraps every template in a paginated result:

```python
PAGINATED_TEMPLATE = """
    WITH _user_query AS ({template})
    SELECT * FROM _user_query
    LIMIT :_max_rows OFFSET :_offset
"""

MAX_ROWS_DEFAULT = 1000
MAX_ROWS_ABSOLUTE = 10_000  # Cannot be overridden by caller
```

**Invariant QS-5: Authorization Tiers**

| Query `domain` | Minimum Required Role | Notes |
|---|---|---|
| Single domain (VULNERABILITY, DETECTION, etc.) | `analytics:analyst` | Standard analyst access |
| `CROSS_DOMAIN` | `analytics:engineer` | Queries joining multiple domain event tables |
| Tenant-unscoped (admin diagnostic) | `analytics:admin` | Never exposed via user-facing API |

**Invariant QS-6: Mandatory Audit Log**

Every `ExecuteAnalyticsQuery` command produces an `analytics_query_audit_log` entry:

```
analytics_query_audit_log:
  audit_id, tenant_id, executed_by, query_id, query_name,
  parameters_json, row_count, duration_ms, executed_at
```

Audit log entries are append-only and retained for 2 years minimum. They are accessible to `analytics:admin` via the audit endpoint. Failed executions produce an audit entry with `row_count = 0` and `error_reason`.

---

### C6 — ML Artifact Security

**Condition from Review:** ML model artifact storage must enforce tenant isolation, integrity, and appropriate lifecycle management.

#### Decision: PostgreSQL BYTEA Storage with Tenant Isolation, Hash Integrity, and Soft-Delete Lifecycle

**Storage schema:**

```sql
CREATE TABLE analytics.ml_model_artifacts (
    artifact_id      UUID         NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id        UUID         NOT NULL,
    model_id         UUID         NOT NULL REFERENCES analytics.ml_models(id),
    artifact_bytes   BYTEA        NOT NULL,
    artifact_hash    VARCHAR(64)  NOT NULL,   -- SHA-256 of artifact_bytes
    artifact_size_b  INTEGER      NOT NULL,
    algorithm        VARCHAR(50)  NOT NULL,   -- e.g., "IsolationForest"
    framework        VARCHAR(50)  NOT NULL DEFAULT 'scikit-learn',
    framework_version VARCHAR(20) NOT NULL,
    python_version   VARCHAR(20)  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    created_by       VARCHAR(255) NOT NULL,
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    deactivated_at   TIMESTAMPTZ,
    deactivated_by   VARCHAR(255)
);

CREATE INDEX idx_ml_model_artifacts_tenant ON analytics.ml_model_artifacts(tenant_id, is_active);
CREATE INDEX idx_ml_model_artifacts_model ON analytics.ml_model_artifacts(model_id);
```

**Tenant Isolation:** The `IMLModelArtifactStore` interface requires `tenant_id` as the first positional argument on all operations. Repository implementations enforce `WHERE tenant_id = :tenant_id` on all reads. Cross-tenant artifact access is structurally impossible at the repository layer.

**Integrity Verification:**

```python
def store_artifact(tenant_id: TenantId, model_id: MLModelId, artifact_bytes: bytes) -> str:
    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
    # Validate size limit
    if len(artifact_bytes) > 500 * 1024 * 1024:  # 500MB hard limit
        raise ArtifactTooLargeError(f"Artifact {len(artifact_bytes)} bytes exceeds 500MB limit")
    # Store with hash
    ...

def load_artifact(tenant_id: TenantId, artifact_ref: str) -> bytes:
    row = db.execute("SELECT artifact_bytes, artifact_hash FROM analytics.ml_model_artifacts "
                     "WHERE artifact_id = :id AND tenant_id = :tid AND is_active = true",
                     {"id": artifact_ref, "tid": str(tenant_id)})
    if not row:
        raise ArtifactNotFoundError(artifact_ref)
    # Verify integrity on load
    computed_hash = hashlib.sha256(row.artifact_bytes).hexdigest()
    if computed_hash != row.artifact_hash:
        raise ArtifactIntegrityError(f"Hash mismatch for artifact {artifact_ref}")
    return row.artifact_bytes
```

**Versioning:** Multiple artifact versions per `model_id` are permitted (each training run creates a new artifact row). Only the artifact linked to the currently DEPLOYED `MLModel` is served for inference. Previous versions remain in the table with `is_active = true` until the model is deprecated.

**Lifecycle:**

| MLModel status | Artifact `is_active` |
|---|---|
| TRAINING | Not yet created |
| TRAINED | `true` |
| DEPLOYED | `true` |
| DEPRECATED | `true` → `false` (set by `ModelGovernanceService.deprecate_model()`) |
| FAILED | Not created (training failed before serialization) |

Physical deletion of `is_active = false` artifacts follows the platform retention policy (compliance engineering workflow only). No M33 code performs physical deletion of artifact rows.

**Encryption:** PostgreSQL data-at-rest encryption is the infrastructure responsibility (pgcrypto extension or TDE at deployment layer). M33 does not implement application-level artifact encryption in this milestone. Application-level encryption (AES-256 of artifact bytes before storage) is deferred to post-M33 based on the platform's key management infrastructure availability.

**No Filesystem Storage:** All artifact storage is database-mediated. No filesystem path is used. No object storage (S3, GCS, Azure Blob) in M33. These are future `IMLModelArtifactStore` implementations, not the default.

---

### C7 — Analytics Scale: Caching, Materialized Projections, Workers, Partitioning

**Condition from Review:** Caching strategy, materialized projections, scheduler, workers, background processing, and partition strategy must all be frozen.

#### Decision: Pre-Computed Projections + Schedule-Based Workers + Hash/Range Partitioning

**No On-Demand Computation for Dashboard Queries**

KPI values, anomaly detections, and predictive risk signals are NEVER computed on-demand at API query time. Every value served to the API is pre-computed and stored by a background worker. This is an absolute architectural rule:

```
Dashboard query → read analytics.kpi_snapshots (pre-computed; sub-millisecond PostgreSQL read)
Anomaly query   → read analytics.anomaly_detections (pre-computed)
Prediction query → read analytics.predictive_risk_signals (pre-computed)
Report generation → aggregate from kpi_snapshots + anomaly_detections (pre-computed inputs)
```

No in-memory application cache (Redis, Memcached) is required in M33 for dashboard queries. PostgreSQL index scans on partition-pruned `kpi_snapshots` complete in < 5ms for single-tenant reads.

**Partition Strategy (frozen)**

```
analytics.vulnerability_events:   HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.detection_events:        HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.execution_events:        HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.campaign_events:         HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.exposure_events:         HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.ai_posture_events:       HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly)
analytics.kpi_snapshots:           HASH(tenant_id, 8 partitions) × RANGE(snapshot_at, quarterly)
analytics.anomaly_detections:      HASH(tenant_id, 8 partitions) × RANGE(detected_at, quarterly)
analytics.ml_model_artifacts:      HASH(tenant_id, 8 partitions) [no time partitioning]
analytics.predictive_risk_signals: HASH(tenant_id, 8 partitions) × RANGE(computed_at, monthly)
```

Sub-partition creation: monthly sub-partitions are created 30 days in advance by `PartitionMaintenanceWorker`. If a sub-partition does not exist when a row arrives, the default partition receives it; the next maintenance run splits it. This is a PostgreSQL standard pattern.

**Worker Architecture (frozen)**

| Worker | Trigger | Schedule | Max Concurrency | Idempotent | Failure Mode |
|---|---|---|---|---|---|
| `AnalyticsProjectionWorker` | Event bus (continuous) | Continuous | 4 workers (one per event stream domain) | Yes (processed_analytics_events) | DLQ + 3× exponential backoff |
| `KPIComputationWorker` | Cron | Daily per KPI type (staggered 02:00–05:00 UTC) | 1 per KPI type | Yes (idempotent re-compute; overwrites snapshot) | Alert + skip; prior snapshot remains |
| `MLTrainingWorker` | Command-triggered | On-demand | 1 per tenant | Yes (job_id deduplication) | MLModelTrainingFailed event + alert |
| `MLInferenceWorker` | Cron | Daily 04:00 UTC | 1 globally | Yes (expires_at-based staleness) | No new predictions; expired predictions removed |
| `DriftCheckWorker` | Cron | Weekly Sunday 00:00 UTC | 1 globally | Yes | Alert; model status unchanged |
| `ReportSchedulerWorker` | Cron | Every 5 minutes | 1 globally | Yes (ScheduledReport.last_run_at check) | DLQ; ReportInstance.status → FAILED |
| `RetentionPolicyWorker` | Cron | Daily 03:00 UTC | 1 globally | Yes (archived flag; no-op on already-archived rows) | Skip; retry next day |
| `PartitionMaintenanceWorker` | Cron | Monthly 01:00 UTC | 1 globally | Yes | Alert; defer to next run |
| `ProjectionRebuildWorker` | Command-triggered | On-demand | 1 per tenant | Yes (checkpoint-based) | Alert; AnalyticsDataSet.status → ERROR |

All workers are supervised by the platform `RuntimeContainer` (Sprint 26). Workers run as async background tasks within the FastAPI process. `MLTrainingWorker` is the primary candidate for extraction to a separate process if CPU-intensive training blocks the event loop — this is an operational assessment deferred to post-Phase 3 load testing.

**KPI Computation Schedule (staggered to prevent resource contention):**

| KPI | Start Time UTC |
|---|---|
| ATT&CK Coverage % | 02:00 |
| MTTD | 02:15 |
| Campaign Success Rate | 02:30 |
| Exposure Trend | 03:00 (after M32 score computation) |
| AI Risk Trend | 03:15 |
| MTTR (stub) | 03:30 (returns REQUIRES_M34_DATA immediately) |

---

## 2. Frozen DDD Model

### Bounded Context Summary

| Context | Module Path | Role | Aggregates |
|---|---|---|---|
| `analytics` | `backend/src/analytics/` | Core Domain | AnalyticsDataSet, SecurityKPI, AnalyticsQuery, AnomalyDetectionBaseline |
| `ml_pipeline` | `backend/src/ml_pipeline/` | Supporting | MLModel, PredictiveRiskSignal |
| `reporting` | `backend/src/reporting/` | Supporting | ReportTemplate, ScheduledReport, ReportInstance |

### Frozen Aggregate Ownership

**`analytics` context owns:**
- `AnalyticsDataSet` — projection registration and checkpoint tracking
- `SecurityKPI` — KPI definition, computation schedule, latest value
- `AnalyticsQuery` — stored parameterized query templates
- `AnomalyDetectionBaseline` — statistical baseline per signal type

**`ml_pipeline` context owns:**
- `MLModel` — ML model lifecycle (training, deployment, deprecation)
- `PredictiveRiskSignal` — ML-generated prediction per asset (point-in-time; carries TTL)

**`reporting` context owns:**
- `ReportTemplate` — report structure and section definitions
- `ScheduledReport` — recurring report generation configuration
- `ReportInstance` — a specific report generation run and its artifact

### Frozen Value Objects

**`analytics` context:**
```
SecurityDomain(Enum): VULNERABILITY | DETECTION | RED_TEAM | CAMPAIGN | EXPOSURE | AI_POSTURE | CROSS_DOMAIN
KPIType(Enum): MTTD | COVERAGE_PCT | EXPOSURE_TREND | CAMPAIGN_SUCCESS_RATE | AI_RISK_TREND | MTTR [stub]
KPIStatus(Enum): ACTIVE | COMPUTING | INSUFFICIENT_DATA | REQUIRES_M34_DATA | ERROR
DataSetStatus(Enum): ACTIVE | REBUILDING | PAUSED | DEPRECATED | ERROR
AnomalySignalType(Enum): VULNERABILITY_INGEST_RATE | DETECTION_FP_RATE | CAMPAIGN_EVASION_RATE | EXPOSURE_SCORE_DELTA | AI_RISK_SCORE_DELTA
DetectionMethod(Enum): ZSCORE | IQR | IQR_ROLLING | ML_ISOLATION_FOREST [Phase 3+]
AnomalySeverity(Enum): INFO | WARNING | CRITICAL
```

**`ml_pipeline` context:**
```
MLModelType(Enum): ANOMALY_DETECTOR | RISK_PREDICTOR | COVERAGE_FORECASTER
MLAlgorithm(Enum): ISOLATION_FOREST | RANDOM_FOREST | LINEAR_REGRESSION | GRADIENT_BOOST [Phase 3+]
MLModelStatus(Enum): TRAINING | TRAINED | DEPLOYED | DEPRECATED | FAILED
PredictiveSignalType(Enum): TECHNIQUE_EXPLOITATION_PROBABILITY | EXPOSURE_SCORE_FORECAST | COVERAGE_GAP_RISK
```

**`reporting` context:**
```
ReportType(Enum): SECURITY_PROGRAM_DASHBOARD | EXECUTIVE_SECURITY_REPORT | PREDICTIVE_THREAT_FORECAST | DETECTION_ANALYTICS | CAMPAIGN_EFFECTIVENESS
ReportFormat(Enum): PDF | HTML | JSON | CSV
ReportStatus(Enum): PENDING | GENERATING | COMPLETE | FAILED
ScheduledReportStatus(Enum): ACTIVE | PAUSED | ERROR
ReportTrigger(Enum): SCHEDULED | ON_DEMAND
```

### Frozen Repository Interfaces

All repository interfaces require `tenant_id` as the first positional argument. No repository method is callable without `TenantId`. Cross-tenant access raises `TenantContextMissingError` (hard failure).

```
IAnalyticsDataSetRepository
  find_by_id(tenant_id, dataset_id) → Optional[AnalyticsDataSet]
  find_by_domain(tenant_id, domain) → List[AnalyticsDataSet]
  find_all_active(tenant_id) → List[AnalyticsDataSet]
  save(tenant_id, dataset) → None

ISecurityKPIRepository
  find_by_id(tenant_id, kpi_id) → Optional[SecurityKPI]
  find_by_type(tenant_id, kpi_type) → Optional[SecurityKPI]
  find_due_for_computation(now) → List[SecurityKPI]  [cross-tenant; supervisor-only; no tenant_id]
  save(tenant_id, kpi) → None

IAnomalyDetectionBaselineRepository
  find_by_signal_type(tenant_id, signal_type) → Optional[AnomalyDetectionBaseline]
  save(tenant_id, baseline) → None

IAnalyticsQueryRepository
  find_by_id(tenant_id, query_id) → Optional[AnalyticsQuery]
  find_all(tenant_id) → List[AnalyticsQuery]
  save(tenant_id, query) → None

IMLModelRepository
  find_by_id(tenant_id, model_id) → Optional[MLModel]
  find_deployed_by_type(tenant_id, model_type) → Optional[MLModel]
  find_models_for_drift_check(last_checked_before) → List[MLModel]  [cross-tenant; supervisor-only]
  save(tenant_id, model) → None

IPredictiveRiskSignalRepository
  find_by_asset(tenant_id, asset_ref_id) → List[PredictiveRiskSignal]
  find_active_by_type(tenant_id, signal_type) → List[PredictiveRiskSignal]
  save(tenant_id, signal) → None
  delete_expired(before) → int  [cleanup; cross-tenant; no business state change]

IMLModelArtifactStore
  store_artifact(tenant_id, model_id, artifact_bytes) → str [returns artifact_ref]
  load_artifact(tenant_id, artifact_ref) → bytes  [verifies hash on load]
  deactivate_artifact(tenant_id, artifact_ref) → None

IReportTemplateRepository
  find_by_id(template_id) → Optional[ReportTemplate]  [platform templates are tenant-unscoped]
  find_by_type_for_tenant(tenant_id, report_type) → Optional[ReportTemplate]
  save(template) → None

IScheduledReportRepository
  find_by_id(tenant_id, schedule_id) → Optional[ScheduledReport]
  find_due(now) → List[ScheduledReport]  [cross-tenant; scheduler-only]
  save(tenant_id, schedule) → None

IReportInstanceRepository
  find_by_id(tenant_id, instance_id) → Optional[ReportInstance]
  find_by_template(tenant_id, template_id, date_range) → List[ReportInstance]
  save(tenant_id, instance) → None
```

### Frozen Outbound Ports (ACL)

All ports are READ-ONLY from upstream contexts. No port may trigger a write in any upstream bounded context.

**`analytics` context ports:**
```
IVulnerabilityAnalyticsPort   → reads M27 events for analytics projection
IDetectionAnalyticsPort       → reads M28 events for analytics projection
ICampaignAnalyticsPort        → reads M29/M30 events for analytics projection
IExposureAnalyticsPort        → reads M32 events for analytics projection
IAIPostureAnalyticsPort       → reads M31 events for analytics projection
IEventStoreReplayPort         → reads platform event_store for projection rebuild
ISecurityGraphWritePort       → write-only; anomaly nodes (append-only)
IATTCKReferencePort           → reads MITRE ATT&CK STIX data (external; cached monthly)
```

**`ml_pipeline` context ports:**
```
IAnalyticsDataQueryPort       → reads from analytics projection tables (via analytics service)
IMLTrainingPort               → abstract: in-process (default) or external ML platform adapter
ISecurityGraphWritePort       → write-only; predictive risk nodes (append-only)
```

**`reporting` context ports:**
```
IAnalyticsKPIQueryPort        → reads KPI snapshots from analytics BC
IMLSignalQueryPort            → reads predictive risk signals from ml_pipeline BC
IReportDeliveryPort           → abstract: email / webhook / storage
IBIExportPort                 → abstract: Tableau / Power BI / Looker connector
IExposureKPIQueryPort         → reads M32 exposure summaries for combined reports [read-only]
```

### Frozen Events

**`analytics` produces:**
```
AnalyticsDataSetRegistered(dataset_id, domain, schema_version, tenant_id)
AnalyticsDataSetPopulated(dataset_id, records_ingested, checkpoint, tenant_id)
AnalyticsDataSetRebuildStarted(dataset_id, tenant_id)
AnalyticsDataSetRebuildCompleted(dataset_id, tenant_id)
KPIComputed(kpi_id, kpi_type, value, unit, computed_at, definition_version, tenant_id)
KPIComputationFailed(kpi_id, kpi_type, error_reason, tenant_id)
KPIInsufficientData(kpi_id, kpi_type, minimum_required, available, tenant_id)
AnomalyBaselineBootstrapped(baseline_id, signal_type, method, sample_size, tenant_id)
AnomalyDetected(baseline_id, signal_type, observed_value, threshold, severity, tenant_id)
AnalyticsQueryCreated(query_id, name, domain, tenant_id)
AnalyticsQueryExecuted(query_id, executed_by, row_count, duration_ms, tenant_id)
```

**`ml_pipeline` produces:**
```
MLModelTrainingStarted(model_id, model_type, algorithm, dataset_id, tenant_id)
MLModelTrained(model_id, accuracy_metrics, artifact_ref, tenant_id)
MLModelTrainingFailed(model_id, error_reason, tenant_id)
MLModelDeployed(model_id, deployed_by, tenant_id)
MLModelDriftDetected(model_id, psi_score, threshold, auto_deprecated, tenant_id)
MLModelDeprecated(model_id, deprecated_by, tenant_id)
PredictiveRiskSignalsGenerated(model_id, asset_count, signal_type, tenant_id)
```

**`reporting` produces:**
```
ReportGenerationStarted(instance_id, template_id, triggered_by, tenant_id)
ReportGenerationCompleted(instance_id, template_id, artifact_ref, tenant_id)
ReportGenerationFailed(instance_id, error_reason, tenant_id)
ReportDelivered(instance_id, recipient_count, tenant_id)
ScheduledReportCreated(schedule_id, template_id, schedule, tenant_id)
DataExportStarted(export_job_id, dataset_id, format, tenant_id)
DataExportCompleted(export_job_id, record_count, tenant_id)
```

### RBAC Roles (Canonical)

Following the `{context}:{function}` platform naming convention:

| Role | Capabilities |
|---|---|
| `analytics:viewer` | Read KPI values, read anomaly list, read report instances, read predictive signals |
| `analytics:analyst` | `analytics:viewer` + execute stored queries, generate on-demand reports |
| `analytics:engineer` | `analytics:analyst` + create/update stored queries, define custom KPIs, manage datasets, cross-domain queries, manage BI exports |
| `analytics:admin` | `analytics:engineer` + configure ML model training/promotion, manage retention policy, manage BI connectors, access audit logs, trigger projection rebuild |

No role aliases. These canonical identifiers are used in authorization policies, audit logs, API responses, and database records.

---

## 3. ADRs (ADR-M33-001 through ADR-M33-006)

---

### ADR-M33-001 — Template-Driven Report Narrative; No LLM in M33

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** M33's `reporting` context generates executive-level security program reports. Options: template-driven generation (deterministic, auditable), LLM-generated narrative (richer, non-deterministic), or hybrid.

**Decision:** M33 uses deterministic multi-variant template selection for all narrative generation. No LLM client dependency is permitted in the `reporting` bounded context in M33. Template selection logic uses the dominant KPI pattern (worst KPI trend) to select from a library of report narrative templates. LLM-assisted narrative enhancement is explicitly deferred to M36.

**Consequences:**

Positive: Deterministic (identical inputs → identical outputs); fully auditable; no LLM API dependency in the critical reporting path; consistent with ADR-M32-005 (M32 `exposure_reporting` made the same decision for the same reasons).

Negative: Templates may read as formulaic for unusual KPI combinations. Accepted trade-off: audit compliance and determinism outweigh narrative richness in M33.

**Rejected alternative:** LLM narrative in M33 — introduces non-determinism, creates an external API dependency in the critical reporting path, risks violating Platform Invariant 7.

**Consistency:** Follows ADR-M32-005 exactly. The same architectural decision for the same architectural reasons. LLM narrative deferred to M36 for both reporting contexts.

---

### ADR-M33-002 — PredictiveRiskSignal Is Advisory-Only; Does Not Modify Upstream Scores

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** M33's `ml_pipeline` context generates `PredictiveRiskSignal` records — ML-enhanced probability scores for asset risk. There is an architectural question of whether these signals should be fed back into M27 vulnerability scores or M32 exposure scores to "enhance" them.

**Decision:** `PredictiveRiskSignal` is advisory-only. It is stored exclusively in M33's own `predictive_risk_signals` table and served via `IMLSignalQueryPort`. It never modifies any aggregate in M27, M32, M31, or any other upstream bounded context. Consumers (API, reports, dashboards) present it as a supplementary signal alongside, not in place of, the primary domain scores.

**Consequences:**

Positive: Platform Invariant 7 (AI suggestions read-only at domain boundaries) is upheld. No cross-context write dependency. Upstream context scores are always computable without M33. M33 can be removed without affecting any operational context.

Negative: Operators must consult two signals (rule-based score + ML prediction) rather than one unified score. Accepted trade-off: the architectural integrity is more important than the UX convenience. A future "blended score" feature, if required, would be designed as an explicit M32 extension accepting M33 signal as a configured input — not a backdoor write from M33.

**Rejected alternative:** ML predictions feed back into M32 exposure score computation — violates Invariant 7 and creates a circular dependency (M32 computes scores; M33 trains on M32 scores; M33 writes back to M32 scores; scores trained on their own derivatives).

---

### ADR-M33-003 — PostgreSQL Analytics Schema as Primary Data Lake; Cloud Backends Are Port-Only

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** The roadmap describes a "security data lake" with optional cloud backends (BigQuery, Redshift, Snowflake). The question is whether M33 should implement a cloud backend as the primary store or use PostgreSQL.

**Decision:** PostgreSQL with a dedicated `analytics` schema is the permanent primary data lake implementation. Hash/range partitioning provides the scalability characteristics required for M33's analytical workloads without introducing a separate database technology. Cloud analytics backends (BigQuery, Redshift, Snowflake) are implementations of `IAnalyticsBackendPort` — the interface is defined in M33; no adapter is implemented in M33.

**Rationale:**
1. Platform consistency: every other bounded context uses PostgreSQL. Adding a second database technology in M33 increases operational complexity, increases infrastructure cost, and introduces a new failure domain.
2. For M33's initial workloads (tens of millions of events per tenant, 10-50 tenants), PostgreSQL with proper partitioning is sufficient. The performance SLO (KPI dashboard query < 50ms) is achievable with pre-computed KPI snapshots and partition pruning.
3. The abstraction port `IAnalyticsBackendPort` ensures that if PostgreSQL becomes a bottleneck at scale, a BigQuery adapter can be plugged in without changing any domain code.

**Consequences:**

Positive: Single database technology; no additional infrastructure; consistent operational model; production-proven scale for M33's realistic data volumes.

Negative: If a tenant reaches 1B+ events/year, PostgreSQL partitioning may require careful management. Mitigated by: retention policy (2-year default), pre-computed KPI snapshots (queries never hit raw event tables for dashboard reads), and the port abstraction for future cloud backend migration.

**Rejected alternative:** BigQuery as primary data lake — adds a required GCP dependency, increases infrastructure cost, breaks PostgreSQL-only deployment model, and is over-engineered for M33's realistic initial data volumes.

---

### ADR-M33-004 — KPI Computation Is Always Pre-Computed; Never On-Demand

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** KPI dashboard queries could be computed on-demand at query time or pre-computed by background workers and served from a snapshot table. On-demand computation eliminates eventual consistency but requires full analytical query execution on every API request.

**Decision:** All KPI values served via API are pre-computed by `KPIComputationWorker` on a scheduled basis and stored in `analytics.kpi_snapshots`. No KPI computation occurs on the API request path. API requests read from the snapshot table only.

**Rationale:**
1. Performance: KPI computation (especially MTTD which requires a join across two large event tables) takes 1–30 seconds depending on data volume. This is not acceptable on the API request path.
2. Consistency: KPI snapshots are point-in-time consistent. On-demand computation would produce slightly different values on each call as new events arrive. For program effectiveness measurement, daily consistency is more meaningful than sub-second freshness.
3. Simplicity: API layer is a simple read-only projection consumer. No business logic on the read path.

**Eventual consistency model:** KPI values are at most 24 hours stale (refreshed daily). This is explicitly acceptable for security program KPIs — a CISO reviewing MTTD does not need sub-hour precision.

**Consequences:**

Positive: Sub-millisecond API response for KPI reads; API layer is stateless and simple; KPI workers can be scaled and monitored independently.

Negative: 24-hour staleness on KPI values. Mitigated by: `snapshot_at` timestamp always visible in API response so consumers know how fresh the data is.

**Rejected alternative:** On-demand KPI computation — unacceptable latency for complex cross-table KPI queries at scale.

---

### ADR-M33-005 — Mandatory Tenant Isolation at Analytics Service Layer; Not Database Layer Alone

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** Tenant isolation in the analytics query engine could be enforced at the database level (PostgreSQL row-level security), the application service layer, or both. The question is which layer is the authoritative isolation enforcement point.

**Decision:** Tenant isolation is enforced at the application service layer AND the database layer as defense-in-depth. The application service layer is the authoritative enforcement point; the database layer provides a second line of defense.

**Application service layer:** `AnalyticsQueryExecutionService` always injects `tenant_id` from the authenticated request context into every query (see C5, QS-1). This cannot be overridden by caller-supplied parameters.

**Database layer:** Row-Level Security (RLS) on analytics projection tables enforces `tenant_id = current_setting('app.current_tenant_id')`. The `analytics_reader` database role has RLS enabled. The application sets `app.current_tenant_id` at the start of every database session.

Defense-in-depth rationale: the application service layer can in principle be bypassed by a developer making a direct database connection. RLS ensures that even a direct database connection to the `analytics_reader` role cannot read another tenant's data.

**Consequences:**

Positive: Two independent isolation enforcement points; no single point of tenant isolation failure; RLS provides isolation even during development/debug access.

Negative: Slightly more complex database setup (RLS configuration per partition). Accepted: RLS configuration is a one-time setup in the migration; no ongoing complexity.

---

### ADR-M33-006 — ML Model Promotion Requires Human Approval; Training Is Automatic

**Status:** Accepted  
**Date:** 2026-07-21  

**Context:** ML model training can be triggered automatically (on schedule or when sufficient data accumulates). Should model promotion to DEPLOYED status also be automatic, or does it require human approval per Platform Invariant 6?

**Decision:** ML model training scheduling and execution is automatic (no human approval required). ML model promotion from TRAINED to DEPLOYED status requires explicit human approval via `PromoteMLModel` command (role: `analytics:admin`). Automatic promotion is prohibited.

**Rationale:** Platform Invariant 6 (Human Approval Gates Cannot Be Bypassed by Configuration) applies to ML model deployment because deployed models produce `PredictiveRiskSignal` records that influence security decision-making. A model trained on corrupted or biased data should not be deployed without human review of its accuracy metrics.

**Training schedule:** Triggered by the `MLTrainingScheduler` on a weekly basis (or when data accumulation crosses the minimum training data threshold for the first time). No human approval required for training runs.

**Accuracy review:** The `analytics:admin` reviews `MLModel.accuracy_metrics` before issuing `PromoteMLModel`. The accuracy thresholds (C2 decision) provide a first gate; human review is the second gate for semantic accuracy (not just metric thresholds).

**Consequences:**

Positive: Platform Invariant 6 upheld; no automated modification of ML-driven security signals without human sign-off; consistent with M28 (detection rule activation requires human) and M35 (playbook activation requires human).

Negative: Newly trained models require manual promotion; a site without active `analytics:admin` oversight could accumulate TRAINED models that are never promoted. Mitigated by: alert when a TRAINED model has been awaiting promotion for > 7 days.

---

## 4. Architecture Corrections

The following corrections apply to `M33_ARCHITECTURE_REVIEW.md` based on decisions C1–C7. These corrections are the authoritative overrides.

### Correction CC1 — Analytics Projection Table Schema
The Review mentioned analytics projection tables without specifying the partitioning scheme. C1 now specifies: HASH(tenant_id, 16 partitions) × RANGE(event_ts, monthly) for event tables; HASH(tenant_id, 8 partitions) × RANGE(snapshot_at, quarterly) for kpi_snapshots. This replaces the Review's under-specified description.

### Correction CC2 — ML Pipeline Scope
The Review described the ML pipeline as "model training, deployment, and inference serving" without explicit scoping. C2 now explicitly restricts M33 ML to in-process scikit-learn (CPU-only; no GPU; max 30-minute training wall time). External ML platform adapters are port-only; no implementations in M33.

### Correction CC3 — MTTR KPI Status
The Review flagged MTTR as a condition. C4 now resolves: MTTR is a `KPIType` enum value present in the schema but returns `KPIStatus.REQUIRES_M34_DATA` on all tenants. The computation logic is a no-op stub in M33. No M33 code change is needed when M34 is released — the projection worker automatically ingests incident events and the computation service detects their presence.

### Correction CC4 — AnalyticsQuery Schema Whitelist Scope
The Review stated query templates "may only reference tables in the `analytics` schema." C5 now specifies that this is enforced by a static validator at template creation time (not only at execution time), using regex to detect cross-schema references.

### Correction CC5 — Reporting Context Boundary
The Review described the boundary between M32 `exposure_reporting` and M33 `reporting` at a high level. C3 now provides a complete non-overlapping taxonomy with explicit ownership rules and enforcement constraints for each dimension (data source, time orientation, report types, API namespace, security graph ownership).

---

## 5. Risk Dispositions (R01–R09)

---

### R01 — Cross-Tenant Leakage in Analytics Query Engine
**Original severity:** CRITICAL  
**Disposition:** MITIGATED  
**Resolution:** C5 specifies five mandatory invariants (QS-1 through QS-6): mandatory tenant injection from auth context (cannot be overridden), SQL parameter binding only, schema whitelist validation at template creation, result set limits, role-based authorization, and mandatory audit log. ADR-M33-005 adds RLS at database layer as second line of defense.

No residual risk at architectural level. Residual operational risk (misuse by analytics:admin) is accepted as inherent to any admin role.

---

### R02 — Analytics Data Volume Exceeds Query Limits
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** C7 specifies the complete mitigation: (a) all dashboard/KPI queries read pre-computed kpi_snapshots (never raw event tables); (b) hash × range partitioning enables PostgreSQL partition pruning to eliminate irrelevant data; (c) KPI computation workers run off-peak to avoid query contention. Residual risk (projection table size at 5+ year retention for large tenants) is managed by retention policy (C1).

---

### R03 — ML Model Drift Degrades Signal Quality
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** C2 specifies: (a) weekly PSI-based drift detection; (b) PSI ≥ 0.20 triggers auto-deprecation; (c) all PredictiveRiskSignal records carry expires_at (30-day TTL); expired signals not served; (d) accuracy metrics visible to analytics:admin; (e) auto-deprecated model triggers retraining queue. ADR-M33-006 ensures human approval for re-promotion after retraining.

Residual risk (PSI threshold may be miscalibrated for a specific model type): accepted. Mitigated by: `analytics:admin` can manually deprecate any deployed model at any time.

---

### R04 — Cold Start: No Analytics Value at Initial Deployment
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** C1 specifies `ProjectionRebuildWorker` which performs historical backfill from the platform event store on tenant onboarding. Target completion: 2–4 hours for large estates. KPIs and rule-based anomaly detection are available immediately after backfill completes. ML-based predictions require an additional 90 days of post-backfill data — this is the documented, expected cold start for ML-based capabilities. Not an architectural defect.

---

### R05 — AnalyticsQuery Template SQL Injection
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** C5 Invariant QS-2 (parameterized binding only) + static analysis enforcement + unit test coverage (`test_injection_prevention.py`). The `AnalyticsQueryExecutionService` uses SQLAlchemy `text()` exclusively. String formatting is structurally not present in the execution path.

---

### R06 — ML Model Artifact Security
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** C6 specifies PostgreSQL BYTEA storage with tenant-scoped repository enforcement, SHA-256 integrity hash on every artifact (verified at load time), soft-delete lifecycle (is_active flag), and no shared filesystem path. Application-level encryption deferred to post-M33 pending platform key management infrastructure. This deferral is accepted; PostgreSQL data-at-rest encryption at the infrastructure layer provides adequate protection for M33.

---

### R07 — Reporting LLM Dependency Creep
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** ADR-M33-001 explicitly prohibits LLM client dependency in the `reporting` context for M33. Template-driven narrative is the architectural decision. This ADR is the governance mechanism: any PR introducing LLM client dependency in `reporting` is blocked at review against ADR-M33-001.

---

### R08 — MTTR KPI Incorrectly Defined Without M34
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** C4 resolution: MTTR is a `KPIType` enum value with computation stub returning `KPIStatus.REQUIRES_M34_DATA`. The KPI is defined in schema but not computed. No incorrect results; no misleading dashboard state. MTTR activates automatically when M34 incident events populate the analytics projection tables.

---

### R09 — Reporting Overlap with M32 `exposure_reporting`
**Original severity:** LOW  
**Disposition:** MITIGATED  
**Resolution:** C3 provides complete non-overlapping ownership taxonomy. Five explicit enforcement rules prevent capability drift. ADR-M33-001 further cements the separate report type ownership by specifying different template sets for the two contexts.

---

## 6. Frozen Phase Plan

---

### Phase 1 — Analytics Foundation

**Scope:** `analytics` bounded context core. Analytics schema and projection tables. Event subscription and ingestion pipeline (all six domain event streams). KPI infrastructure: definition, computation worker, snapshot storage. Five KPI types (including MTTR stub). Rule-based anomaly detection (Z-score and IQR). ProjectionRebuildWorker. Historical backfill on tenant onboarding. RetentionPolicyWorker. PartitionMaintenanceWorker. Analytics RBAC.

**Bounded Contexts:** `analytics`

**Aggregates:** `AnalyticsDataSet`, `SecurityKPI`, `AnomalyDetectionBaseline`

**Domain Services:**
- `KPIComputationService` (all 5 KPI formulas; MTTR stub)
- `AnomalyDetectionService` (Z-score and IQR methods; bootstrapped state management)
- `AnalyticsProjectionWorker` (event ingestion and idempotency)

**API Commands:**
- `RegisterAnalyticsDataSet(tenant_id, domain, schema_version)`
- `DefineSecurityKPI(tenant_id, kpi_type, computation_schedule)` — requires `analytics:engineer`
- `CreateAnomalyBaseline(tenant_id, signal_type, method, window_days)` — requires `analytics:engineer`
- `TriggerProjectionRebuild(tenant_id)` — requires `analytics:admin`
- `TriggerKPIComputation(tenant_id, kpi_type)` — requires `analytics:admin`

**API Queries:**
- `GetSecurityKPI(tenant_id, kpi_type)` — returns latest snapshot + status
- `GetKPIHistory(tenant_id, kpi_type, date_range)` — returns time series of daily snapshots
- `ListAnomalies(tenant_id, signal_type, date_range, severity_filter)`
- `GetDataSetStatus(tenant_id, dataset_id)`
- `GetAnalyticsSummary(tenant_id)` — all KPI statuses + anomaly count

**Events Consumed (via AnalyticsProjectionWorker):**
- `VulnerabilityInstanceDiscovered`, `VulnerabilityInstancePatched`, `VulnerabilityKevStatusChanged`
- `DetectionFindingProduced`, `DetectionRuleActivated`, `DetectionRuleDeprecated`
- `AttackActionExecuted`, `EngagementClosed`
- `CampaignCompleted`, `CampaignDetectionCoverageComputed`
- `ExposureScoreComputed`, `ExposureRecordCreated`, `ExposureRecordResolved`
- `AISystemAssetDiscovered`, `AISystemAssetClassified`, `AIRiskScoreComputed`

**Migrations:** 0086–0092
- `0086_analytics_schema_and_roles.sql` — schema creation, PostgreSQL roles and grants, RLS policies
- `0087_analytics_vulnerability_events.sql` — partitioned event table
- `0088_analytics_detection_events.sql` — partitioned event table
- `0089_analytics_execution_campaign_events.sql` — execution and campaign event tables
- `0090_analytics_exposure_ai_posture_events.sql` — exposure and AI posture event tables
- `0091_analytics_kpi_and_anomaly_tables.sql` — kpi_snapshots, anomaly_detections, processed_analytics_events
- `0092_analytics_attck_reference_table.sql` — ATT&CK technique reference table

**Workers:** AnalyticsProjectionWorker, KPIComputationWorker, RetentionPolicyWorker, PartitionMaintenanceWorker, ProjectionRebuildWorker

**Tests:**
- Unit: KPI formula for each of 5 types (MTTD, Coverage %, Exposure Trend, Campaign Success Rate, AI Risk Trend)
- Unit: MTTR stub returns REQUIRES_M34_DATA
- Unit: Anomaly detection (Z-score, IQR; bootstrapped and unbootstrapped state)
- Unit: Tenant isolation enforcement (AnalyticsQueryExecutionService always injects tenant_id)
- Unit: Multi-tenancy: no cross-tenant data in any repository query
- Integration: Event subscription → projection table population (all 6 event streams)
- Integration: KPI computation from projection data (SQL formula → kpi_snapshot)
- Integration: ProjectionRebuildWorker (delete → replay → verify)
- Integration: RetentionPolicyWorker (mark rows archived; no physical deletion)
- Architecture: No upstream domain type imports in analytics BC (static analysis test)
- Architecture: All repository interfaces require tenant_id

**Phase 1 Exit Criteria:**
- All 5 KPI types computing from live projection data
- Anomaly detection bootstrapping from historical events
- ProjectionRebuildWorker completes full backfill in < 4 hours (simulated load test with 10M events)
- Cross-tenant isolation test: tenant A's KPI data never visible to tenant B's queries
- All unit, integration, and architecture tests pass
- Ruff check and MyPy --strict pass on all analytics BC files

---

### Phase 2 — Stored Queries, Analytics API, and Reporting Foundation

**Scope:** `AnalyticsQuery` aggregate and execution engine. Parameterized query API with full tenant isolation and injection prevention. Cross-domain dashboard API. `reporting` bounded context foundation: `ReportTemplate`, `ScheduledReport`, `ReportInstance`. Template-driven report generation (4 initial templates). `ReportSchedulerWorker`. BI export API foundation.

**Bounded Contexts:** `analytics` (extended), `reporting`

**New Aggregates:** `AnalyticsQuery`, `ReportTemplate`, `ScheduledReport`, `ReportInstance`

**New Domain Services:**
- `AnalyticsQueryValidationService` (schema whitelist, tenant_id presence, parameter validation)
- `AnalyticsQueryExecutionService` (parameterized execution, audit log)
- `ReportGenerationService` (template selection, section rendering, artifact storage)
- `ScheduledReportService` (schedule management, invocation)

**API Commands:**
- `CreateAnalyticsQuery(tenant_id, name, template, parameters, domain)` — requires `analytics:engineer`
- `ExecuteAnalyticsQuery(tenant_id, query_id, parameters)` — requires `analytics:analyst`
- `CreateScheduledReport(tenant_id, template_id, schedule, parameters, recipients)` — requires `analytics:analyst`
- `GenerateReportOnDemand(tenant_id, template_id, parameters)` — requires `analytics:analyst`

**API Queries:**
- `ListAnalyticsQueries(tenant_id)`
- `GetAnalyticsQueryResult(tenant_id, execution_id)` — paginated; retrieves stored result
- `GetReportInstance(tenant_id, instance_id)`
- `ListReportInstances(tenant_id, template_id, date_range)`
- `ExportDataSet(tenant_id, dataset_id, format, page, page_size)` — BI export

**Migrations:** 0093–0095
- `0093_analytics_queries_and_audit_log.sql` — analytics_queries, analytics_query_audit_log
- `0094_reporting_templates_and_schedules.sql` — report_templates, scheduled_reports
- `0095_report_instances.sql` — report_instances

**Workers:** ReportSchedulerWorker

**Key Tests:**
- Unit: SQL parameter injection prevention (all parameter types; no string formatting)
- Unit: Schema whitelist validation (templates referencing non-analytics schemas rejected at creation)
- Unit: Mandatory tenant_id injection (caller-supplied tenant_id always overridden)
- Unit: Result set limits (MAX_ROWS_ABSOLUTE enforced; pagination mandatory)
- Unit: Template-driven report narrative (4 template types; correct template selection by KPI pattern)
- Integration: Stored query round-trip (create → validate → execute → paginated result → audit log)
- Integration: Report generation pipeline (template → KPI data → rendered report → artifact storage)
- Integration: ScheduledReportWorker invocation (due schedules only; idempotency)
- Integration: BI export pagination (correct page boundaries, rate limiting)
- Security: SQL injection attempt via query parameter (must fail; parameterized binding prevents execution)
- Architecture: No LLM client dependency in reporting BC (static analysis test)
- Architecture: reporting BC does not import any exposure_reporting type

**Phase 2 Exit Criteria:**
- SQL injection test suite passes (10+ injection attempt scenarios)
- Schema whitelist correctly rejects templates with non-analytics schema references
- Report generation for all 4 initial templates produces correct output
- BI export pagination returns consistent results under concurrent requests
- ScheduledReportWorker invokes due reports without double-firing

---

### Phase 3 — ML Pipeline

**Scope:** `ml_pipeline` bounded context. `MLModel` and `PredictiveRiskSignal` aggregates. In-process ML training (Isolation Forest, Random Forest, Linear Regression via scikit-learn). Model artifact storage (PostgreSQL BYTEA with SHA-256 integrity). Drift detection (PSI). Cold start protocol. Security graph integration (predictive risk nodes). MLTrainingWorker, MLInferenceWorker, DriftCheckWorker.

**Bounded Contexts:** `ml_pipeline`

**Aggregates:** `MLModel`, `PredictiveRiskSignal`

**Domain Services:**
- `MLModelTrainingService` (feature extraction, training, accuracy evaluation, artifact storage)
- `MLInferenceService` (artifact load + integrity check, prediction generation, expiry enforcement)
- `ModelGovernanceService` (promote, deprecate, governance history)
- `DriftDetectionService` (PSI computation, threshold checks, auto-deprecation)

**API Commands:**
- `ScheduleMLModelTraining(tenant_id, model_type, dataset_id)` — requires `analytics:admin`
- `PromoteMLModel(tenant_id, model_id)` — requires `analytics:admin`
- `DeprecateMLModel(tenant_id, model_id)` — requires `analytics:admin`

**API Queries:**
- `GetMLModel(tenant_id, model_id)`
- `ListMLModels(tenant_id, model_type, status_filter)`
- `GetPredictiveRiskSignals(tenant_id, asset_ref_id, signal_type)`
- `GetMLModelGovernanceHistory(tenant_id, model_id)`

**Migrations:** 0096–0098
- `0096_ml_models.sql` — ml_models table
- `0097_ml_model_artifacts.sql` — ml_model_artifacts table (BYTEA; tenant-scoped; hash integrity)
- `0098_predictive_risk_signals.sql` — predictive_risk_signals table

**Workers:** MLTrainingWorker, MLInferenceWorker, DriftCheckWorker

**Key Tests:**
- Unit: Cold start protocol (no deployed model → INSUFFICIENT_TRAINING_DATA response)
- Unit: Artifact integrity (SHA-256 mismatch on load → ArtifactIntegrityError)
- Unit: Artifact tenant isolation (load with wrong tenant_id → ArtifactNotFoundError)
- Unit: Drift detection (PSI computation; auto-deprecation at PSI ≥ 0.20)
- Unit: PredictiveRiskSignal expiry (expired signals not served; expires_at enforced)
- Unit: Model accuracy threshold gates (below threshold → FAILED status)
- Integration: Full training pipeline (schedule_training → extract features → train → evaluate → store artifact → TRAINED)
- Integration: Promotion gate (TRAINED → promotion command → human-gated → DEPLOYED; no auto-promotion)
- Integration: Inference pipeline (deployed model → load artifact → verify hash → generate predictions → store signals → security graph write)
- Integration: Drift detection → auto-deprecation → retraining trigger
- Architecture: No LLM client dependency in ml_pipeline BC
- Architecture: PredictiveRiskSignal is read-only advisory (no writes to M27, M32, or M31)

**Phase 3 Exit Criteria:**
- Isolation Forest anomaly detection model trains and deploys end-to-end
- PredictiveRiskSignal generated and stored with correct expires_at
- Security graph receives predictive risk node for deployed model
- Artifact integrity check catches bit-flip corruption (injected test)
- Cold start API response is correct (no error; AWAITING_MODEL status)
- Model promotion requires analytics:admin (403 for lower roles)

---

### Phase 4 — Advanced Reporting and BI Export

**Scope:** Complete `reporting` bounded context. Three additional report templates (Detection Analytics, Campaign Effectiveness, Predictive Threat Forecast). BI export connector framework (`IBIExportPort` interface; no vendor implementations). Data export rate limiting. Report delivery (`IReportDeliveryPort`: email and webhook implementations). Reporting audit log.

**New Report Types:**
- Detection Analytics Report (ATT&CK coverage, FP rate trends, top coverage gaps)
- Campaign Effectiveness Report (campaign success rate trends, technique coverage delta over campaigns)
- Predictive Threat Forecast (ML-predicted top-risk techniques by exploitation probability)

**Migrations:** 0099–0100
- `0099_reporting_delivery_log.sql` — report delivery audit log
- `0100_bi_export_rate_limit_log.sql` — BI export rate limiting and audit

**New Ports:**
- `IBIExportPort` — abstract interface for Tableau/Power BI/Looker
- `IReportDeliveryPort` — email and webhook implementations

**Key Tests:**
- Unit: Predictive Threat Forecast template selects top-N techniques from PredictiveRiskSignal (ML cold start → fallback to rule-based top-N by CVSS + exposure score)
- Unit: BI export rate limiting (11th request in window → 429)
- Integration: Report delivery (email adapter, webhook adapter)
- Integration: BI export pagination with concurrent requests (result consistency)
- Architecture: IBIExportPort has no vendor-specific implementations in M33 (only interface)

**Phase 4 Exit Criteria:**
- All 7 report templates (5 from Phase 2 + 2 new) generating correctly
- Predictive Threat Forecast degrades gracefully when no ML model is deployed
- BI export rate limiting enforced correctly
- Report delivery audit log captures all delivery attempts

---

### Phase 5 — Completion, Security Graph, Hardening

**Scope:** Full Security Graph integration (anomaly nodes and predictive risk nodes). Advanced anomaly detection methods (`IQR_ROLLING`). `ML_ISOLATION_FOREST` method for `AnomalyDetectionBaseline` (wires ml_pipeline's inference into anomaly detection baseline). Retention policy hardening. Operational metrics and health. Complete test suite.

**New Capabilities:**
- Anomaly node writes to Security Graph (via `ISecurityGraphWritePort` from analytics BC)
- `IQR_ROLLING` anomaly detection method (rolling window; better for bursty signals)
- `ML_ISOLATION_FOREST` baseline method (requires deployed MLModel; wires Phase 3 into Phase 1's anomaly layer)

**Migrations:** 0101
- `0101_analytics_operational_metrics.sql` — operational metrics tables (worker health, KPI computation timing)

**Test Suite Additions:**
- Unit: ML_ISOLATION_FOREST anomaly detection (wired to deployed MLModel)
- Unit: Security graph write (anomaly node appended; no read from graph)
- Integration: End-to-end analytics → anomaly → security graph write
- Performance: KPI dashboard query latency < 50ms for tenant with 10M projection table rows (benchmark test)
- Security: Cross-tenant query isolation (50 concurrent requests from different tenants; no data leakage)
- Security: AnalyticsQuery injection suite (10 SQL injection patterns; all blocked by parameterized binding)
- Security: ML model artifact cross-tenant access (tenant B cannot load tenant A's artifact)
- Architecture: All 3 analytics contexts have zero imports from M26–M32 domain types

**Phase 5 Exit Criteria:**
- All Phase 1–5 tests passing
- Ruff check PASS on all analytics, ml_pipeline, reporting BC files
- Ruff format --check PASS
- MyPy --strict PASS on all 3 bounded contexts
- Security graph anomaly and predictive nodes visible after anomaly detection run
- KPI dashboard latency benchmark passes (< 50ms)
- Cross-tenant isolation test: 50 concurrent sessions with different tenant IDs; no cross-tenant rows in any query result
- M33 Final Repository Validation Report produced

---

## 7. Implementation Readiness

### Boundary Verification

| Context | Module Path | Aggregate Roots | Repository Interfaces |
|---|---|---|---|
| `analytics` | `backend/src/analytics/` | AnalyticsDataSet, SecurityKPI, AnalyticsQuery, AnomalyDetectionBaseline | IAnalyticsDataSetRepository, ISecurityKPIRepository, IAnomalyDetectionBaselineRepository, IAnalyticsQueryRepository |
| `ml_pipeline` | `backend/src/ml_pipeline/` | MLModel, PredictiveRiskSignal | IMLModelRepository, IPredictiveRiskSignalRepository, IMLModelArtifactStore |
| `reporting` | `backend/src/reporting/` | ReportTemplate, ScheduledReport, ReportInstance | IReportTemplateRepository, IScheduledReportRepository, IReportInstanceRepository |

### Migration Sequence

| Migration | Description |
|---|---|
| 0086 | Analytics PostgreSQL schema, roles, RLS |
| 0087 | analytics.vulnerability_events (partitioned) |
| 0088 | analytics.detection_events (partitioned) |
| 0089 | analytics.execution_events + campaign_events (partitioned) |
| 0090 | analytics.exposure_events + ai_posture_events (partitioned) |
| 0091 | kpi_snapshots, anomaly_detections, processed_analytics_events |
| 0092 | attck_technique_reference |
| 0093 | analytics_queries + analytics_query_audit_log |
| 0094 | report_templates + scheduled_reports |
| 0095 | report_instances |
| 0096 | ml_models |
| 0097 | ml_model_artifacts |
| 0098 | predictive_risk_signals |
| 0099 | report delivery audit log |
| 0100 | BI export rate limit log |
| 0101 | analytics operational metrics |

Current migration head before M33: `0085`. M33 migrations begin at `0086`. Single Alembic head throughout.

### Platform Invariant Compliance

| Invariant | M33 Compliance |
|---|---|
| Invariant 1: Domain Purity | No upstream domain type imports in any M33 context. All upstream data translated at ACL adapters. Verified by architecture test in Phase 1 and Phase 5. |
| Invariant 2: Multi-Tenancy Non-Negotiable | All repository methods require tenant_id. AnalyticsQueryExecutionService enforces tenant injection. RLS provides database-layer defense. |
| Invariant 3: Security Graph Append-Only | M33 writes anomaly and predictive nodes via append-only ISecurityGraphWritePort. No graph reads in M33. |
| Invariant 4: Evidence Immutable | Not directly applicable (M33 has no evidence aggregates). kpi_snapshots are point-in-time immutable records (never updated; new snapshots are new rows). |
| Invariant 5: Kill Switch is Domain Invariant | Not applicable to M33 — no offensive or defensive execution actions. |
| Invariant 6: Human Approval Gates | ML model promotion to DEPLOYED requires `analytics:admin` explicit command. Auto-promotion is permanently prohibited (ADR-M33-006). |
| Invariant 7: AI Suggestion Read-Only | PredictiveRiskSignal is advisory-only; stored only in M33's own tables; never writes to M27, M32, M31, or any other upstream BC (ADR-M33-002). |

### Pre-Implementation Checklist

Before Phase 1 begins, verify:

- [ ] Current Alembic head confirmed as `0085` (`alembic current` in `/backend/`)
- [ ] `backend/src/analytics/` module namespace does not conflict with any existing module
- [ ] `backend/src/ml_pipeline/` module namespace does not conflict
- [ ] `backend/src/reporting/` module namespace does not conflict with M32 `exposure_reporting`
- [ ] scikit-learn is available as a project dependency or will be added to `pyproject.toml` in Phase 3
- [ ] Platform event bus subscription interface available (all 6 upstream event streams)
- [ ] `IEventStoreReplayPort` available for ProjectionRebuildWorker
- [ ] `ISecurityGraphWritePort` (M32's implementation) accessible for analytics and ml_pipeline contexts
- [ ] PostgreSQL version supports hash partitioning (PG 11+) and JSONB (PG 9.4+) — confirm deployment version

### Outstanding Items (Post-M33)

| Item | Priority | Notes |
|---|---|---|
| Application-level ML artifact encryption (AES-256) | Medium | Requires platform key management; deferred post-M33 |
| External ML platform adapters (SageMaker, Vertex AI, Azure ML) | Low | IMLTrainingPort interface defined in M33; adapters are future milestones |
| BigQuery/Redshift analytics backend adapters | Low | IAnalyticsBackendPort defined in M33; adapters are future milestones |
| MTTR KPI computation | — | Automatically activates when M34 incident events populate projection tables; no M33 code change |
| Gradient Boosting model (XGBoost) | Low | Deferred post-Phase 3 based on operational assessment of scikit-learn Random Forest accuracy |
| LLM-assisted report narrative | — | Deferred to M36 per ADR-M33-001 |

---

## M33 Architecture Freeze Complete.

**Architecture status:** FROZEN FOR IMPLEMENTATION  
**Bounded contexts:** `analytics`, `ml_pipeline`, `reporting`  
**Module paths:** `backend/src/analytics/`, `backend/src/ml_pipeline/`, `backend/src/reporting/`  
**Migrations:** 0086–0101 (16 migrations across 5 phases)  
**ADRs:** ADR-M33-001 through ADR-M33-006 (complete)  
**Risks:** R01–R09 all dispositioned (R01–R07 Mitigated; R08–R09 Mitigated)  
**Conditions:** C1–C7 all resolved  
**Implementation phases:** 5 phases frozen with scope, aggregates, services, events, migrations, tests, exit criteria  
**Pending:** Implementation authorization required before Phase 1 begins

STOP. Do NOT implement code. Do NOT create migrations. Do NOT modify repository.
