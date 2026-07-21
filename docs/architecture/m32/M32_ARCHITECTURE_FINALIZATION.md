# M32 Architecture Finalization
## Enterprise Continuous Threat Exposure Management (CTEM) Platform

**Status:** FROZEN FOR IMPLEMENTATION  
**Date:** 2026-07-21  
**Precondition:** M32 Architecture Review APPROVED FOR IMPLEMENTATION — WITH CONDITIONS  
**Constraint:** Documentation only. No code, no migrations, no repository modifications.

---

## Table of Contents

1. [Final Decisions (D1–D5)](#1-final-decisions-d1d5)
2. [ADR Updates (ADR-M32-001 through ADR-M32-005)](#2-adr-updates-adr-m32-001-through-adr-m32-005)
3. [Architecture Corrections](#3-architecture-corrections)
4. [Risk Dispositions (R01–R09)](#4-risk-dispositions-r01r09)
5. [Final Frozen Phase Plan](#5-final-frozen-phase-plan)
6. [Implementation Readiness](#6-implementation-readiness)

---

## 1. Final Decisions (D1–D5)

---

### D1 — ExposureRecord Aggregate Identity (Cardinality)

**Condition from Review (R01):** ExposureRecord cardinality was under-specified. The review raised ambiguity between per-asset cardinality (one record per asset) and per-signal cardinality (one record per finding per asset). This condition must be frozen before Phase 1 begins.

#### Decision: Per Signal Domain and Signal Source, Per Asset, Per Tenant

The canonical identity of `ExposureRecord` is:

```
(TenantId × AssetRefId × SignalDomain × SignalSourceRefId)
```

This is enforced as a unique constraint in the database. One `ExposureRecord` per signal per asset per tenant. No exceptions.

#### Signal Domain Taxonomy

`SignalDomain` is a closed value type. The exhaustive set for M32:

| SignalDomain | Signal Source Type | Source Milestone |
|---|---|---|
| `VulnerabilityManagement` | `VulnerabilityInstanceId` (per CVE-per-asset) | M27 |
| `CloudSecurity` | `CloudMisconfigurationId` (per misconfig finding) | M26 |

`AISystemRisk` is NOT a `SignalDomain` — it is a `RiskAmplifier` type applied to records in existing signal domains. `AISystemRisk` amplifiers are sourced from M31 and attached to existing `VulnerabilityManagement` or `CloudSecurity` records when an AI system is the affected asset.

#### Detection Gap Boundary Decision

Detection gaps (M28) are NOT standalone `ExposureRecord` entities. They are `RiskAmplifier` entities of type `DetectionGap` attached to existing vulnerability-based or cloud-security-based `ExposureRecord` aggregates.

Rationale: A detection gap without an associated exploitable vulnerability or misconfiguration is a monitoring coverage concern (M28's domain), not a CTEM exposure concern (M32's domain). The presence of an unexploited technique gap that has no corresponding vulnerability on the asset does not create exposure risk in the CTEM sense. M28 retains full ownership of raw detection coverage.

The boundary is: detection gaps become M32 amplifiers when and only when M28 determines that a known exploitable signal (VulnerabilityInstance or CloudMisconfiguration) exists for this asset AND the technique associated with the vulnerability has no detection rule deployed. The amplifier is sourced from M28 via the `IDetectionCoverageQueryPort`.

#### Aggregate Model

```
ExposureRecord (Aggregate Root)
  id: ExposureRecordId                       # surrogate
  tenant_id: TenantId                        # multi-tenancy invariant
  asset_ref: AssetRef                        # reference to external asset
  signal_domain: SignalDomain                # VulnerabilityManagement | CloudSecurity
  signal_source_ref: SignalSourceRef         # VulnerabilityInstanceId | CloudMisconfigId
  status: ExposureStatus                     # Active | Resolved | Suppressed
  base_exposure_level: ExposureLevel         # CVSS-derived or misconfig severity
  risk_amplifiers: List[RiskAmplifier]       # entities; see type taxonomy below
  current_exposure_score: float              # denormalized; recomputed asynchronously
  created_at: DateTime
  resolved_at: Optional[DateTime]
  version: int                               # optimistic concurrency

RiskAmplifier (Entity within ExposureRecord)
  amplifier_id: RiskAmplifierId              # UUID; scoped within aggregate
  type: RiskAmplifierType
  source_ref: str                            # opaque reference to sourcing system
  first_observed_at: DateTime
  last_confirmed_at: DateTime
  applied_weight: Decimal                    # snapshot of weight at time of attachment
  is_active: bool

RiskAmplifierType (Value Object — Closed Enum):
  InternetExposure         ← sourced from M26
  DetectionGap             ← sourced from M28
  ThreatActorMatch         ← sourced from M21 via ThreatActorMatchCache
  KevPresent               ← sourced from M27 enrichment
  ConfirmedExploitation    ← sourced from M29
  CloudMisconfiguration    ← sourced from M26 (amplifier on VulnManagement records)
  AISystemRisk             ← sourced from M31
```

#### Repository Interface

```
IAExposureRecordRepository:
  find_by_id(tenant_id, record_id) → Optional[ExposureRecord]
  find_by_signal(tenant_id, signal_domain, signal_source_ref) → Optional[ExposureRecord]
  find_by_asset(tenant_id, asset_ref) → List[ExposureRecord]
  find_active_by_tenant(tenant_id, page, page_size) → Page[ExposureRecord]
  find_with_amplifier(tenant_id, amplifier_type, page, page_size) → Page[ExposureRecord]
  find_stale_scores(tenant_id, stale_before: DateTime) → List[ExposureRecord]
  save(tenant_id, record: ExposureRecord) → None
  save_batch(tenant_id, records: List[ExposureRecord]) → None  # for bulk signal ingestion
```

All methods require `tenant_id` as the first positional argument. Calls without a valid `TenantId` raise `TenantContextMissingError` (hard failure — never defaults).

#### Concurrency Model

`ExposureRecord` uses optimistic concurrency via the `version` field. Concurrent amplifier additions from different signal sources (M26, M27, M28, M21, M29) use compare-and-swap on `version`. If a conflict is detected (stale version), the writer reloads the aggregate and retries once. If the second attempt fails, the operation is routed to the DLQ as `ExposureRecordConflict` for ordered replay.

Concurrent modification of the same `ExposureRecord` by two different amplifier sources is expected (for example, M26 setting `InternetExposure` simultaneously with M28 setting `DetectionGap` on the same vulnerability). Optimistic locking at the aggregate level prevents lost-update without requiring aggregate-level serialization.

#### Lifecycle Invariants

- An `ExposureRecord` transitions to `Resolved` when its `signal_source_ref` is marked resolved in the source system (e.g., VulnerabilityInstance patched, CloudMisconfiguration remediated). This transition is triggered by an upstream domain event subscription — it is never driven by an API call directly.
- A `Resolved` record is retained for 2 years (exposure history). It is not deleted.
- A `Suppressed` record is excluded from score computation. Suppression requires `exposure:analyst` role and a mandatory `suppression_justification` (non-empty string). Suppression is audited.
- `resolved_at` is immutable once set. A new exposure on the same signal creates a new `ExposureRecord` with a new `ExposureRecordId` (not a resurrection of the resolved record).

---

### D2 — Score Recomputation Model

**Condition from Review (R02):** Score recomputation architecture must be designed to handle high-frequency signal updates (new KEV entries, mass detection pack deployments) without thundering-herd failure. The design must specify debouncing, batching, idempotency, failure recovery, backpressure, and event replay behavior.

#### Decision: Four-Stage Debounced Recomputation Pipeline

The permanent score computation architecture is a four-stage pipeline with explicit back-pressure controls.

```
Stage 1: INGESTION
  ExposureSignalIngestionService
  ─ subscribes to upstream domain events from M26, M27, M28, M21, M29, M31
  ─ for each event: mutates the relevant ExposureRecord (add/update/remove amplifier)
  ─ after each record mutation: writes a marker into the pending_recomputations table

Stage 2: DEBOUNCE
  RecomputationDebouncerService
  ─ pending_recomputations: (tenant_id, asset_ref_id) → marked_at (upsert-on-conflict)
  ─ debounce window: configurable per tenant, default 5 minutes
  ─ only assets where marked_at < now() - debounce_window are eligible for dispatch
  ─ runs on a sweep cycle: every 60 seconds by default

Stage 3: DISPATCH
  RecomputationDispatcherService
  ─ reads eligible assets from pending_recomputations (SELECT ... FOR UPDATE SKIP LOCKED)
  ─ applies per-tenant rate limit: max 1,000 dispatch events/minute per tenant
  ─ applies global ceiling: max 5,000 dispatch events/minute across all tenants
  ─ emits ScoreRecomputationJob(job_id, tenant_id, asset_ref_id, dispatched_at)
  ─ deletes dispatched asset from pending_recomputations table
  ─ if back-pressure threshold exceeded: pauses dispatch (see below)

Stage 4: COMPUTATION
  ExposureScoreComputationWorker
  ─ picks up ScoreRecomputationJob from work queue
  ─ loads all active ExposureRecords for the asset
  ─ loads current AmplifierWeightConfiguration snapshot (from cache)
  ─ computes weighted composite exposure score
  ─ writes new ExposureScoreSnapshot (append-only, immutable)
  ─ updates TenantExposureProfile read model (incremental)
  ─ emits ExposureScoreComputed domain event
```

#### Idempotency Design

`job_id` derivation:

```
job_id = SHA-256(f"{tenant_id}:{asset_ref_id}:{dispatch_window_bucket}")
dispatch_window_bucket = floor(dispatched_at / 5min) * 5min
```

Before computing a score, `ExposureScoreComputationWorker` checks: does a `ExposureScoreSnapshot` for `(tenant_id, asset_ref_id)` exist with `computed_at > dispatch_window_bucket_start`? If yes, this job was already satisfied by a concurrent worker — skip silently and ack.

This guarantees that retried jobs from the message queue do not produce duplicate snapshots.

Event ingestion idempotency follows the platform-standard `IdempotentProjectionEngine` pattern (established Sprint 25): each upstream event has a stable `event_id`; the ingestion service records processed event IDs in `processed_exposure_signals` and skips re-delivery.

#### Failure Recovery

| Scenario | Behavior |
|---|---|
| `ScoreRecomputationJob` fails | Retry with exponential backoff: 1m → 5m → 15m (max 3 attempts) |
| After 3 failed retries | Route to platform DLQ; existing snapshot retained; `recomputation_failed_at` field set on TenantExposureProfile read model for that asset |
| DLQ depth > 100 items for any tenant | Alert `exposure:admin` via platform operational health engine |
| Weight configuration change | INSERT all tenant assets into `pending_recomputations` (idempotent bulk upsert); use 1-minute debounce window override for this operation |
| Event replay (full tenant) | `ExposureSignalIngestionService` replays all events idempotently (via IdempotentProjectionEngine); after replay, all assets inserted into `pending_recomputations` with debounce bypass flag |

#### Back-Pressure Control

```
Back-pressure threshold:       10,000 pending jobs in work queue (configurable)
Back-pressure pause condition: queue_depth > threshold
Resume condition:              queue_depth < threshold × 0.5 (50%)
Pause alert threshold:         pause duration > 30 minutes
During pause:                  pending_recomputations table continues absorbing signals
                               (debounce absorbs mass-update scenarios gracefully)
Operator escape hatch:         exposure:admin can flush the pending_recomputations table
                               for a specific tenant, triggering prioritized recomputation
```

#### Score Formula (Frozen)

```
exposure_score(record) =
  base_score(record) × Π[1 + (weight(amplifier) × active_amplifiers)]

where:
  base_score: [0.0, 10.0] derived from CVSS base score (vulns) or misconfig severity (cloud)
  weight(amplifier): from current AmplifierWeightConfiguration
  active_amplifiers: only amplifiers where is_active = true
  output range: [0.0, 10.0] (clamped)

tenant_exposure_score =
  Σ(asset_exposure_scores) / total_scoreable_assets
```

Weight configuration changes do NOT retroactively alter historical `ExposureScoreSnapshot` records. They only affect subsequent computations. Historical snapshots carry `score_input_version` to identify which weight set was in effect.

---

### D3 — M21 Integration Model

**Condition from Review (R06):** The integration model for consuming threat actor targeting data from M21 was unresolved. The options were: event subscription, polling, or hybrid. This condition must be frozen with ACL ownership, failure behavior, and synchronization semantics specified.

#### Decision: Hybrid — Event Subscription Primary, Polling Fallback, Local Cache Projection

The M21 integration uses a hybrid model. Neither pure event nor pure polling alone provides sufficient resilience.

#### Rationale

| Factor | Event-Only | Poll-Only | Hybrid |
|---|---|---|---|
| Real-time updates | Yes | No | Yes (primary path) |
| Resilience to M21 outage | No | Partial (uses last poll) | Yes (cache survives outage) |
| Bootstrap (new tenant) | Gap risk | OK | OK (first poll fills cache) |
| Event bus gap recovery | Requires replay | N/A | Poll fills gap within 24h |
| Complexity | Low | Low | Moderate |

The hybrid model is the permanent architecture.

#### Integration Architecture

**Primary Path — Event Subscription:**

M32's `ExposureSignalIngestionService` subscribes to the following M21-published event:

```
ThreatActorAssetClassTargetingUpdated
  tenant_id: TenantId
  threat_actor_ref: ThreatActorRef
  targeted_asset_classes: List[AssetClass]
  targeted_cve_ids: List[CveId]            # optional; may be empty
  targeting_confidence: ConfidenceLevel    # High | Medium | Low
  effective_at: DateTime
  event_id: EventId
```

When received:
1. Update `ThreatActorMatchCache` (local projection) for the affected `(tenant_id, cve_id)` and `(tenant_id, asset_class)` keys
2. For all active `ExposureRecord` entities affected (matching CVE or asset class), add or update `ThreatActorMatch` amplifier
3. Insert affected assets into `pending_recomputations` for score recomputation

**Fallback Path — Scheduled Polling:**

`IThreatIntelligenceQueryPort` (ACL port, M32's domain):

```
IThreatIntelligenceQueryPort:
  query_threat_actor_matches(
    tenant_id: TenantId,
    cve_ids: List[CveId],
    asset_classes: List[AssetClass]
  ) → ThreatActorMatchResult

ThreatActorMatchResult:
  matches: List[ThreatActorMatch]
  queried_at: DateTime
  data_freshness: DateTime        # last time M21's data was updated

ThreatActorMatch:
  threat_actor_ref: ThreatActorRef
  matched_cve_ids: List[CveId]
  matched_asset_classes: List[AssetClass]
  confidence: ConfidenceLevel
```

Polling schedule: daily, per-tenant, at a configurable time (default 02:00 UTC per tenant shard). Full refresh of the `ThreatActorMatchCache` for each tenant.

**Local `ThreatActorMatchCache` Projection:**

```
ThreatActorMatchCache (Read Model, per tenant)
  entries: Map<CveId, List[ThreatActorRef]>
  asset_class_entries: Map<AssetClass, List[ThreatActorRef]>
  last_event_update_at: Optional[DateTime]
  last_poll_update_at: Optional[DateTime]
  is_stale: bool                  # true if neither event nor poll succeeded in last 48h
```

The cache is the single source of truth for `ThreatActorMatch` amplifier decisions within M32. It is reconstructable via replay of M21 events or by triggering a fresh poll.

**Failure Behavior:**

| Scenario | Behavior |
|---|---|
| M21 event bus gap | Existing `ThreatActorMatch` amplifiers RETAIN (conservative; do not remove on silence) |
| M21 poll unavailable | Retry with exponential backoff; set `is_stale = true` after 48h with no successful poll |
| `is_stale = true` | Surface staleness in operational health; set `data_freshness_warning` in ExposureReport metadata |
| Cache cold (new tenant) | Force poll on first request; mark records pending recomputation after cache population |

**ACL Ownership:**

```
Port interface:  backend/src/exposure/domain/ports/i_threat_intelligence_query_port.py
Adapter:         backend/src/exposure/infrastructure/acl/threat_intelligence_m21_adapter.py
Cache:           backend/src/exposure/infrastructure/projections/threat_actor_match_cache.py
Cache repo:      backend/src/exposure/infrastructure/repositories/threat_actor_match_cache_repository.py
```

`ThreatActorMatchCache` is owned exclusively by the `exposure` bounded context. M21 is the provider; M32 is the consumer. No M21 types cross the ACL boundary. All M21 types are translated to M32 internal types at the adapter.

---

### D4 — M30 ExposureScopePort Contract

**Condition from Review (I04):** The port contract between M30 (campaign scope) and M32 (exposure data) must specify ownership, DTOs, failure handling, versioning, and compatibility semantics.

#### Decision: Pull Model — M30 Owns the Port Interface, M32 Owns the Implementation

This follows the DDD ACL convention established in M31 (M31's `ISupplyChainQueryPort` is owned by the consuming context). M30 owns the abstract capability definition; M32 implements it.

#### Port Ownership

```
Port interface:  backend/src/campaign/domain/ports/i_exposure_scope_query_port.py
                 (M30's domain — M30 owns this file)

Adapter:         backend/src/campaign/infrastructure/acl/exposure_scope_m32_adapter.py
                 (M30's infrastructure — wraps the HTTP call to M32's internal service)

Service:         backend/src/exposure/application/services/exposure_scope_service.py
                 (M32's application layer — computes and returns scope responses)
```

#### DTO Contract

```
ExposureScopeRequest:
  tenant_id: TenantId
  max_assets: int                           # default 100; max 1,000
  min_exposure_score: Optional[float]       # exclude assets below this score
  amplifier_filter: List[RiskAmplifierType] # only assets with at least one of these
  asset_kind_filter: List[str]              # optional; filter by asset classification
  include_stale_scores: bool                # default False
  requested_at: DateTime                    # for reproducibility logging

ExposureScopeResponse:
  tenant_id: TenantId
  assets: List[ScopedAsset]
  total_eligible: int                       # before max_assets cap
  score_version: str                        # ScoreInputVersion (weight config version)
  queried_at: DateTime
  has_stale_scores: bool                    # true if any returned assets have stale snapshots
  query_duration_ms: int                    # for M30 caller logging

ScopedAsset:
  asset_ref: AssetRef
  exposure_score: float
  dominant_amplifiers: List[RiskAmplifierType]  # top 3 by weight contribution
  business_criticality: Optional[str]           # from BusinessImpactMapping if present
  snapshot_computed_at: DateTime
  is_score_stale: bool
```

All DTO types are defined in M30's domain ports module. M32 does not reference these DTOs — M32's service returns M32-internal types, which the M30-side adapter translates.

#### Failure Handling

| Scenario | M30 Behavior |
|---|---|
| M32 unavailable (timeout 10s) | Log failure; M30 campaign planner receives manual-scope fallback UI |
| Partial stale results | `has_stale_scores = true` surfaced to planner before scope confirmation |
| Zero eligible assets | Return empty list with `total_eligible = 0`; M30 does not treat as error |
| M32 returns error | M30 logs and falls back to manual scope; no automatic retry on campaign creation path |

#### Versioning and Compatibility

Breaking changes to the `ExposureScopeRequest` or `ExposureScopeResponse` schema require:
1. A new method on `IExposureScopeQueryPort` (e.g., `query_scope_v2`)
2. The old method retained until all callers have migrated
3. No silent removal of response fields; additive changes only

`ExposureScopeResponse.score_version` allows M30 to record which exposure weight configuration was in effect when the campaign scope was decided. This is included in campaign audit records.

---

### D5 — Remediation Simulation Algorithm

**Condition from Review (R03):** The remediation simulation algorithm for `IExposureReductionPlanRepository` and `ExposureReductionPlanService` was unspecified. Candidate algorithms were: Greedy Marginal Contribution, Branch-and-Bound, Integer Programming, Heuristic Search. One canonical algorithm must be chosen.

#### Decision: Greedy Marginal Contribution with Bounded Top-K Approximation

The permanent simulation algorithm is `GreedyMarginalContribution`. Branch-and-Bound, Integer Programming, and Simulated Annealing are all rejected.

#### Algorithm Comparison

| Algorithm | Quality | Time Complexity | Deterministic | Enterprise Scale (1M+ assets) | Decision |
|---|---|---|---|---|---|
| Greedy Marginal Contribution | ~63% of optimal (1-1/e bound for submodular objectives) | O(K² × S) | Yes | Yes (with Top-K + sampling) | **ACCEPTED** |
| Branch-and-Bound | Exact optimal | Exponential worst-case | Yes | **No** — impractical at >100 remediations | **REJECTED** |
| Integer Programming | Near-optimal | Polynomial (LP relaxation) + exponential (branch-and-cut) | Yes | **No** — constraint matrix too large at 1M assets; requires external solver dependency | **REJECTED** |
| Simulated Annealing | Good in practice | Polynomial | **No** — stochastic | Yes | **REJECTED** — non-determinism violates audit requirements |

#### Algorithm Specification

**Algorithm: `GreedyMarginalContribution`**

```
Input:
  candidate_remediations: List[RemediationCandidate]
    each candidate has: remediation_id, affected_asset_refs, estimated_amplifier_removals
  current_exposure_scores: Map<AssetRef, float>
  amplifier_weight_config: AmplifierWeightConfiguration
  plan_budget: int (max remediations to include in plan)
  top_k: int (default 200; max candidate pool to consider per greedy step)
  sample_size: Optional[int] (if None, use full asset estate)

Algorithm:
  selected = []
  remaining_candidates = top_k_candidates_by_estimated_impact(candidate_remediations, top_k)
  working_scores = copy(current_exposure_scores)

  for i in range(plan_budget):
    if not remaining_candidates:
      break

    # For each remaining candidate, compute marginal exposure reduction
    best_candidate = None
    best_delta = 0.0

    for candidate in remaining_candidates:
      delta = compute_marginal_delta(candidate, working_scores, amplifier_weight_config)
      if delta > best_delta:
        best_delta = delta
        best_candidate = candidate

    if best_delta < MIN_DELTA_THRESHOLD:  # default 0.01
      break  # no candidate produces meaningful improvement

    selected.append(best_candidate)
    apply_candidate_to_working_scores(best_candidate, working_scores, amplifier_weight_config)
    remaining_candidates.remove(best_candidate)

  return SimulationResult(
    plan_steps=selected,
    projected_exposure_reduction=compute_total_delta(working_scores, current_exposure_scores),
    algorithm="GreedyMarginalContribution",
    top_k=top_k,
    sample_size=len(working_scores),
    approximation_mode="Exact" if sample_size is None else f"Sampled ({sample_size}/{total_assets})",
    simulation_seed=derive_seed(plan_generated_at),
    score_input_version=amplifier_weight_config.version
  )
```

#### Large Estate Approximation (> 100K assets)

For estates exceeding the full-computation threshold (default 100,000 assets; configurable), the algorithm switches to portfolio-weighted sampling:

```
sample_size = min(max_sample_size, total_assets)  # default max_sample_size = 20,000
sampling_strategy = PortfolioWeighted(
  high_exposure_weight = 0.6,     # 60% of sample from top quartile by exposure score
  medium_exposure_weight = 0.3,   # 30% from middle quartiles
  low_exposure_weight = 0.1       # 10% from bottom quartile
)

projected_delta is scaled by (total_assets / sample_size) × stratum_weight
```

The `SimulationResult.approximation_mode` field makes the sampling explicit and auditable. Simulation results using sampling are labeled `Approximated — Sampled (N assets)` in the UI.

#### Determinism Guarantee

Given identical inputs (same `ExposureScoreSnapshot` state + same `AmplifierWeightConfiguration.version` + same candidate remediation set + same `TopK` budget + same `plan_budget`), the algorithm produces identical output.

Sampling is deterministic: the sample seed is derived from `plan_generated_at` truncated to the nearest second:

```
simulation_seed = int(plan_generated_at.timestamp()) % (2**32)
```

Two simulation runs with the same parameters and timestamp always produce the same result.

---

## 2. ADR Updates (ADR-M32-001 through ADR-M32-005)

### ADR-M32-001 — ExposureRecord Signal-Scoped Identity

**Status:** Accepted  
**Date:** 2026-07-21  
**Deciders:** M32 Architecture Finalization  

#### Context

The M32 ExposureRecord aggregate must have a canonical identity that determines uniqueness, lifecycle ownership, and concurrency semantics. Candidate models: per-asset (one record per asset), per-vulnerability-per-asset, per-signal-per-asset.

#### Decision

ExposureRecord identity is `(TenantId × AssetRefId × SignalDomain × SignalSourceRefId)`. One ExposureRecord per signal per asset per tenant.

#### Consequences

Positive:
- Clear lifecycle: a record resolves when its specific signal resolves (not when the asset is "generally remediated")
- Amplifiers are signal-contextualized (a `DetectionGap` amplifier on a specific CVE is different from one on a misconfiguration)
- Enables per-signal suppression with full audit trail
- Score aggregation at asset level is explicit summation across signal records

Negative:
- An asset with 50 open CVEs has 50 ExposureRecords; repository queries must aggregate at asset level for dashboards
- Mitigated by: `TenantExposureProfile` read model (pre-aggregated per asset); all dashboard queries use the read model, not live repository queries

Rejected alternatives:
- **Per-asset cardinality:** Loss of signal-level lifecycle tracking; cannot suppress individual vulnerabilities
- **Per-vulnerability-per-asset only:** Excludes cloud misconfigurations without associated CVEs — a real and important signal type

#### Consistency with Platform Standards

Multi-tenancy invariant: all repository calls include `tenant_id`. Cross-tenant access is a hard failure. Append-only resolution model (resolved records are retained 2 years). Consistent with M22 AIAsset aggregate design pattern.

---

### ADR-M32-002 — Upstream Signal Consumption via Idempotent Event Subscription

**Status:** Accepted  
**Date:** 2026-07-21  
**Deciders:** M32 Architecture Finalization  

#### Context

M32 consumes signals from M26, M27, M28, M29, M31, and M21. The consumption model must handle event bus replay, out-of-order delivery, duplicate delivery, and partial failures without producing inconsistent ExposureRecord state.

#### Decision

M32's `ExposureSignalIngestionService` uses idempotent event subscription (platform `IdempotentProjectionEngine` pattern, Sprint 25). All inbound signal events are recorded in `processed_exposure_signals` by `event_id`. Duplicate delivery is a no-op.

For M21 specifically, the hybrid model (event subscription primary + daily polling fallback + local `ThreatActorMatchCache` projection) is the permanent architecture. See D3.

#### Consequences

Positive:
- Full replay safety: event bus replay does not corrupt ExposureRecord state
- M21 outage resilience: existing amplifiers retained during outage; stale flag surfaces operationally
- Clear ACL: all upstream types translated at adapter boundary; no upstream types reach the domain

Negative:
- M21 daily polling introduces up to 24-hour lag for new threat actor associations not covered by events
- Accepted: threat actor targeting data changes rarely enough that 24-hour lag is operationally acceptable

Rejected alternative:
- **Event-only from M21:** Unacceptable — cold-start gap (new tenants have no historical event data) and event bus replay gaps cannot be covered without a polling fallback

---

### ADR-M32-003 — Debounced Four-Stage Score Recomputation Pipeline

**Status:** Accepted  
**Date:** 2026-07-21  
**Deciders:** M32 Architecture Finalization  

#### Context

Score recomputation is triggered by every ExposureRecord mutation. Mass signal events (new KEV list, mass detection pack, bulk cloud scan results) can generate thousands of mutations simultaneously. Without architectural controls, this creates thundering-herd failure.

#### Decision

Score recomputation uses a four-stage pipeline: Ingestion → Debounce → Dispatch → Computation. The `pending_recomputations` table (PostgreSQL; unique on `(tenant_id, asset_ref_id)`) acts as the debounce absorber. Default debounce window: 5 minutes. Per-tenant rate limit: 1,000 dispatches/minute. Global ceiling: 5,000 dispatches/minute. Backpressure threshold: 10,000 queued jobs.

#### Consequences

Positive:
- Mass signal events are absorbed by the debounce layer — thousands of amplifier mutations on the same asset within 5 minutes produce exactly one recomputation
- Per-tenant rate limiting prevents a single large tenant from starving others during mass recomputation
- Backpressure prevents computation worker exhaustion
- Idempotent `job_id` prevents duplicate snapshots on worker retry

Negative:
- 5-minute debounce means exposure score may lag signal reality by up to 5 minutes under normal load
- Acceptable: CTEM operates on a tactical timescale; 5-minute score lag is not operationally significant

Rejected alternative:
- **Synchronous inline recomputation:** Catastrophic at scale; one KEV list update would block the ingestion pipeline while recomputing scores for all affected assets

---

### ADR-M32-004 — Per-Tenant Versioned Amplifier Weight Governance

**Status:** Accepted  
**Date:** 2026-07-21  
**Deciders:** M32 Architecture Finalization  

#### Context

`AmplifierWeightConfiguration` controls the relative impact of each `RiskAmplifierType` on `ExposureScore`. These weights must be: per-tenant (different organizations prioritize different risk signals), auditable (weight changes affect score interpretation), and non-retroactive (historical snapshots must be interpretable against the weights in effect at the time).

#### Decision

`AmplifierWeightConfiguration` is an aggregate root with an append-only version history. Changes require `exposure:admin` role and a mandatory `change_rationale` (non-empty string). All versions are retained indefinitely. `ExposureScoreSnapshot` records carry `score_input_version` referencing the weight configuration version in effect at computation time. A weight configuration change triggers bulk recomputation of all active asset scores (via `pending_recomputations` batch insert, 1-minute debounce override).

#### Consequences

Positive:
- Full auditability: any historical snapshot can be re-interpreted knowing the weights in effect at that time
- Non-retroactive: historical risk posture reports are not altered by current weight changes
- Per-tenant: enterprise customers with custom risk frameworks are supported

Negative:
- After a weight configuration change, the tenant's entire active asset estate is queued for recomputation; for large estates this may take hours
- During recomputation: the dashboard displays a `RECOMPUTING` status banner; cached scores are labeled as `pending_update`
- Accepted trade-off: correctness over immediacy for configuration changes

Rejected alternative:
- **Global (cross-tenant) weight configuration:** Would prevent enterprise customization; violates product requirements for enterprise CTEM

---

### ADR-M32-005 — Template-Driven Exposure Reporting; LLM Narrative Deferred

**Status:** Accepted  
**Date:** 2026-07-21  
**Deciders:** M32 Architecture Finalization  

#### Context

`ExposureReport` generation (Board Risk Summary, Remediation Roadmap, Compliance Gap Report) requires readable narrative content. Options: template-driven generation (deterministic, auditable), LLM-generated narrative (richer, less deterministic), or hybrid.

#### Decision

M32 uses deterministic multi-variant template selection for all narrative generation. The dominant risk pattern in the tenant's exposure data selects the narrative template from a curated library. Templates contain dynamic data substitution but no LLM calls. LLM-assisted narrative enhancement is explicitly deferred to M36.

Template selection logic:

```
if dominant_amplifier_type == KevPresent:
  → select template: "Critical Exploit Availability"
elif dominant_amplifier_type == ThreatActorMatch:
  → select template: "Active Threat Actor Targeting"
elif dominant_amplifier_type == ConfirmedExploitation:
  → select template: "Confirmed Active Exploitation"
elif dominant_amplifier_type == DetectionGap:
  → select template: "Detection Coverage Critical Gap"
elif dominant_amplifier_type == InternetExposure:
  → select template: "Internet Attack Surface Expansion"
elif dominant_amplifier_type == AISystemRisk:
  → select template: "AI System Exposure Risk"
else:
  → select template: "General Exposure Accumulation"
```

The dominant amplifier is determined by: highest weight × highest prevalence across active ExposureRecords in the tenant.

#### Consequences

Positive:
- Fully deterministic: two identical exposure states always produce identical reports
- Auditable: the template selection logic is inspectable and testable
- No LLM dependency: reports function even when LLM services are unavailable
- Compliant with platform Invariant 7 (AI suggestions are read-only at domain boundaries)

Negative:
- Templates may read as formulaic for tenants with unusual exposure patterns
- Board-level executive narrative may not capture nuance as well as LLM-generated text
- Accepted: correctness and auditability outweigh narrative richness for M32; M36 addresses this

Rejected alternative:
- **LLM narrative in M32:** Introduces non-determinism in report generation; creates audit traceability challenge; adds LLM API dependency to the critical CTEM path

---

## 3. Architecture Corrections

The following corrections apply to `M32_ARCHITECTURE_REVIEW.md` based on decisions D1–D5. The Review document is NOT modified in place; these corrections are the authoritative overrides.

### Correction C1 — Signal Domain Taxonomy (replaces Review §3.1 ExposureRecord description)

The Review described ExposureRecord as per `(AssetRef × VulnerabilityInstanceRef)`. This is now refined. The canonical identity is `(TenantId × AssetRefId × SignalDomain × SignalSourceRefId)`. Two signal domains are in scope for M32: `VulnerabilityManagement` (M27) and `CloudSecurity` (M26). Detection gaps from M28 are amplifiers, not signal domains.

### Correction C2 — ThreatActorMatchCache as Explicit Projection

The Review described M21 integration as "M32 subscribes to ThreatActorTargetsAssetClass events" without specifying the local cache projection. The final design requires an explicit `ThreatActorMatchCache` read model as the single source of truth for threat actor matching within M32. This projection must be initialized via polling before the first event is processed.

### Correction C3 — ExposureScopePort Interface Location

The Review described `IExposureScopeQueryPort` as residing in M32's domain ports. The final decision places this interface in **M30's domain ports** (`backend/src/campaign/domain/ports/`). M32 implements the service that satisfies M30's interface. This corrects the direction of dependency ownership.

### Correction C4 — Simulation Algorithm Specificity

The Review identified the simulation algorithm as a condition to resolve. The algorithm is now frozen as `GreedyMarginalContribution` with Top-K approximation (K=200 default). `SimulationResult` must carry `algorithm`, `top_k`, `sample_size`, `approximation_mode`, and `simulation_seed` fields. The Review's risk item R03 is now mitigated (see Risk Dispositions below).

### Correction C5 — Report Narrative Method Frozen

The Review left report narrative generation open. The method is now frozen as deterministic template selection (ADR-M32-005). `ExposureReportGenerationService` must carry no LLM client dependency in M32. The `dominant_amplifier_type` selection algorithm is part of the domain service, not infrastructure.

---

## 4. Risk Dispositions (R01–R09)

---

### R01 — ExposureRecord Cardinality Ambiguity
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** Decision D1 specifies the exact identity tuple. Unique database constraint on `(tenant_id, asset_ref_id, signal_domain, signal_source_ref_id)` enforces this at the persistence layer. ADR-M32-001 is the governing record. No residual risk.

---

### R02 — Thundering Herd on Mass Signal Update
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** Decision D2 specifies the four-stage debounced recomputation pipeline. The `pending_recomputations` table absorbs mass mutations within the debounce window. Per-tenant rate limits and global ceiling prevent cascade. Back-pressure pauses dispatch when work queue exceeds threshold. ADR-M32-003 is the governing record.

Residual risk (LOW): If a mass signal event fills the `pending_recomputations` table faster than the sweep can clear it, PostgreSQL write contention on the `pending_recomputations` table could become a bottleneck. Mitigation: partition `pending_recomputations` by `tenant_id` hash in M32 Phase 1; monitor table size during load testing.

---

### R03 — Simulation Algorithm Undefined
**Original severity:** HIGH  
**Disposition:** MITIGATED  
**Resolution:** Decision D5 selects `GreedyMarginalContribution` with Top-K approximation. ADR-M32-001 through ADR-M32-005 are complete. Complexity is bounded at O(K² × S). Determinism is guaranteed. Approximation mode is surfaced in the UI.

Residual risk (LOW): For tenants with highly correlated remediations (where the greedy algorithm's ~63% quality bound is insufficient), the simulation may underweight combinatorial remediation bundles. Mitigation: Surface approximation quality metric in the `SimulationResult`; document the algorithm's suboptimality gap; post-M32 roadmap item for exact small-estate optimization.

---

### R04 — M26/M27 Event Schema Dependency
**Original severity:** MEDIUM  
**Disposition:** ACCEPTED WITH CONTROL  
**Justification:** M26 and M27 are released milestones with stable event schemas. Breaking changes to upstream event schemas require platform-level change control (EventEnvelope anti-corruption layer, Sprint 24 pattern). M32's `ExposureSignalIngestionService` translates at the adapter boundary — no upstream types enter the domain. If M26 or M27 introduces a breaking event schema change, the adapter is updated without touching the domain.

Control: The `IVulnerabilityQueryPort` and `IDetectionCoverageQueryPort` port interfaces are versioned explicitly. Adapters must carry the upstream version as a comment annotation.

---

### R05 — ExposureScoreSnapshot Historical Volume
**Original severity:** MEDIUM  
**Disposition:** ACCEPTED WITH CONTROL  
**Justification:** Append-only snapshots accumulate indefinitely. For a tenant with 10,000 assets and daily recomputation, this is ~3.6M rows/year. This is within PostgreSQL's operational range with proper indexing and tablespace management.

Control: M32 Phase 1 implements `ExposureScoreSnapshot` with:
- Partition by `tenant_id` and `computed_at` month
- Index on `(tenant_id, asset_ref_id, computed_at DESC)` for latest-snapshot queries
- Dashboard queries always use the `TenantExposureProfile` read model (pre-aggregated), never raw snapshots
- Snapshot retention policy: 2 years; configurable per tenant via `exposure:admin`; beyond retention, snapshots are archived (not deleted)

---

### R06 — M21 Integration Model Uncertainty
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** Decision D3 specifies the hybrid model. Event subscription is primary; daily polling fallback fills gaps. `ThreatActorMatchCache` local projection eliminates runtime dependency on M21 for score computation (the cache is already populated). `is_stale` flag surfaces data freshness concerns operationally. No residual architectural risk; operational risk (stale threat actor data) is surfaced and monitored.

---

### R07 — AmplifierWeightConfiguration Race on Mass Recomputation
**Original severity:** MEDIUM  
**Disposition:** MITIGATED  
**Resolution:** Weight configuration changes trigger a bulk insert into `pending_recomputations` with a 1-minute debounce override. Recomputation jobs use `score_input_version` to ensure they apply the new weight configuration (not a stale cached version). The weight configuration cache is invalidated atomically when a new `AmplifierWeightConfiguration` version is committed. Recomputation jobs that began before the weight change (and have not yet completed) will re-read the weight configuration before writing the snapshot — they will correctly use the new version.

The `AmplifierWeightConfiguration` cache invalidation must be a hard invalidation (not a TTL-based expiry). The cache is updated synchronously when the `AmplifierWeightConfigurationChanged` domain event is processed.

---

### R08 — Remediation Simulation Plan Staleness
**Original severity:** LOW  
**Disposition:** ACCEPTED  
**Justification:** An `ExposureReductionPlan` is computed at a point in time. Subsequent signal updates (new KEV entries, new detection gaps) may render a plan's projected impact stale. This is inherent to point-in-time simulation. The plan carries `simulation_computed_at` and `score_input_version` to communicate its temporal basis.

Control: Plans older than 30 days display a `PLAN_MAY_BE_STALE` warning in the UI. Plans can be recomputed on demand (triggering a new simulation from current exposure state). No automatic plan invalidation — the decision to re-plan belongs to the security team.

---

### R09 — Board Narrative Template Coverage
**Original severity:** LOW  
**Disposition:** ACCEPTED  
**Justification:** The 7-template library covers the most common dominant amplifier types. Edge cases (e.g., a tenant where AISystemRisk and ThreatActorMatch are co-dominant with equal prevalence) fall through to the `General Exposure Accumulation` template. This is correct behavior — the template library is conservative.

Control: Post-M32, the template library is extensible without code changes (templates stored in configuration, not hardcoded). New dominant-pattern templates can be added as operational experience reveals gaps. LLM-enhanced narrative in M36 will supersede template limitations.

---

## 5. Final Frozen Phase Plan

All five phases below are the authoritative implementation sequence for M32. Phases are reviewable checkpoints; implementation does not proceed to the next phase without explicit sign-off.

---

### Phase 1 — Exposure Foundation
**Scope:** Core `exposure` bounded context. ExposureRecord aggregate, signal ingestion from M27 (vulnerability signals only), score snapshot, base score computation.

**Bounded Contexts:** `exposure`

**Aggregate Roots:**
- `ExposureRecord` (identity: TenantId × AssetRefId × SignalDomain × SignalSourceRefId)
- `ExposureScoreSnapshot` (append-only)
- `AmplifierWeightConfiguration` (versioned, per-tenant)

**Domain Services:**
- `ExposureSignalIngestionService` (M27 event subscription only; other sources in later phases)
- `ExposureScoreComputationWorker` (four-stage pipeline; no M21 cache yet — ThreatActorMatch amplifier not available until Phase 3)
- `RecomputationDebouncerService`
- `RecomputationDispatcherService`

**API Commands:**
- `IngestVulnerabilitySignal` (internal; triggered by M27 event subscription)
- `SuppressExposureRecord` (requires `exposure:analyst`)
- `ConfigureAmplifierWeights` (requires `exposure:admin`)

**API Queries:**
- `GetExposureRecord(tenant_id, record_id)`
- `ListExposureRecordsByAsset(tenant_id, asset_ref, status_filter)`
- `GetLatestExposureScore(tenant_id, asset_ref)`
- `GetAmplifierWeightConfiguration(tenant_id)`

**Events Produced:**
- `ExposureRecordCreated`
- `ExposureRecordResolved`
- `ExposureRecordSuppressed`
- `ExposureScoreComputed`
- `AmplifierWeightConfigurationChanged`

**Events Consumed:**
- `VulnerabilityInstanceDiscovered` (M27)
- `VulnerabilityInstancePatched` (M27)
- `VulnerabilityKevStatusChanged` (M27)

**Migrations:**
- `0041_create_exposure_records.sql`
- `0042_create_exposure_score_snapshots.sql`
- `0043_create_amplifier_weight_configurations.sql`
- `0044_create_pending_recomputations.sql`
- `0045_create_processed_exposure_signals.sql`

**Read Models:**
- `TenantExposureProfile` (per-tenant; pre-aggregated asset-level scores)

**Dependencies:** M27 (event schema), platform `IdempotentProjectionEngine` (Sprint 25), platform `PostgreSQL DLQ` (Sprint 28/29)

**Test Strategy:**
- Unit: ExposureRecord aggregate (cardinality enforcement, amplifier lifecycle, optimistic concurrency)
- Unit: Score computation formula (all amplifier combinations)
- Integration: M27 event subscription end-to-end (ingest → record → debounce → compute → snapshot)
- Integration: AmplifierWeightConfiguration change → bulk recomputation trigger
- Integration: pending_recomputations debounce (mass mutations → single recomputation)
- Performance: 10K concurrent signal mutations (thundering herd simulation)

**Phase 1 Exit Criteria:**
- All Phase 1 tests passing
- Thundering herd performance test: 10K signal mutations in 1 minute → ≤ 1 recomputation per asset
- Multi-tenant isolation: no cross-tenant score visibility

---

### Phase 2 — Multi-Source Amplification
**Scope:** Integrate M26 (cloud security signals, InternetExposure and CloudMisconfiguration amplifiers), M28 (DetectionGap amplifier), and M31 (AISystemRisk amplifier). Extend ingestion to all signal domains.

**Bounded Contexts:** `exposure`

**New Aggregate Roots:** None (all signals become amplifiers on existing ExposureRecord or new CloudSecurity signal-domain records from M26)

**Domain Services Extended:**
- `ExposureSignalIngestionService` extended with: M26 adapter, M28 adapter, M31 adapter
- `ExposureScoreComputationWorker` now computes scores with InternetExposure, DetectionGap, CloudMisconfiguration, and AISystemRisk amplifiers active

**API Commands Added:**
- `IngestCloudSecuritySignal` (internal; M26)
- `IngestDetectionGapSignal` (internal; M28)
- `IngestAISystemRiskSignal` (internal; M31)

**Events Consumed Added:**
- `CloudMisconfigurationFound` (M26)
- `CloudMisconfigurationRemediated` (M26)
- `DetectionGapIdentified` (M28)
- `DetectionGapClosed` (M28)
- `AIThreatProfileExposureLevelChanged` (M31)

**New Outbound Ports:**
- `ICloudExposureQueryPort` (adapter to M26)
- `IDetectionCoverageQueryPort` (adapter to M28)
- `IAIRiskQueryPort` (adapter to M31)

**Migrations:**
- None additional (signal domains were designed in Phase 1; new signal_domain values are data-level additions)

**Dependencies:** M26, M28, M31 (event schemas and query ports)

**Test Strategy:**
- Unit: All 7 amplifier types with their sourcing adapters
- Integration: M26, M28, M31 event subscriptions end-to-end
- Integration: Multi-amplifier score computation (asset with 4+ active amplifiers)
- Integration: CloudSecurity signal domain (misconfig without CVE creates standalone ExposureRecord)

**Phase 2 Exit Criteria:**
- All M26, M28, M31 amplifiers active and contributing to scores
- CloudSecurity signal domain records created and resolved correctly

---

### Phase 3 — Threat Actor Integration
**Scope:** Integrate M21 (ThreatActorMatch amplifier) via hybrid model. Implement `ThreatActorMatchCache` projection. Implement `IThreatIntelligenceQueryPort` adapter and daily poll scheduler.

**Bounded Contexts:** `exposure`

**New Read Model:**
- `ThreatActorMatchCache` (per-tenant projection; indexed by CVE and asset class)

**Domain Services Added:**
- `ThreatActorMatchSyncService` (daily poll + cache update + affected-assets recomputation trigger)

**New Outbound Ports:**
- `IThreatIntelligenceQueryPort` (adapter to M21)

**Events Consumed Added:**
- `ThreatActorAssetClassTargetingUpdated` (M21; if published by M21; polling fallback if not)

**Migrations:**
- `0046_create_threat_actor_match_cache.sql`

**Dependencies:** M21 (event publication or query port)

**Test Strategy:**
- Unit: ThreatActorMatchCache population from events and polling
- Unit: Stale cache detection and surfacing
- Integration: Hybrid path (event → cache update → recomputation; poll → cache refresh → recomputation)
- Integration: M21 unavailability (cache retained; staleness flagged; existing amplifiers not removed)

**Phase 3 Exit Criteria:**
- ThreatActorMatch amplifier active in score computation
- Staleness detection working (48h no update → `is_stale = true`)
- Cold-start bootstrap working (new tenant → poll → cache populated → scores computed)

---

### Phase 4 — Remediation Impact Simulation and Campaign Scope
**Scope:** `remediation_impact` bounded context. `ExposureReductionPlan` aggregate. GreedyMarginalContribution simulation. M30 ExposureScopePort implementation.

**Bounded Contexts:** `remediation_impact`, `exposure` (ExposureScopeService addition)

**New Aggregate Roots:**
- `ExposureReductionPlan` (per-tenant; carries simulation result, plan steps, projected delta)

**Domain Services Added:**
- `ExposureReductionPlanService` (GreedyMarginalContribution simulation; Top-K approximation for large estates)
- `ExposureScopeService` (serves M30's IExposureScopeQueryPort)

**API Commands Added:**
- `GenerateExposureReductionPlan(tenant_id, candidate_remediations, plan_budget, top_k)` (requires `exposure:analyst`)
- `CommitExposureReductionPlan(tenant_id, plan_id)` (requires `exposure:analyst`)

**API Queries Added:**
- `GetExposureReductionPlan(tenant_id, plan_id)`
- `ListExposureReductionPlans(tenant_id, status_filter)`
- `QueryExposureScope(request: ExposureScopeRequest)` (serves M30)

**Events Produced Added:**
- `ExposureReductionPlanGenerated`
- `ExposureReductionPlanCommitted`

**New Inbound Ports:**
- `IExposureReductionPlanRepository`

**Migrations:**
- `0047_create_exposure_reduction_plans.sql`

**Dependencies:** M30 (`IExposureScopeQueryPort` port interface definition lives in M30; M32 implements the service)

**Test Strategy:**
- Unit: GreedyMarginalContribution algorithm (small estate, exact mode)
- Unit: Top-K approximation (large estate sampling; determinism assertion with same seed)
- Unit: Simulation result determinism (identical inputs → identical output)
- Integration: Plan generation end-to-end (signals → scores → simulation → plan)
- Integration: ExposureScopeService (M30 port contract; filter combinations)
- Integration: Plan staleness warning (plan > 30 days displays warning)

**Phase 4 Exit Criteria:**
- GreedyMarginalContribution producing verifiably deterministic plans
- Large estate sampling mode functional with approximation metadata in SimulationResult
- ExposureScopeService satisfying M30's port contract (confirmed with M30 integration test)

---

### Phase 5 — Reporting and Security Graph
**Scope:** `exposure_reporting` bounded context. `ExposureReport` aggregate. `BusinessImpactMapping` aggregate. Template-driven narrative. Security graph integration.

**Bounded Contexts:** `exposure_reporting`

**New Aggregate Roots:**
- `ExposureReport` (Board Risk Summary, Remediation Roadmap, Compliance Gap Report variants)
- `BusinessImpactMapping` (per-tenant; maps AssetRef to BusinessCriticality and ImpactDomain)

**Domain Services Added:**
- `ExposureReportGenerationService` (template selection + data substitution)
- `BusinessImpactMappingService` (CRUD for business criticality mappings)

**API Commands Added:**
- `GenerateExposureReport(tenant_id, report_type, time_range)` (requires `exposure:analyst`)
- `CreateBusinessImpactMapping(tenant_id, asset_ref, criticality, impact_domain)` (requires `exposure:engineer`)
- `UpdateBusinessImpactMapping(...)` (requires `exposure:engineer`)

**API Queries Added:**
- `GetExposureReport(tenant_id, report_id)`
- `ListExposureReports(tenant_id, report_type, date_range)`
- `GetBusinessImpactMapping(tenant_id, asset_ref)`

**Events Produced Added:**
- `ExposureReportGenerated`
- `ExposureReportDelivered` (if email/API delivery is triggered)
- `BusinessImpactMappingCreated`
- `BusinessImpactMappingUpdated`
- `ExposureGraphNodeUpserted` (to SecurityGraph write port)
- `ExposureGraphEdgeUpserted` (to SecurityGraph write port)

**New Outbound Ports:**
- `ISecurityGraphWritePort` (adapter to security graph; append-only writes for exposure nodes and edges)

**Migrations:**
- `0048_create_exposure_reports.sql`
- `0049_create_business_impact_mappings.sql`

**Dependencies:** Security graph (write port only; M32 never reads from the graph)

**Test Strategy:**
- Unit: Template selection logic (all 7 dominant amplifier patterns)
- Unit: BusinessImpactMapping CRUD with tenant isolation
- Integration: ExposureReport generation (exposure data → template selection → rendered report)
- Integration: Security graph writes (exposure nodes and edges written correctly; append-only invariant)
- Integration: Report generation with BusinessImpactMapping enrichment

**Phase 5 Exit Criteria:**
- All 7 narrative templates functional with correct dominant amplifier selection
- Security graph write integration verified (append-only; no cross-context reads)
- Board Risk Summary, Remediation Roadmap, and Compliance Gap Report all generate successfully
- Business impact mapping per-tenant isolation verified

---

## 6. Implementation Readiness

### Boundary Verification

All five bounded contexts across M32's domain are cleanly bounded:

| Context | Module Path | Aggregate Roots | Repository Interfaces |
|---|---|---|---|
| `exposure` | `backend/src/exposure/` | ExposureRecord, ExposureScoreSnapshot, AmplifierWeightConfiguration, ThreatActorMatchCache (projection) | IExposureRecordRepository, IExposureScoreSnapshotRepository, IAmplifierWeightConfigurationRepository |
| `remediation_impact` | `backend/src/remediation_impact/` | ExposureReductionPlan | IExposureReductionPlanRepository |
| `exposure_reporting` | `backend/src/exposure_reporting/` | ExposureReport, BusinessImpactMapping | IExposureReportRepository, IBusinessImpactMappingRepository |

### Multi-Tenancy Verification

All repository interfaces require `TenantId` as first argument. No repository interface has a method callable without `TenantId`. Cross-tenant access is a hard failure (`TenantContextMissingError`). RLS enforcement at the PostgreSQL layer backs this up.

### Platform Invariant Compliance

| Invariant | Compliance |
|---|---|
| Invariant 1: Domain Purity | No cross-context type imports. M26/M27/M28/M21/M29/M31 types translated at ACL adapters. |
| Invariant 2: Multi-Tenancy Non-Negotiable | All repository methods tenant-scoped. Verified in D1. |
| Invariant 3: Security Graph Append-Only | ExposureGraphNodeUpserted and ExposureGraphEdgeUpserted are write-only events. No graph reads from M32. |
| Invariant 4: Evidence Immutable | ExposureScoreSnapshot is append-only. Resolved ExposureRecords are retained (not deleted). |
| Invariant 5: Kill Switch is Domain Invariant | N/A — M32 does not introduce AI-driven autonomous actions. |
| Invariant 6: Human Approval Gates | ExposureReductionPlan requires explicit `CommitExposureReductionPlan` command by an authorized human. Simulation output is advisory — no auto-remediation in M32. |
| Invariant 7: AI Suggestion Read-Only | Template-driven narrative (ADR-M32-005) carries no AI dependency. LLM deferred to M36. If LLM is introduced in M36, it will be constrained to read-only suggestion per Invariant 7. |

### RBAC Roles

Canonical roles for M32 (following `{context}:{function}` pattern):

| Role | Capabilities |
|---|---|
| `exposure:viewer` | Read exposure records, scores, reports |
| `exposure:analyst` | `exposure:viewer` + generate/commit plans, generate reports, suppress records |
| `exposure:engineer` | `exposure:analyst` + manage business impact mappings, manage signal configurations |
| `exposure:admin` | `exposure:engineer` + configure amplifier weights, trigger manual recomputation, manage DLQ |

No role aliases. These are the canonical role identifiers used in authorization policies, audit logs, API responses, and database records.

### Open Technical Decisions (Resolved)

| Condition | Status |
|---|---|
| D1 — ExposureRecord cardinality | RESOLVED — per (TenantId × AssetRefId × SignalDomain × SignalSourceRefId) |
| D2 — Score recomputation model | RESOLVED — 4-stage debounced pipeline; 5-min default debounce |
| D3 — M21 integration model | RESOLVED — hybrid (event primary + poll fallback + local cache) |
| D4 — M30 ExposureScopePort contract | RESOLVED — pull model; M30 owns interface; M32 implements service |
| D5 — Simulation algorithm | RESOLVED — GreedyMarginalContribution; Top-K=200; B&B and IP rejected |

### Outstanding Items (Post-M32)

| Item | Priority | Notes |
|---|---|---|
| `pending_recomputations` table partitioning by tenant_id | Medium | Performance optimization; not a Phase 1 blocker |
| GreedyMarginalContribution exact mode for small estates | Low | Post-M32; add opt-in exact solver for tenants with < 1,000 assets |
| LLM narrative enhancement | Deferred to M36 | ADR-M32-005; do not introduce in M32 |
| M30 ExposureScopePort v2 versioning | Deferred | Only needed if breaking changes required; additive changes are backward-compatible |

### Pre-Implementation Checklist

Before Phase 1 begins, verify:

- [ ] M27 event schema published and stable (VulnerabilityInstanceDiscovered, VulnerabilityInstancePatched, VulnerabilityKevStatusChanged)
- [ ] Platform `IdempotentProjectionEngine` available in `backend/src/platform/` (Sprint 25)
- [ ] Platform `PostgreSQL DLQ` and replay worker available (Sprint 28/29)
- [ ] Migration sequence: next migration after current head is 0041 (confirm with `alembic current`)
- [ ] `backend/src/exposure/` module directory does not conflict with existing namespaces
- [ ] M30 has acknowledged the pull model for `IExposureScopeQueryPort` (cross-team alignment)

---

## M32 Architecture Freeze Complete.

**Architecture status:** FROZEN FOR IMPLEMENTATION  
**Bounded contexts:** `exposure`, `remediation_impact`, `exposure_reporting`  
**Module paths:** `backend/src/exposure/`, `backend/src/remediation_impact/`, `backend/src/exposure_reporting/`  
**ADRs:** ADR-M32-001 through ADR-M32-005 (complete)  
**Risks:** R01–R09 dispositioned (R01 Mitigated, R02 Mitigated, R03 Mitigated, R04 Accepted with Control, R05 Accepted with Control, R06 Mitigated, R07 Mitigated, R08 Accepted, R09 Accepted)  
**Implementation phases:** 5 phases frozen  
**Pending implementation authorization:** Required before Phase 1 begins
