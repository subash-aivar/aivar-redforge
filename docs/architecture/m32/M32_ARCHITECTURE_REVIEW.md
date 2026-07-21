# M32 – Enterprise Continuous Threat Exposure Management (CTEM)
# Architecture Review

**Review Status:** APPROVED FOR IMPLEMENTATION — WITH CONDITIONS
**Milestone:** M32
**Review Date:** 2026-07-21
**Reviewer Classification:** Independent Enterprise Architecture Review

**Source Documents Reviewed:**
- `docs/roadmap/REDFORGE_ENTERPRISE_ROADMAP_M31_M36.md` — M32 strategic specification
- `docs/roadmap/REDFORGE_CAPABILITY_MATRIX.md` — M32 capability assignments
- `docs/roadmap/REDFORGE_STRATEGIC_DEPENDENCIES.md` — M32 dependency analysis
- `docs/roadmap/REDFORGE_LONG_TERM_ARCHITECTURE.md` — Platform invariants
- `docs/architecture/m31/M31_ARCHITECTURE_FREEZE.md` — Immediately preceding milestone
- `docs/architecture/m31/M31_ARCHITECTURE_FINALIZATION.md` — Finalized M31 decisions
- `docs/architecture/m31/M31_ARCHITECTURE_REVIEW.md` — M31 review precedent
- `docs/architecture/m30/` — M30 architecture (integration context)
- `docs/architecture/m28/` — M28 architecture (primary signal source)
- `docs/architecture/m27/` — M27 architecture (primary signal source)

**Status of M32 Architecture Documents:**
No M32-specific architecture freeze document, ADR set, hardening review, or implementation plan exists in the repository at the time of this review. This review is based on the roadmap strategic specification and platform source documents, and serves as the foundation for the M32 architecture freeze to be authored by the implementation team.

---

## CRITICAL PRE-REVIEW NOTICE: Milestone Identity Discrepancy

The review request described M32 as the **"Enterprise Threat Hunting Platform"** with capabilities including Hunt Templates, Hunt Scheduler, Hunt Library, IOC Correlation, TTP Correlation, AI-assisted Hunt Generation, and Continuous Hunting.

**The repository does not support this description.**

The repository's source of truth — `REDFORGE_ENTERPRISE_ROADMAP_M31_M36.md`, `REDFORGE_CAPABILITY_MATRIX.md`, and `REDFORGE_STRATEGIC_DEPENDENCIES.md` — consistently and unambiguously defines:

**M32 = Enterprise Continuous Threat Exposure Management (CTEM)**

Threat hunting as a platform capability appears in **M36** (not M32), as the `threat_hunt` supporting bounded context under `autonomous_intelligence`. Its function is described as: "proactive candidate rule generation from anomaly signals" — which is AI-assisted rule candidate generation, not a standalone threat hunting platform.

This review is conducted against the repository's definition of M32 (CTEM). The architecture review herein is based exclusively on the repository as the single source of truth, per the stated review instruction.

If the intent is to introduce a new milestone or redefine M32 as a Threat Hunting Platform, that requires: (a) an update to the roadmap documents, (b) a new strategic dependencies analysis, and (c) a fresh architecture review against the updated definition. The current review cannot support that decision — it can only review what the repository defines.

This review proceeds with M32 = CTEM.

---

## Contents

1. Executive Summary
2. Architecture Assessment
3. Bounded Context Review
4. Integration Review
5. Risk Assessment
6. Recommended Improvements
7. Implementation Phase Plan
8. Architecture Verdict

---

## 1. Executive Summary

M32 — Enterprise Continuous Threat Exposure Management (CTEM) — is the milestone that transforms RedForge from a platform of excellent individual security capabilities into a unified risk posture answer. By M31, the platform produces rich security signals from six distinct domains (cloud posture, vulnerability, detection, red team, campaign, AI-SPM) but has no mechanism to synthesize them into a coherent, prioritized exposure view. M32 is that synthesis layer.

The strategic design is sound: a correlation-and-aggregation platform that consumes signals from M26–M31 without duplicating them, amplifies exposure scores using context that individual domain tools cannot see, and produces the ranked, business-context-aware risk view that CISOs need to justify security investment and answer "what is our most critical risk right now?"

Because M32 does not yet have a frozen architecture document, this review serves a dual purpose: validating the strategic design decisions implicit in the roadmap specification, and identifying the architectural decisions that must be resolved in the M32 freeze document before implementation begins.

**Five areas require resolution before the M32 architecture freeze:**

1. **ExposureRecord cardinality model** — the roadmap implies both per-vulnerability-per-asset records (ExposureRecord description) and per-asset scoring (ExposureScore definition). The correct cardinality model — per-correlation-point or per-asset with embedded amplifier collection — must be explicitly decided before aggregate design begins.

2. **Score computation storm mitigation** — when a new KEV advisory, a new detection pack, or a new red team campaign simultaneously invalidates thousands of ExposureRecords, the recomputation load must not degrade the platform. The computation model needs a named strategy (rate-limited queue, incremental delta, or snapshot-carry-forward) before Phase 1.

3. **Amplifier weight governance model** — per-tenant weight configuration is required by the roadmap. The version-control and audit model for weight changes is architecturally consequential (a weight change retroactively affects all historical scores unless snapshots are immutable by scoring-model version, following M31's `ScoreInputVersion` pattern).

4. **Remediation simulation algorithm** — the roadmap notes "efficient approximation algorithms" for large estates. The algorithm strategy must be decided (marginal contribution, greedy knapsack, or full factorial) before Phase 4 implementation.

5. **Executive narrative generation model** — the roadmap includes narrative generation. Whether this is template-driven, LLM-assisted, or structured-data serialization is an architectural choice with security implications (Invariant 7 prohibits AI from writing directly to bounded context aggregates).

Absent these decisions, the review finds no structural defect in the M32 design as described in the roadmap. The three bounded context structure is correct, the integration model is consistent with platform patterns, and the scope is additive without duplicating any capability from M26–M31.

---

## 2. Architecture Assessment

### 2.1 Strategic Design Quality: EXCELLENT

The CTEM concept as implemented in M32 correctly occupies a gap that all prior milestones leave open. M27 scores vulnerabilities; M28 measures detection coverage; M29 confirms exploitation; M31 rates AI risk. None of these tells the CISO what an asset's total prioritized exposure is given all signals simultaneously. M32's ExposureRecord + RiskAmplifier + ExposureScore model directly addresses this gap.

The risk amplifier model is well-conceived. The five amplifier types (InternetExposure, DetectionGap, ThreatActorMatch, KevPresent, ConfirmedExploitation) represent orthogonal risk dimensions: reachability, detectability, threat targeting, known-exploitability, and confirmed exploitation. Each amplifier class maps cleanly to a specific upstream context, avoiding double-counting.

### 2.2 Bounded Context Count: CORRECT

Three bounded contexts — `exposure` (core), `remediation_impact` (supporting), `exposure_reporting` (supporting) — is the right granularity. Under-partitioning to one context would produce a monolith that owns scoring, simulation, and reporting simultaneously — high coupling. Over-partitioning to five contexts (one per amplifier type) would create artificial boundaries between concepts that share the ExposureRecord aggregate as their center of gravity.

### 2.3 Signal Consumption Model: REQUIRES DECISION

The roadmap does not specify whether M32 consumes upstream signals through **event subscriptions** (reacting to domain events published by M27/M28/M29/M30/M31/M26/M21) or through **polling** (querying upstream repositories via ACL ports on a schedule). This decision has significant architectural consequences:

- **Event-driven consumption** (recommended): M32 subscribes to domain events from upstream contexts (`VulnerabilityInstancePrioritized`, `DetectionCoverageUpdated`, `AttackActionCompleted`, `AIRiskScoreComputed`, etc.) and updates ExposureRecords in near-real-time. This follows the platform's event-driven pattern but requires that all upstream contexts publish events that M32 needs — some may not.

- **Scheduled polling via ACL ports** (fallback for gaps): M32 queries upstream repositories via ACL ports on a schedule when the upstream context does not publish the required event. This creates staleness and should be the exception, not the primary model.

The hybrid model (event-driven primary, scheduled poll for contexts without published events) is the correct approach. It must be explicitly documented in the M32 architecture freeze and ADRs before implementation begins.

### 2.4 Aggregate Design Quality: GOOD WITH CLARIFICATIONS

The roadmap's aggregate list (ExposureRecord, ExposureScore, RiskAmplifier, TenantExposureProfile, ExposureReductionPlan, ExposureTrend, BusinessImpactMapping) is logically sound but needs cardinality clarification. The review's analysis of the correct cardinality model is provided in §3.1.

### 2.5 Security Model Quality: VERY GOOD

The roadmap correctly identifies two security concerns unique to M32:
1. Exposure records aggregate sensitive information across the entire security program — access controls must be stricter than individual domain contexts, because M32's read models reveal what is *not* detected (which is operationally sensitive).
2. Remediation simulation results must not be accessible to operators without appropriate authorization — knowing that removing a specific set of controls would reduce exposure reveals the inverse: where the gaps are.

Both concerns require role-based access control at a finer granularity than typical read access. The RBAC model for M32 must include a distinct `exposure:simulation_reader` role gated above the standard `exposure:analyst` role.

### 2.6 Performance Model: REQUIRES ATTENTION

The roadmap notes that "top-N exposure queries must be sub-second even for tenants with 1M+ assets" and that "exposure score recalculation on signal change must not block the signal-producing context." These two requirements in combination constrain the architecture significantly:

- Top-N sub-second queries at 1M+ asset scale require pre-computed, indexed read models (not on-demand aggregation from ExposureRecord tables). The TenantExposureProfile read model must be maintained incrementally, not rebuilt on each query.
- Score recalculation must be async, queue-based, and rate-limited — the same pattern as M31's AIRiskScoringService.

The combination of these two constraints means M32 must implement a two-layer score model: (a) ExposureRecord stores the per-signal raw data; (b) an incremental projection maintains the per-asset ExposureScore snapshot in a pre-indexed read model. Score updates are propagated asynchronously; queries always hit the pre-computed layer.

---

## 3. Bounded Context Review

### 3.1 `exposure` (Core Domain)

**Purpose:** Aggregate exposure signals from M26–M31, compute composite risk scores, model risk amplification, and serve the authoritative per-asset exposure view.

---

#### Aggregate: `ExposureRecord`

**Cardinality Decision Required (Architecture Risk R01)**

The roadmap defines ExposureRecord as "a correlated risk finding: vulnerability + asset + context + amplifiers." This phrasing implies one ExposureRecord per vulnerability-instance per asset (i.e., a VulnerabilityInstance on AssetRef is the natural key). However, a single asset may have hundreds of vulnerability instances, and ExposureScore is defined as a per-asset aggregate.

**This review recommends the following cardinality model:**

- **ExposureRecord** — one per `(AssetRef × SignalSourceRef)` where `SignalSourceRef` identifies the upstream signal domain that produced the finding (M27 for a specific VulnerabilityInstance, M28 for a specific DetectionGap, M29 for a specific AttackAction). This is finer-grained than per-asset but coarser-grained than per-vulnerability-per-technique.
- **ExposureScore** — a derived, append-only snapshot of the composite per-asset score, computed from all ExposureRecords for that asset. Never stored as a mutable field on ExposureRecord.
- **TenantExposureProfile** — a read model (not an aggregate), maintained as an incrementally-updated projection of per-asset ExposureScores, indexed for top-N retrieval.

This model avoids the "God Aggregate" anti-pattern (one ExposureRecord per asset with 200 embedded amplifiers) while keeping per-asset score computation tractable.

**Identity:** `ExposureRecordId` (tenant-scoped UUID)

**Value Objects:**
- `ExposureRecordId`
- `AssetRef` — ACL reference to M22 `AIAsset`
- `SignalSourceRef` — typed reference to the upstream signal: `VulnerabilityInstanceRef`, `DetectionCoverageRef`, `AttackActionRef`, `AIRiskScoreRef`, `CloudMisconfigRef`
- `SignalDomain` — enum: VulnerabilityManagement | DetectionEngineering | RedTeam | AIPosture | CloudSecurity | ThreatIntelligence
- `ExposureRecordState` — enum: Active | Resolved | Superseded | Archived
- `BaseExposureWeight` — the intrinsic weight of this signal type (configurable via AmplifierWeightConfiguration, not hardcoded)
- `BusinessCriticalityRef` — ACL reference to M22 asset business criticality; applied as the primary weighting multiplier

**Entities (within ExposureRecord):**
- `RiskAmplifier` — one per active amplifier type on this record

**Aggregate Invariants:**
- An `ExposureRecord` is `Active` only while its `SignalSourceRef` exists in the upstream context; when the upstream signal is resolved (vulnerability remediated, detection gap closed, etc.), the record transitions to `Resolved`
- `ExposureRecord` never stores a computed score — scoring is delegated to the `ExposureScoreSnapshot` aggregate
- An `ExposureRecord` without at least one `RiskAmplifier` is in `Active` state with base weight only; it does not carry a zero score (even a vulnerability alone, without amplifiers, represents baseline exposure)
- `BusinessCriticalityRef` is resolved once at record creation via `IInventoryQueryPort`; it is not re-queried on every score computation (staleness of business criticality is acceptable; it changes slowly)

**Domain Events:**
- `ExposureRecordCreated`
- `RiskAmplifierAdded`
- `RiskAmplifierRemoved` (when an amplifier condition is resolved: detection gap closed, internet exposure removed)
- `ExposureRecordResolved` (upstream signal remediated)
- `ExposureRecordArchived`

---

#### Aggregate: `RiskAmplifier`

Modeled as an entity within `ExposureRecord` rather than a standalone aggregate, because it has no meaningful lifecycle independent of the record it amplifies.

**AmplifierType Enum (exhaustive for M32):**
- `InternetExposure` — asset is reachable from internet (source: M26)
- `DetectionGap` — no detection rule covers the technique associated with this vulnerability on this asset (source: M28)
- `ThreatActorMatch` — a tracked threat actor is known to target this vulnerability or asset class (source: M21)
- `KevPresent` — vulnerability is in CISA KEV (source: M27, resolved via VulnerabilityInstance enrichment)
- `ConfirmedExploitation` — a M29 red team attack action confirmed successful exploitation on this asset via this vulnerability (source: M29; the strongest amplifier)
- `CloudMisconfiguration` — cloud security misconfiguration on this asset increases exploitability (source: M26)
- `AISystemRisk` — AI system risk score (from M31) amplifies exposure for AI asset types (source: M31)

**AmplifierWeight:** Configurable per `AmplifierType` per tenant via `AmplifierWeightConfiguration`. Default weights:
- `ConfirmedExploitation`: highest weight (e.g., 3.0x)
- `KevPresent` + `ThreatActorMatch`: high weight (e.g., 2.0x each, cumulative)
- `DetectionGap`: medium weight (e.g., 1.5x)
- `InternetExposure` + `CloudMisconfiguration`: medium weight (e.g., 1.3x)
- `AISystemRisk`: parameterized by AI risk score value, not a fixed weight

**Amplifier Invariants:**
- A `ConfirmedExploitation` amplifier can only be added with a valid, non-null `AttackActionRef` (no unattributed confirmation)
- `KevPresent` is derived from `VulnerabilityInstance.is_kev` (M27 enrichment data) — it is not manually asserted
- Only one amplifier of each `AmplifierType` may be active on a given `ExposureRecord` at once

---

#### Aggregate: `ExposureScoreSnapshot`

Modeled after M31's `AIRiskScoreSnapshot` — append-only, immutable, with `ScoreInputVersion` for reproducibility.

**Identity:** `ExposureScoreSnapshotId`

**Value Objects:**
- `ExposureScoreSnapshotId`
- `AssetRef`
- `CompositeScore` — float 0–100 (weighted aggregation of all active `ExposureRecord` base weights × amplifier multipliers × `BusinessCriticalityRef` weight)
- `ScoreBreakdown` — per-`SignalDomain` score contribution (enables "why is this asset scored so high?" drill-down)
- `AmplifierSummary` — count and types of active amplifiers across all records for this asset
- `ComputedAt`
- `ScoreInputVersion` — version of the `AmplifierWeightConfiguration` used for this computation
- `StalenessBound` — max age before recomputation is required (default 24h, tenant-configurable)
- `IsStale` — computed field: `now() - ComputedAt > StalenessBound`

**Aggregate Invariants:**
- `ExposureScoreSnapshot` is immutable once created
- `CompositeScore` is deterministic given identical inputs and `ScoreInputVersion`
- The current score for an asset is always the latest `ExposureScoreSnapshot` for that `AssetRef`; stale snapshots are never served without explicit `is_stale` labeling
- Every API response that includes an exposure score must include `computed_at`, `score_input_version`, and `is_stale`

**Domain Events:**
- `ExposureScoreComputed`
- `ExposureScoreStalenessExceeded`

---

#### Aggregate: `ExposureReductionPlan`

A simulation output — a ranked list of remediation actions and their predicted exposure score impact. Immutable once generated.

**Identity:** `ExposureReductionPlanId`

**Value Objects:**
- `ExposureReductionPlanId`
- `PlanScope` — assets in scope (all tenant assets, a specific asset class, top-N highest exposure)
- `RemediationItem` — per recommended action: `RemediationRef` (to M27 `RemediationPlan`), `ProjectedScoreDelta` (per asset), `AggregateScoreDelta` (sum across tenant), `ImplementationComplexity`
- `PlanGeneratedAt`
- `ScoreInputVersion` (the same version used for current `ExposureScoreSnapshot` computation, for consistency)
- `SimulationAlgorithm` — enum: `GreedyMarginalContribution` | `TopNByDelta` | `ThresholdTarget`
- `ProjectedExposureReductionPct` — estimated aggregate score reduction if all items in the plan are implemented

**Aggregate Invariants:**
- `ExposureReductionPlan` is a simulation output; it has no lifecycle states and cannot be "executed" by M32. Execution of remediation plans is M27's domain.
- `ProjectedScoreDelta` must be disclosed with its `ScoreInputVersion` — a plan computed against outdated weights is explicitly labeled as such
- Viewing an `ExposureReductionPlan` requires `exposure:simulation_reader` role — not standard `exposure:analyst` — because it reveals detection gaps by implication

---

#### Aggregate: `AmplifierWeightConfiguration`

Per-tenant configuration of the weight multipliers for each `AmplifierType`. This aggregate is the most governance-sensitive in M32 because weight changes retroactively affect the meaning of historical `ExposureScoreSnapshot` records.

**Identity:** `AmplifierWeightConfigurationId`

**Value Objects:**
- `AmplifierWeightConfigurationId`
- `TenantId`
- `ConfigurationVersion` — incremented on every weight change
- `AmplifierWeights` — map of `AmplifierType → weight multiplier`
- `BusinessCriticalityMultipliers` — map of `BusinessCriticality → score multiplier` (Mission Critical assets get higher multiplier than Non-Critical)
- `ApprovedBy` — identity of the approver (weight changes require `exposure:admin`)
- `EffectiveFrom` — timestamp; weight changes do not retroactively alter existing `ExposureScoreSnapshot` records with a prior `ScoreInputVersion`
- `ChangeReason` — mandatory; why weights were changed (audit requirement)

**Aggregate Invariants:**
- Weight changes require `exposure:admin` role and a non-null `ChangeReason`
- A `ConfigurationVersion` change triggers a full tenant-wide `ExposureScoreSnapshot` recomputation (queued, not synchronous)
- Prior `ConfigurationVersion` values are retained indefinitely; historical `ExposureScoreSnapshot` records reference the `ScoreInputVersion` they were computed under and are not retroactively updated
- The `AmplifierWeightConfiguration` must carry all prior versions, not just the current one — audit requirement

---

#### Aggregate: `BusinessImpactMapping`

Maps a technical exposure record to a business process or business unit risk.

**Identity:** `BusinessImpactMappingId`

**Value Objects:**
- `BusinessImpactMappingId`
- `AssetRef`
- `BusinessProcessRef` — the business process or capability this asset supports (self-defined by the tenant; not an external taxonomy)
- `BusinessUnitRef`
- `DataClassificationRef` — what data classifications does this asset process?
- `FinancialImpactEstimate` — optional; tenant-supplied estimate of business impact of compromise
- `RegulatoryScope` — list of applicable regulations/frameworks (PCI DSS, HIPAA, SOX, NIS2) for this asset
- `AuthoredBy` — identity who mapped this (human-authored; not AI-generated without review)

**Aggregate Invariants:**
- `BusinessImpactMapping` is human-authored; there is no automated business impact derivation in M32
- One `BusinessImpactMapping` per `AssetRef` per tenant
- `FinancialImpactEstimate`, if provided, is explicitly labeled "Tenant-provided estimate, not platform-computed"

---

#### Domain Services in `exposure`

**`ExposureSignalIngestionService`**
Receives integration events from upstream contexts (M27, M28, M29, M30, M31, M26, M21) and creates/updates `ExposureRecord` records. This is the primary event handler for the `exposure` context. It translates foreign events into `exposure` domain operations via ACL.

**`ExposureScoreComputationService`**
Asynchronously computes `ExposureScoreSnapshot` for an asset given all active `ExposureRecord` records for that asset and the current `AmplifierWeightConfiguration` version. Never invoked synchronously from a request path. Queued via work queue with rate limiting per tenant to prevent thundering herd.

**`ExposureSignalReconciliationService`**
Periodic reconciliation job that polls upstream contexts via ACL ports for signals not yet received via events. Covers: (a) upstream contexts that don't publish events M32 needs, (b) catch-up after platform event bus outages. Not the primary signal path — a fallback.

**`ExposureScopeService`**
Produces targeted asset lists for M30 campaign scope definition: "top-N highest-exposure assets" filtered by `AISystemKind`, `BusinessCriticalityRef`, or `AmplifierType`. Read-only service consuming `ExposureScoreSnapshot` read model. This is the M32 → M30 integration surface for campaign targeting.

---

#### Repository Interfaces in `exposure`

```
IExposureRecordRepository
  save(r: ExposureRecord) → void
  find_by_id(id: ExposureRecordId, tenant: TenantId) → Option<ExposureRecord>
  find_by_asset(asset_ref: AssetRef, tenant: TenantId) → List<ExposureRecord>
  find_active_by_signal_domain(domain: SignalDomain, tenant: TenantId) → Page<ExposureRecord>
  find_by_signal_source(signal_source_ref: SignalSourceRef, tenant: TenantId) → Option<ExposureRecord>

IExposureScoreSnapshotRepository
  save(s: ExposureScoreSnapshot) → void
  find_latest_by_asset(asset_ref: AssetRef, tenant: TenantId) → Option<ExposureScoreSnapshot>
  find_top_n_by_tenant(n: int, tenant: TenantId) → List<ExposureScoreSnapshot>
  find_stale(staleness_bound: Duration, tenant: TenantId) → List<AssetRef>
  find_history_by_asset(asset_ref: AssetRef, limit: int, tenant: TenantId) → List<ExposureScoreSnapshot>

IAmplifierWeightConfigurationRepository
  save(c: AmplifierWeightConfiguration) → void
  find_current(tenant: TenantId) → Option<AmplifierWeightConfiguration>
  find_by_version(version: ConfigurationVersion, tenant: TenantId) → Option<AmplifierWeightConfiguration>
  find_all_versions(tenant: TenantId) → List<AmplifierWeightConfiguration>

IBusinessImpactMappingRepository
  save(m: BusinessImpactMapping) → void
  find_by_asset(asset_ref: AssetRef, tenant: TenantId) → Option<BusinessImpactMapping>
  find_by_business_unit(unit_ref: BusinessUnitRef, tenant: TenantId) → List<BusinessImpactMapping>
```

---

#### Outbound Ports in `exposure`

```
IEventPublisher

IInventoryQueryPort (ACL to M22)
  — Resolves AssetRef, BusinessCriticality

IVulnerabilityQueryPort (ACL to M27)
  — Resolves VulnerabilityInstance (CVE, CVSS, EPSS, KEV status)
  — Used by reconciliation service; primary path is event-driven

IDetectionCoverageQueryPort (ACL to M28)
  — Resolves DetectionCoverage per (technique × asset)
  — Used by reconciliation service; primary path is event-driven

IRedTeamQueryPort (ACL to M29)
  — Resolves confirmed exploitation status for asset × vulnerability
  — Used by reconciliation service; primary path is event-driven

IAIRiskQueryPort (ACL to M31)
  — Resolves AIRiskScore for AI system assets
  — Used by reconciliation service; primary path is event-driven

ICloudExposureQueryPort (ACL to M26)
  — Resolves internet exposure, cloud misconfiguration exposure for an asset
  — Used by reconciliation service; primary path is event-driven

IThreatIntelligenceQueryPort (ACL to M21)
  — Resolves threat actor targeting for a CVE or asset class
  — Used by reconciliation service; primary path is event-driven

ISecurityGraphWritePort
  — Writes ExposureRecordNode, RiskAmplifierNode, ExposureTrend edges

ICampaignScopePort (ACL to M30)
  — ExposureScopeService writes targeted asset lists for M30 campaign targeting
```

---

### 3.2 `remediation_impact` (Supporting Domain)

**Purpose:** Remediation simulation — compute the predicted exposure score delta from applying a set of proposed remediations. Produces `ExposureReductionPlan` records for human consumption.

---

#### Domain Service: `RemediationImpactSimulationService`

Accepts a `SimulationRequest` (set of `RemediationPlanRef` from M27) and computes the predicted `ExposureScoreDelta` per asset and in aggregate. Writes an `ExposureReductionPlan` record.

**Algorithm options (must be decided in M32 freeze — Architecture Risk R03):**

| Algorithm | Description | Suitability |
|---|---|---|
| `GreedyMarginalContribution` | Ranks remediations by marginal score delta; selects top-K for the plan | Default; computationally efficient; appropriate for estates up to ~100K assets |
| `TopNByDelta` | Ranks each remediation independently by absolute delta; no marginal contribution accounting | Fast; appropriate for initial "what would help most?" analysis |
| `ThresholdTarget` | Given a target score threshold ("reduce exposure by 30%"), selects the minimum remediation set needed | Requires more computation; appropriate for board-level goal-setting exercises |

For M32 initial implementation: `GreedyMarginalContribution` is recommended as the default. `TopNByDelta` as a fast-path alternative for large estates. `ThresholdTarget` deferred to Phase 5 or post-M32.

**Simulation Invariants:**
- Simulation never modifies `ExposureRecord` or `ExposureScoreSnapshot` — it is a read-only projection computation
- Simulation results are stamped with the `ScoreInputVersion` used so they can be reproduced
- Simulation is not served from cache; it is always freshly computed against the current `ExposureScoreSnapshot` state. A simulation computed yesterday against different weights is not reused.
- Simulation access requires `exposure:simulation_reader` role (not standard reader)

**Boundary with M27:** `remediation_impact` never authors or modifies `RemediationPlan` aggregates in M27. It only reads them via `IRemediationPlanQueryPort`. M27 owns all remediation planning; M32 only simulates the exposure impact of M27's plans.

---

### 3.3 `exposure_reporting` (Supporting Domain)

**Purpose:** Produce structured executive and operational exposure reports. Generate the Board Risk Summary and other scheduled/on-demand reports from the `exposure` context's read models.

---

#### Aggregate: `ExposureReport`

**Identity:** `ExposureReportId`

**Value Objects:**
- `ExposureReportId`
- `ReportType` — enum: TenantExposureDashboard | ExposureScoreTrend | RemediationImpactView | DetectionGapExposureView | ThreatActorExposureMap | BoardRiskSummary | AISystemExposureView
- `ReportScope` — time range, asset scope, amplifier filter
- `GeneratedAt`
- `GeneratedBy` — identity of the requestor (for audit)
- `ReportContent` — structured report body; the exact schema is type-specific

**Narrative Generation — Architecture Decision Required (Risk R05):**

The roadmap mentions "Executive exposure narrative: human-readable risk summary from machine-readable exposure data." Three implementation models are available:

- **Template-driven narrative** (recommended for M32): Structured data templates produce human-readable text using pre-authored language with slot-filling from exposure data. No LLM dependency. Deterministic, auditable, reviewer-understandable.
- **LLM-assisted narrative** (M36 enhancement): The `exposure_reporting` context provides structured data; an M36 `IntelligenceSuggestion` generates a narrative suggestion; human approves before it appears in a board report. This is the correct model for LLM involvement — write-only to suggestion aggregate, human approval gate required.
- **Hybrid**: Template-driven narrative for all standard reports; LLM-suggested narrative enhancements surfaced as suggestions for human review (M36 addition).

**This review recommends template-driven narrative for M32, with the interface designed to accept LLM-generated narrative input as an optional field in M36.** No LLM dependency in M32.

---

## 4. Integration Review

### 4.1 M27 (Vulnerability) — PRIMARY SIGNAL — SOUND

`VulnerabilityInstance` from M27 is the primary baseline signal for `ExposureRecord` creation. M32 subscribes to:
- `VulnerabilityInstanceCreated` → create `ExposureRecord` with `SignalDomain = VulnerabilityManagement`
- `VulnerabilityInstancePriorityUpdated` → update `ExposureRecord.BaseExposureWeight`
- `VulnerabilityInstanceRemediated` → transition `ExposureRecord` to `Resolved`
- `VulnerabilityInstanceKevFlagChanged` → add/remove `KevPresent` amplifier

M32 never writes back to M27. M32 reads `RemediationPlan` data via `IRemediationPlanQueryPort` for simulation only.

**No capability duplication.** M27 owns vulnerability scoring; M32 owns contextual exposure amplification.

### 4.2 M28 (Detection Engineering) — AMPLIFIER SIGNAL — SOUND

M28's `DetectionCoverage` per (technique × asset) feeds the `DetectionGap` amplifier. M32 subscribes to:
- `DetectionCoverageUpdated` → add/remove `DetectionGap` amplifier on relevant `ExposureRecord` records

M32 never writes to M28. M32 never reads `DetectionRule` internal structure — only the coverage status for a given technique on a given asset.

**Boundary clarification required in M32 freeze:** When M28 updates detection coverage for a technique (e.g., a new rule added), M32 needs to identify all `ExposureRecord` records for assets with vulnerabilities targeting that technique. This is a fan-out query (technique → vulnerabilities → assets → ExposureRecords). The implementation must use an index on `(technique_ref, tenant_id)` within M32's `ExposureRecord` table, not by calling back into M28 for each record.

### 4.3 M29 (Red Team) — STRONGEST AMPLIFIER — SOUND

Confirmed exploitation from M29 is the `ConfirmedExploitation` amplifier — the highest-weight amplifier in M32. M32 subscribes to:
- `AttackActionSucceeded` (with `confirmed_exploitation: true`) → add `ConfirmedExploitation` amplifier with `AttackActionRef`
- `AttackActionEvidenceRetracted` → remove `ConfirmedExploitation` amplifier (rare; only on evidence review revision)

**Critical invariant:** `ConfirmedExploitation` amplifier requires a valid `AttackActionRef`. M32 must not accept a `ConfirmedExploitation` signal without this reference — the evidentiary link is mandatory, not optional.

M32 never writes to M29. M29's evidence chain is immutable; M32 references it, never modifies it.

### 4.4 M30 (Campaign) — SCOPE SERVICE CONSUMER — SOUND

The integration is inverted from most: M30 consumes M32, not the other way around. M32's `ExposureScopeService` produces targeted asset lists that M30's campaign scoping can consume.

This integration requires explicit design: M30 queries M32 via a read-only `IExposureScopePort` (not a direct ACL — M30 initiates the query, M32 serves the response). M32 never pushes scope updates to M30; M30 pulls them on campaign creation.

**No capability duplication.** M30 owns campaign targeting scope definition; M32 provides the ranked asset input.

### 4.5 M31 (AI-SPM) — ADDITIVE SIGNAL — SOUND

`AIRiskScore` from M31 feeds the `AISystemRisk` amplifier for AI asset types. M32 subscribes to:
- `AIRiskScoreComputed` → add/update `AISystemRisk` amplifier on the AI asset's `ExposureRecord`
- `AIRiskScoreStalenessExceeded` → flag the `AISystemRisk` amplifier as stale (not remove it — a stale score is still a signal)

The `AISystemRisk` amplifier is unique in that its weight is not a fixed multiplier but is parameterized by the `AIRiskScore.CompositeScore` value. The amplifier weight formula must be documented in the M32 freeze (e.g., `amplifier_weight = 1.0 + (ai_risk_score / 100) * ai_risk_max_multiplier`).

**No capability duplication.** M31 owns AI posture scoring; M32 incorporates that score as one amplifier in a unified exposure view.

### 4.6 M26 (Cloud Security) — REACHABILITY SIGNAL — SOUND

`InternetExposure` and `CloudMisconfiguration` amplifiers are sourced from M26. M32 subscribes to:
- `AssetInternetExposureChanged` → add/remove `InternetExposure` amplifier
- `CloudMisconfigurationDetected` → add `CloudMisconfiguration` amplifier
- `CloudMisconfigurationRemediated` → remove `CloudMisconfiguration` amplifier

**Note for M32 freeze:** M26's misconfiguration model is asset-level (a misconfigured security group affecting an asset). M32's amplifier is also asset-level. No translation complexity.

### 4.7 M21 (Threat Intelligence) — THREAT TARGETING SIGNAL — SOUND WITH NOTE

`ThreatActorMatch` amplifier is sourced from M21. The integration model is less well-defined than other integrations because M21's event model (from M21's architecture documents) may not publish per-asset threat actor targeting events in the format M32 requires.

**Architecture Risk R06:** M21's `CrossDomainThreatCorrelation` and investigation context may not publish asset-level `ThreatActorTargetsAsset` events in the pattern M32 expects. M32 may need to compute threat actor matching itself from M21's IOC data and M22's asset data, rather than consuming a pre-computed event. The M32 freeze must explicitly resolve whether:
- (a) M21 publishes `ThreatActorTargetsAssetClass` events that M32 subscribes to, or
- (b) M32 queries M21 via `IThreatIntelligenceQueryPort` and runs its own matching

Option (a) is preferred (follows the event-driven model) but requires M21 to publish events at the asset-class level. Option (b) is the fallback.

### 4.8 M22 (Inventory) — BUSINESS CRITICALITY WEIGHTING — SOUND

`BusinessCriticality` from M22 is the primary weighting multiplier for ExposureScore. Mission Critical assets receive a higher multiplier than Non-Critical assets, ensuring that the same technical exposure is scored higher for business-critical systems.

M32 resolves `BusinessCriticality` once at `ExposureRecord` creation via `IInventoryQueryPort`. It subscribes to `AssetBusinessCriticalityChanged` to trigger ExposureScore recomputation on criticality changes.

**No capability duplication.** M22 owns asset identity and criticality; M32 applies criticality as a weighting factor.

### 4.9 Confirmed Non-Duplication

M32 does not duplicate:
- Vulnerability scanning or scoring (M27)
- Detection rule authoring or management (M28)
- Red team execution (M29/M30)
- AI risk assessment (M31)
- Cloud security posture management (M26)
- Threat intelligence (M21)
- Asset inventory (M22)

M32 is purely a correlation and aggregation layer. It reads from all of the above, amplifies and contextualizes their signals, and produces an exposure score that no individual context can produce alone.

---

## 5. Risk Assessment

### R01 — ExposureRecord Cardinality Ambiguity (HIGH — Must Resolve Before Phase 1)

The roadmap's ExposureRecord definition is ambiguous: "vulnerability + asset + context + amplifiers" implies one record per vulnerability per asset, but ExposureScore is defined as "per asset per tenant." At scale (1M assets × 10 vulnerabilities per asset average = 10M ExposureRecords per tenant), the cardinality choice materially affects storage, query performance, and score computation design.

**Resolution (this review's recommendation):** Per `(AssetRef × SignalSourceRef)` — one record per asset per upstream signal source (not one record per vulnerability, which would be too granular; not one record per asset, which would be a god aggregate). For the vulnerability domain: one ExposureRecord per `(AssetRef × VulnerabilityInstanceRef)` pair.

This must be decided in the M32 freeze before Phase 1 implementation.

### R02 — Score Computation Thundering Herd (HIGH)

When a new KEV advisory is published and M27 updates hundreds of `VulnerabilityInstance` records, M32 will receive hundreds of simultaneous `KevPresent` amplifier-add signals, triggering a fan-out of score recomputation requests for potentially thousands of affected assets. This is the thundering herd problem.

**Mitigation strategy:** Score recomputation must be debounced and batched. Incoming amplifier-add signals do not trigger immediate recomputation — they set a `recomputation_needed` flag on the asset's score record. A periodic sweep job (or a configurable debounce window, e.g., 5 minutes) batches all flagged assets and dispatches recomputation jobs to the queue. Rate-limited at per-tenant recomputation throughput ceiling.

This must be explicitly designed in the M32 freeze — not left to implementation-time improvisation.

### R03 — Remediation Simulation Algorithm at Scale (MEDIUM)

For tenants with 1M+ assets and thousands of `RemediationPlan` candidates, marginal contribution simulation is O(M × N) where M = remediations and N = assets. At scale, this is computationally expensive.

**Mitigation:** The `GreedyMarginalContribution` algorithm with a `TopK` budget (simulate only the top-K most impactful remediations, where K is configurable) bounds the computation. The M32 freeze must specify the default K and the per-tenant configurable maximum.

### R04 — Detective Gap Fan-Out Query Performance (MEDIUM)

When M28 adds a new detection rule covering technique T, M32 needs to add/remove `DetectionGap` amplifiers on all `ExposureRecord` records for assets with vulnerabilities targeting technique T. This fan-out query (technique → vulnerabilities → assets → ExposureRecords) must be indexed efficiently.

**Mitigation:** M32 maintains an internal index: `(technique_ref, tenant_id) → List[ExposureRecordId]`. This index is maintained incrementally as `ExposureRecord` records are created and as vulnerabilities are enriched with ATT&CK technique mappings. The fan-out then becomes a single indexed lookup rather than a full-table scan.

### R05 — Executive Narrative Quality (MEDIUM)

Template-driven narrative generation can produce accurate but stilted executive summaries. If the templates are designed with insufficient variation, board reports become formulaic and lose engagement value over time.

**Mitigation:** The template system should support multiple narrative variants per `ReportType`, selected based on the dominant risk pattern in the current data (e.g., "CVE-heavy" vs. "detection-gap-heavy" vs. "threat-actor-targeted" narrative variant). This is a product quality concern, not an architecture defect — but it should be designed into the `ReportTemplate` model.

### R06 — M21 Integration Event Model Uncertainty (MEDIUM)

As noted in §4.7, M21's event model may not publish asset-class-level threat actor targeting events in the format M32 needs. The `ThreatActorMatch` amplifier depends on this.

**Mitigation:** The M32 architecture freeze must explicitly verify M21's event publication model before designing the `ThreatActorMatch` amplifier integration. If M21 does not publish the required events, the fallback `IThreatIntelligenceQueryPort` polling model must be documented.

### R07 — Business Impact Mapping Human Dependency (LOW-MEDIUM)

`BusinessImpactMapping` is human-authored and optional. A tenant that has not mapped business impact for their assets will receive exposure scores that are less contextualized (missing the business process weighting). In the extreme case, a tenant with no business impact mappings receives a purely technical exposure score.

**Mitigation:** The Tenant Exposure Dashboard must clearly indicate when business impact mapping is absent, and the onboarding workflow must guide tenants through mapping their top-N most critical assets first. A "missing business impact" indicator should appear on `ExposureScoreSnapshot` records where `BusinessImpactMappingRef` is null.

### R08 — Weight Configuration Governance Burden (LOW)

Per-tenant `AmplifierWeightConfiguration` introduces configuration debt: once tenants have customized weights, platform-wide weight improvements (e.g., a new study shows `ConfirmedExploitation` should carry higher default weight) cannot be automatically propagated. Each tenant's customization becomes a blocking dependency for default weight updates.

**Mitigation:** Weight changes are versioned (`ScoreInputVersion`). The platform can publish a new "recommended" weight configuration version that tenants choose to adopt. A migration tool that shows "current config vs. recommended config" helps tenants make informed decisions. This is a product feature, not an architecture change.

### R09 — Exposure Scope Data Sensitivity (HIGH — Operational)

The `ExposureReductionPlan` and `DetectionGapExposureView` read models reveal what is *not* detected. If accessible to an operator without appropriate authorization, they reveal the exact attack paths an adversary would exploit. Access controls for these read models must be enforced at application service layer, not only at API gateway.

**Mitigation:** The `exposure:simulation_reader` role is required for `ExposureReductionPlan` access. The `DetectionGapExposureView` read model requires `exposure:analyst` or above. These role requirements must be enforced at the application service layer (not only API authorization middleware), following the platform's established authorization pattern.

---

## 6. Recommended Improvements

### I01 — Decide ExposureRecord Cardinality Before Phase 1 (Required)

Freeze the per-`(AssetRef × SignalSourceRef)` cardinality model (this review's recommendation) or an alternative, before any Phase 1 implementation begins.

### I02 — Document Thundering Herd Mitigation in M32 Freeze (Required)

The debounced/batched score recomputation strategy (debounce window + rate-limited queue) must be explicitly designed and documented. This is a platform stability concern, not an implementation detail.

### I03 — Verify M21 Event Publication Model Before Phase 3 (Required)

Before Phase 3 (ThreatActorMatch amplifier) implementation, verify whether M21 publishes `ThreatActorTargetsAssetClass` events or whether M32 must use the query port fallback. Document the result as a named decision.

### I04 — Define `ExposureScopePort` Contract for M30 Before Phase 4 (Required)

The M30 campaign scoping integration requires a named ACL port contract (`IExposureScopePort` on M30's side, or `ICampaignScopeWritePort` on M32's side). This must be defined before Phase 4 to avoid uncoordinated implementation.

### I05 — Specify Remediation Simulation Algorithm in M32 Freeze (Required)

Document `GreedyMarginalContribution` as default, `TopNByDelta` as fast-path alternative. Specify the default `TopK` budget and the per-tenant configurable maximum. `ThresholdTarget` algorithm deferred post-M32.

### I06 — Add `exposure:simulation_reader` to RBAC Model (Required)

The role must be defined in the M32 freeze authorization model. It gates: `ExposureReductionPlan` read access, `RemediationImpactSimulator` read model, `DetectionGapExposureView` read model.

### I07 — Design ExposureScoreSnapshot with ScoreInputVersion (Required)

Following M31's `AIRiskScoreSnapshot` pattern exactly. Historical snapshots must reference the `AmplifierWeightConfiguration.ConfigurationVersion` used for computation, so that weight changes don't silently invalidate historical trend data.

### I08 — Narrative Template System with Variant Support (Phase 5)

Design `ReportTemplate` to support multiple narrative variants per `ReportType`, selected by dominant risk pattern. Not required for Phase 1; required before Phase 5 executive reporting.

### I09 — Missing Business Impact Indicator on ExposureScoreSnapshot (Phase 1)

ExposureScoreSnapshot should carry `business_impact_mapped: bool` to surface when a score is not fully contextualized by business impact data.

---

## 7. Implementation Phase Plan

No M32 architecture freeze document exists. This phase plan provides the implementation-ready breakdown the freeze document must encode.

---

### Phase 1 — Exposure Foundation

**Scope:** `ExposureRecord` aggregate (with `RiskAmplifier` entity), `AmplifierWeightConfiguration`, M27 integration only, basic `ExposureScoreSnapshot`.

**Bounded Contexts Activated:** `exposure`

**New Module Paths (following M31 convention):**
```
backend/src/exposure/
  domain/
    aggregates/
    value_objects/
    services/
    events/
    ports/
  application/
  infrastructure/
    repositories/
    acl/
    adapters/
    container.py
backend/tests/exposure/
```

**Migrations:**
- `exposure_records` table: `(id, tenant_id, asset_ref_id, signal_domain, signal_source_ref, state, base_exposure_weight, business_criticality_ref, technique_index_json, created_at, resolved_at)`
- `risk_amplifiers` table: `(id, exposure_record_id, amplifier_type, weight_multiplier, evidence_ref, added_at, removed_at)`
- `exposure_score_snapshots` table: partitioned monthly by `(tenant_id, computed_at)`; append-only
- `amplifier_weight_configurations` table: all historical versions retained

**APIs:**
- Get exposure record for an asset (all active records)
- Get current exposure score for an asset
- Get exposure score history for an asset
- Configure amplifier weights (admin-only)
- Get amplifier weight configuration history

**Events Published:**
- `ExposureRecordCreated`, `RiskAmplifierAdded`, `RiskAmplifierRemoved`, `ExposureRecordResolved`
- `ExposureScoreComputed`, `ExposureScoreStalenessExceeded`

**Events Consumed:**
- From M27: `VulnerabilityInstanceCreated`, `VulnerabilityInstancePriorityUpdated`, `VulnerabilityInstanceRemediated`, `VulnerabilityInstanceKevFlagChanged`

**Tests:**
- ExposureRecord created from M27 VulnerabilityInstance event via ACL adapter
- `KevPresent` amplifier added when `VulnerabilityInstanceKevFlagChanged` (kev: true)
- `ExposureRecord` resolves when `VulnerabilityInstanceRemediated` received
- `ExposureScoreSnapshot` is append-only (no update-in-place)
- Score computation is async (no synchronous score computation in request path)
- `is_stale` flag returned on scores exceeding StalenessBound
- `business_impact_mapped: false` indicator on records without BusinessImpactMapping
- AmplifierWeightConfiguration changes require `exposure:admin` role and non-null ChangeReason

**Dependencies:** M27 operational; event bus subscription to M27 events confirmed.

**Pre-Phase Conditions:**
- [ ] ExposureRecord cardinality model decided (I01)
- [ ] Thundering herd mitigation strategy documented (I02)

**Exit Criteria:**
- Full M27 vulnerability signal ingestion pipeline operational
- Score computation is fully asynchronous
- AmplifierWeightConfiguration version-controlled with all historical versions retained

---

### Phase 2 — Multi-Source Amplification

**Scope:** M28 `DetectionGap` amplifier, M26 `InternetExposure` and `CloudMisconfiguration` amplifiers, technique-to-asset fan-out index, per-asset score aggregation.

**Events Consumed (additions):**
- From M28: `DetectionCoverageUpdated` (adds/removes `DetectionGap` amplifier for covered/uncovered techniques)
- From M26: `AssetInternetExposureChanged`, `CloudMisconfigurationDetected`, `CloudMisconfigurationRemediated`

**APIs (additions):**
- Detection Gap Exposure View (assets with `DetectionGap` amplifier, by risk level)

**Tests:**
- Fan-out index: adding a detection rule for technique T removes `DetectionGap` from all `ExposureRecord` records for assets with vulnerabilities targeting T
- `InternetExposure` amplifier added when asset becomes internet-exposed; removed when exposure changes
- Score correctly reflects additive amplification from multiple simultaneous amplifiers

**Dependencies:** Phase 1 complete; M28 `DetectionCoverage` event model confirmed.

**Pre-Phase Conditions:**
- [ ] Technique fan-out index design confirmed (R04 mitigation strategy)

---

### Phase 3 — Red Team and Threat Actor Amplification

**Scope:** M29 `ConfirmedExploitation` amplifier, M21 `ThreatActorMatch` amplifier, `ExposureScoreTrend` read model (time-series snapshots).

**Events Consumed (additions):**
- From M29: `AttackActionSucceeded` (with confirmed exploitation), `AttackActionEvidenceRetracted`
- From M21: `ThreatActorTargetsAssetClass` (or polling via `IThreatIntelligenceQueryPort` if M21 does not publish this event)

**APIs (additions):**
- Threat Actor Exposure Map read model
- Exposure Score Trend read model (week/month/quarter)

**Tests:**
- `ConfirmedExploitation` amplifier requires valid `AttackActionRef`; null ref rejected at domain layer
- `AttackActionEvidenceRetracted` removes `ConfirmedExploitation` amplifier
- Score trend is correctly computed across multiple `ExposureScoreSnapshot` records over time
- `ScoreInputVersion` in trend view is surfaced when multiple versions exist in the time window

**Dependencies:** Phase 2 complete; M29 event publication model confirmed; M21 event model verified (I03).

**Pre-Phase Conditions:**
- [ ] M21 integration model decided: event subscription vs. `IThreatIntelligenceQueryPort` polling (I03)

---

### Phase 4 — AI System Exposure and Campaign Scope

**Scope:** M31 `AISystemRisk` amplifier, M22 `BusinessImpactMapping`, `ExposureScopeService` → M30 integration, `ExposureReductionPlan` aggregate, `RemediationImpactSimulationService`.

**Events Consumed (additions):**
- From M31: `AIRiskScoreComputed`, `AIRiskScoreStalenessExceeded`
- From M22: `AssetBusinessCriticalityChanged`

**New Aggregate:** `ExposureReductionPlan` (see §3.1)
**New Domain Service:** `RemediationImpactSimulationService`
**New Domain Service:** `ExposureScopeService` (serves M30 campaign scoping)

**APIs (additions):**
- AI System Exposure View read model (AI assets with `AISystemRisk` amplifier)
- Remediation Impact Simulator (request simulation → returns `ExposureReductionPlan`)
- Exposure Scope API (serves campaign targeting requests from M30)
- Business Impact Mapping CRUD (human-authored per asset)

**Tests:**
- `AISystemRisk` amplifier weight is parameterized by AI risk score value (not fixed)
- `ExposureReductionPlan` is immutable once generated
- Simulation access requires `exposure:simulation_reader` role (enforced at application service layer)
- `ExposureScopeService` returns top-N assets filtered by amplifier type — correctly excludes resolved records
- `BusinessImpactMapping` is one-per-asset per tenant

**Dependencies:** Phase 3 complete; M31 operational; M30 `IExposureScopePort` contract defined (I04).

**Pre-Phase Conditions:**
- [ ] `ExposureScopePort` ACL contract defined between M32 and M30 (I04)
- [ ] Remediation simulation algorithm specified in freeze (I05)

---

### Phase 5 — Reporting, Security Graph, and Read Models

**Scope:** All remaining read models, `exposure_reporting` bounded context, `BusinessImpactMapping` aggregation into reports, Security Graph node/edge implementations, full tenant exposure dashboard.

**New Bounded Context:** `exposure_reporting`
**New Module Path:** `backend/src/exposure_reporting/`

**Migrations:**
- `exposure_reports` table: one per generated report; content as JSONB

**Read Models Implemented:**
- Tenant Exposure Dashboard (top-N highest exposure assets; sub-second query required)
- Exposure Score Trend (week/month/quarter sparklines)
- Remediation Impact Simulator view
- Detection Gap Exposure View (`exposure:analyst` required)
- Threat Actor Exposure Map
- Board Risk Summary (template-driven narrative)
- AI System Exposure View

**Security Graph:**
- `ExposureRecordNode`: `exposure_record_id`, `signal_domain`, `composite_score`, `amplifier_count`
- `RiskAmplifierNode`: `amplifier_type`, `weight_multiplier`, `evidence_ref`
- Edges: `AMPLIFIES_EXPOSURE` (RiskAmplifierNode → AssetNode), `REDUCES_EXPOSURE` (RemediationRef → ExposureRecordNode), `EXPOSURE_TREND` (ExposureScoreSnapshot time-series edge per asset)

**Tests:**
- Top-N Tenant Exposure Dashboard query is sub-second against 100K-asset test fixture
- Board Risk Summary narrative variant selected correctly by dominant risk pattern
- All Security Graph writes are idempotent under event replay
- All read models rebuild correctly from event replay

**Pre-Phase Conditions:**
- [ ] Narrative template system designed with variant support (I08)
- [ ] Top-N query performance confirmed with appropriate indexing strategy

**Exit Criteria:**
- All seven read models operational
- Top-N exposure dashboard sub-second at 100K asset scale
- Security Graph extensions operational and queryable
- Board Risk Summary generatable in under 5 minutes from live data

---

## 8. Architecture Verdict

### Scope Identity Verdict

The repository defines M32 as Enterprise Continuous Threat Exposure Management (CTEM). The request described M32 as Enterprise Threat Hunting Platform. **The repository is the source of truth.** This review is for CTEM.

If the product roadmap is changing to redefine M32 as a Threat Hunting Platform, that requires:
1. Updated roadmap documents in the repository
2. Updated capability matrix
3. Updated strategic dependencies analysis
4. A fresh architecture review against the new definition

This review cannot be used to support an undocumented redefinition.

### Architecture Verdict: CTEM

The M32 CTEM architecture, as described in the roadmap and as elaborated in this review, is sound. The three bounded context structure is correct and appropriately scoped. The integration model with M26–M31 is additive and non-duplicative. The aggregate model, once the cardinality decision is made, is consistent with the platform's established DDD patterns. The performance model (cache-first scores, async computation, debounced thundering herd) follows the pattern established by M31.

Five items must be resolved in the M32 architecture freeze document before Phase 1 begins:
1. ExposureRecord cardinality model (I01, R01)
2. Score computation thundering herd mitigation strategy (I02, R02)
3. M21 integration event model (I03, R06)
4. ExposureScopePort contract for M30 (I04)
5. Remediation simulation algorithm specification (I05, R03)

These are design decisions that must be frozen before implementation begins. None require a redesign of the strategic architecture.

Five additional ADRs are required before the M32 architecture freeze is complete:
- **ADR-M32-001:** ExposureRecord cardinality model
- **ADR-M32-002:** Signal consumption model (event-driven primary, polling fallback)
- **ADR-M32-003:** Score computation pattern (async, debounced, rate-limited — following M31 ADR pattern)
- **ADR-M32-004:** Amplifier weight governance model (versioned, audit-required, non-retroactive)
- **ADR-M32-005:** Executive narrative generation model (template-driven for M32; LLM-optional in M36)

---

**M32 Architecture Approved for Implementation.**

This approval is conditional on:
1. An M32 architecture freeze document being authored before Phase 1 begins, resolving the five decisions above
2. Five ADRs (ADR-M32-001 through ADR-M32-005) authored as part of the freeze
3. A hardening review conducted before the freeze is finalized
4. The module path `backend/src/exposure/`, `backend/src/remediation_impact/`, `backend/src/exposure_reporting/` confirmed following the M28–M31 top-level context module convention

---

*This document is documentation only. No code, API definitions, repository implementations, migration files, or implementation artifacts are produced by this review. No production files have been modified.*
