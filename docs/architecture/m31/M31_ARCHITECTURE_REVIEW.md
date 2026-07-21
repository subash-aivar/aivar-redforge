# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Architecture Review

**Review Status:** APPROVED FOR IMPLEMENTATION
**Milestone:** M31
**Review Date:** 2026-07-21
**Reviewer Classification:** Independent Enterprise Architecture Review
**Source Documents Reviewed:**
- `M31_ARCHITECTURE_FREEZE.md`
- `M31_ADR.md` (ADR-M31-001 through ADR-M31-008)
- `M31_IMPLEMENTATION_PLAN.md`
- `M31_HARDENING_REVIEW.md`
- `REDFORGE_ENTERPRISE_ROADMAP_M31_M36.md`
- `REDFORGE_LONG_TERM_ARCHITECTURE.md`
- `M30_ARCHITECTURE_FREEZE.md` (integration context)
- `M29_M30_INTEGRATION_ARCHITECTURE.md`

**Not Modified:** This document contains no code, no API definitions, no repository declarations, and no schema changes. It is a documentation-only architectural review.

---

## 1. Executive Summary

M31 — Enterprise AI Security Posture Management (AI-SPM) — is architecturally well-conceived, correctly bounded, and ready for phased implementation. The design makes the right structural decisions: extending M22 inventory rather than forking it, applying the same tamper-evident evidence philosophy from M29 to supply chain integrity, correctly separating declarative behavioral governance (M31) from telemetry-based detection engineering (M28), and designing a cache-first risk scoring model that avoids both stale-silent-confidence and synchronous-blocking-latency failure modes.

The frozen architecture is internally consistent across its three bounded contexts, correctly integrates with M22/M24/M26/M27/M28 via well-defined ACL ports, and does not duplicate or redesign any completed milestone capability.

Four areas require implementation-phase attention before they become delivery blockers:
1. **Hardening Review open conditions** (four pre-conditions stated as gating Phase 1) must be explicitly closed — these are not optional.
2. **One structural refinement** is recommended: `AIThreatProfile` is modeled as both a nested entity within `AISystemAsset` and as a standalone aggregate root with its own repository. This dual positioning requires clarification before Phase 2 implementation begins.
3. **Two open questions** from the Hardening Review are high-priority design decisions that, if deferred to implementation, will produce rework: model artifact size policy for large-model provenance (Hardening Review §12.3) and Kubernetes admission controller integration model (§12.4).
4. **The Phase 3 file layout** uses a different path convention (`redforge/domain/ai_posture/`) than the M30 implementation pattern (`campaign/`, `taskgraph/`, `evaluation/`, `scenario/`, `campaignexecution/` as top-level contexts under `backend/src/`). This discrepancy requires a pre-Phase-1 path resolution to avoid a layout split across the codebase.

These are addressable items, not blocking defects in the architecture. The verdict at the conclusion of this review is affirmative.

---

## 2. Architecture Assessment

### 2.1 Domain Model Quality: EXCELLENT

The three-context structure (`ai_posture` / `ai_supply_chain` / `ai_agent_governance`) is the correct granularity for this domain, as demonstrated by ADR-M31-005's rigorous rejection of both under-partitioning (one context) and over-partitioning (five+ contexts). The aggregate boundaries are clean, the value objects are well-named, and the lifecycle state machines (AISystemAsset, ProvenanceIntegrityStatus, ShadowAIAlert, AgentOperationalEnvelope) are correctly modeled as forward-only with documented terminal states.

### 2.2 Architectural Pattern Consistency: EXCELLENT

M31 faithfully applies the platform's established patterns throughout:
- **ACL discipline:** Every cross-milestone dependency is behind a named port (`IInventoryQueryPort`, `ICloudDiscoveryQueryPort`, `IVulnerabilityQueryPort`, `IDetectionRuleQueryPort`, `IComplianceQueryPort`). This is the same pattern as M27/M28/M29/M30 and represents the platform's ACL convention at its best.
- **Multi-tenancy:** `TenantId` scoping on every aggregate root; cross-tenant `AssetRef` resolution is a hard error; discovery scope is tenant-bounded (scan never leaves the tenant's registered account set).
- **Immutability where it matters:** `ProvenanceChainEntry` and `ModelBillOfMaterials` additions are explicitly append-only, following M29's evidence chain philosophy.
- **Event-driven:** `AIDiscoveryScanCoordinator` as a domain service (ADR-M31-007) rather than a pure infrastructure job — scan runs produce domain events, not just infrastructure logs. This is the correct long-term decision even though it adds upfront complexity in Phase 3.
- **Human approval gates:** Shadow AI confirmation requires human triage (no auto-confirm path); agent envelope activation requires explicit approval; compliance attestation for attestation-required controls requires human signature. All three are consistent with Invariant 6 (the platform-wide human-approval-gate invariant from the Long-Term Architecture).

### 2.3 Integration Model Quality: VERY GOOD

The integration relationships are correctly one-directional: `ai_posture` calls `ai_supply_chain` and `ai_agent_governance` (via ACL ports for risk score computation); neither supporting context calls back into `ai_posture`. This avoids the circular dependency that would result if `AIRiskScoringService` were split across the boundary.

One integration area warrants attention: `IAssetRegistrationPort` (the M22 stub-asset creation path) is a **write** ACL to M22, which is structurally different from all other M31-to-M22 interactions (which are reads via `IInventoryQueryPort`). This write path is architecturally sound — new AI services discovered by M31 do need a canonical M22 `AIAsset` entry — but the implementation must ensure it only creates a minimal stub (asset identity: kind, source, discovery timestamp) and that M31 never writes posture data (risk scores, threat profiles) back into M22. This constraint is stated in the architecture but should be reinforced in the Phase 3 ACL adapter code review checklist.

### 2.4 Security Model Quality: EXCELLENT

The AI-SPM risk model is honestly bounded: the architecture distinguishes `Verified` (cryptographic hash matched), `Mismatched` (hash diverged — security event), `Unverified` (not yet verified), and `VerificationFailed` (infrastructure/retrieval failure, not a security signal) as four distinct states. This four-way distinction is production-quality thinking — collapsing `Mismatched` and `VerificationFailed` is a common implementation shortcut that the ADR explicitly rejects. The hardening requirement that `ProvenanceIntegrityStatus` transitions must be backed by `ProvenanceChainEntry` records (never a silent in-place column update) is exactly right.

The `AIRiskScore` staleness model (cache-first with bounded staleness, event-driven recomputation on high-signal events, explicit `is_stale` flag on every API response) is likewise honest: it acknowledges the freshness latency and surfaces it to consumers rather than hiding it.

### 2.5 Authorization Model Quality: GOOD

The six-role model (`ai_posture:reader`, `ai_posture:analyst`, `mlsecops:engineer`, `ai_posture:approver`, `ai_posture:admin`, `ai_posture:auditor`) covers the principal personas correctly. Two observations:

1. The `mlsecops:engineer` role name breaks the `<context>:<verb>` naming convention used by all prior milestones (`campaign:engineer`, `redteam:operator`, etc.). This is a minor inconsistency; consider `ai_posture:engineer` for naming symmetry, with `mlsecops:engineer` as an alias if the persona name matters for the product UI. Not a blocking issue but worth addressing before the role names are exposed in API responses and audit logs.

2. Envelope suspension (`EnvelopeState = Suspended`) requires `ai_posture:approver` or above — this is correct, as suspension is a governance action that immediately affects an agent's authorized operational status. The review confirms this is enforced at the application service boundary (not only in the API layer), consistent with the platform's authorization model.

---

## 3. Bounded Context Review

### 3.1 `ai_posture` (Core Domain)

**Aggregate Review:**

**`AISystemAsset`** — Well-bounded. Lifecycle state machine (Discovered → PendingClassification → UnderReview → Registered → Deprecated → Decommissioned) is correct and complete. Invariants are tight: `FormallyRegistered` requires `BusinessOwnerRef`, `ShadowAI` blocks `Registered`, `AgentEnvelopeRef` required-iff-AIAgent, `ModelProvenanceRef` required-iff-{model kinds}. The sealed-at-`Decommissioned` invariant matches M29's evidence sealing and is the right pattern for a legally significant asset record.

**Identified structural tension:** The freeze document lists `AIThreatProfile` as an entity *within* `AISystemAsset` (§8.2, Entity list) while simultaneously defining it as its own aggregate root (§8.2, `AIThreatProfile` Aggregate Root header) with its own `IAIThreatProfileRepository`. These are two different patterns:
- If `AIThreatProfile` is an entity within `AISystemAsset`, it is loaded with the asset, mutated via `AISystemAsset` commands, and saved by `IAISystemAssetRepository`.
- If it is a separate aggregate root with its own repository, it is loaded independently, mutated independently, and its `AIThreatProfileId` is a reference (not an embedded child) within `AISystemAsset`.

**Recommendation:** Adopt the **separate aggregate root** pattern. `AIThreatProfile` has its own domain events (`AIThreatProfileCreated`, `ThreatCategoryAssessed`, `ExposureLevelChanged`, `ThreatProfileFlaggedStale`), its own staleness domain logic, and its own query patterns (`find_stale(threshold_days, tenant)`). These are the canonical signals of a separate aggregate, not a nested entity. The `AISystemAsset` should reference `AIThreatProfileId` as a value object. This is the pattern used by `CampaignEvaluation` (separate from `CampaignInstance`) and by `TaskGraphExecution` (separate from `CampaignInstance`) in M30.

**`ShadowAIAlert`** — Correct. The mandatory `Open → UnderTriage` step before any `Confirmed*` transition is the right human-gate enforcement. The deduplication strategy (`find_by_fingerprint`) using a unique constraint on `(tenant_id, discovery_source, fingerprint_hash)` is operationally sound. Bulk triage (Hardening Review §9) is a validated need and should be scoped into Phase 1 or added to Phase 5 scope explicitly — not left as a post-milestone concern.

**`AIRiskScoreSnapshot`** — Excellent design. Append-only snapshots eliminate write contention on the hot read path. `ScoreInputVersion` versioning enables future scoring model upgrades without invalidating historical snapshots. The immutability guarantee on `CompositeScore` given fixed inputs (no manual override) is the right invariant for a governance record.

**Domain Services:** All five are correctly scoped. `AISystemClassificationService` as a human-reviewable suggestion (not a committed classification) is the right model for a risk-governance context — automated classification as a suggestion, human confirmation as the state machine gate.

### 3.2 `ai_supply_chain` (Supporting Domain)

**`ModelProvenance`** — The most security-critical aggregate in M31. The four-state `ProvenanceIntegrityStatus` FSM (`Unverified`, `Verified`, `Mismatched`, `VerificationFailed`) is correctly modeled. The invariant that `ModelOrigin = Unknown` caps status at `Unverified` is important and must be unit-tested as a first-class test (not an edge case). The `ProvenanceChainEntry` append-only requirement with database-level enforcement (Hardening Review §7) is mandatory, not optional.

**`ModelBillOfMaterials`** embedded within `ModelProvenance` — The JSONB storage choice (Implementation Plan §19) is appropriate for MBOM component variety; structured query against specific component types should use PostgreSQL JSONB operators for the `find_components_with_known_cve` query pattern. This query pattern (`IModelBillOfMaterialsRepository.find_components_with_known_cve`) returns `MBOMComponent` rows; the underlying JSONB `@>` or `jsonb_array_elements` query must be covered by a performance test against a realistically large component list (tens of components per model), not just a trivial fixture.

**`AIDiscoveryScanCoordinator` as Domain Service (ADR-M31-007)** — The decision is correct and the consequences are well-articulated. One implementation note: the `ai_discovery_scan_runs` bookkeeping table is a projection/ledger, not an event-sourced aggregate — this is fine, but the migration that creates it must specify that it is append-only (scan runs are never updated in-place; a "retry" creates a new run record with `partial_retry_of: scan_run_id`).

**Provider Ports:** Five new provider ports (`IHuggingFaceHubProviderPort`, `ICloudAIServiceProviderPort`, `IModelRegistryProviderPort`, `IMCPServerDiscoveryPort`, `IKubernetesAdmissionQueryPort`) are a significant expansion of the external integration surface. Phase 3's test strategy (all five implemented against fakes, no live provider credentials in the automated suite) is the right approach and consistent with the codebase's existing external-integration test pattern.

**Open question requiring decision before Phase 3:** The Kubernetes admission controller integration model (read-access-to-logs vs. deploy-a-webhook) is architecturally consequential and security-sensitive. Deploying a RedForge webhook into customer clusters is a significant operational trust decision. This review recommends the **read-only access to existing admission records** model for M31, with the admission-webhook model deferred to a post-M31 enhancement if customers request it. This reduces the first-deployment security posture surface and avoids a trust decision that requires customer-by-customer negotiation.

### 3.3 `ai_agent_governance` (Supporting Domain)

**`AgentOperationalEnvelope`** — The explicit-version-rows pattern (ADR-M31-008) over full event sourcing is the right tradeoff for a low-frequency governance aggregate with a simple history query pattern. The `find_active_version_at(asset_id, at)` repository method design is clean and the SQL semantics are documented correctly in the ADR.

**One implementation trap to pre-empt:** The ADR correctly notes that `WHERE state = Active` is ambiguous on historical rows. The repository implementation must use `ORDER BY envelope_version DESC LIMIT 1` for current-version lookup, and `WHERE approved_at <= ? ORDER BY envelope_version DESC LIMIT 1` for point-in-time lookup. These constraints must be enforced by repository tests, not only documented in the ADR.

**`AgentDeviationEvent`** — The forward-only `ReviewState` FSM (Unreviewed → UnderReview → {ConfirmedDeviation | ConfirmedBenign | EnvelopeUpdated}) is correct for an immutable governance record. The invariant that `ReviewState = EnvelopeUpdated` requires a linked `AgentOperationalEnvelopeRevised` event is the critical audit chain connection (Hardening Review §4). This must be enforced at the domain service level, not only as a validation check on the API input.

**`EnvelopeRevisionAdvisoryService`** — Correctly scoped as an *advisory* service only (generates recommendations, never auto-applies). The Hardening Review's concern about envelope revision becoming an evasion path is valid; the `ConfirmedBenign` mandatory `ReviewNotes` requirement is the right control.

---

## 4. Integration Review

### 4.1 M22 (Inventory) — SOUND

The `AISystemAsset` as extension (not fork) of M22 `AIAsset` is the correct integration model (ADR-M31-001). The `IInventoryQueryPort` (read) + `IAssetRegistrationPort` (stub creation write) + event subscription for M22 decommission propagation covers all integration scenarios. No M22 schema changes are required by M31.

**Risk to close before Phase 1:** The Hardening Review's first pre-condition ("M22 `AIAsset` `AssetRef` ACL pattern reviewed and confirmed compatible") should be explicitly verified against the live M22 repository implementation (not just its interface) since M22 data shapes may differ from what was current when M31's ACL was designed. Assign this verification to a named team member with a completion date before Phase 1 kick-off.

### 4.2 M26 (Cloud Security) — SOUND

`ICloudDiscoveryQueryPort` for AI service enumeration in cloud accounts is the correct pattern. M26 already enumerates cloud resources; M31 filters for AI-specific resource types from that enumeration. No M26 duplication.

**Integration dependency:** Phase 3 requires `ICloudAIServiceProviderPort` for SageMaker/Vertex AI/Azure OpenAI/Bedrock discovery. If M26's credential vault and cloud account access model is the source of the discovery credentials, this dependency must be confirmed operational before Phase 3's external provider port work begins (Hardening Review pre-condition §12.1 — credential management model confirmation).

### 4.3 M27 (Vulnerability Management) — SOUND

`IVulnerabilityQueryPort` for MBOM CVE flagging is a read-only, well-scoped integration. CVE data from M27 flows into `ModelBillOfMaterialsBuilder` to flag at-risk components; M27 receives no writes from M31. No duplication of vulnerability management.

**Note for Phase 3:** The `find_components_with_known_cve` repository method implies that M31 stores which MBOM components have CVE flags. These flags are derived from M27 data but stored in M31's read model (JSONB component list). The staleness of these CVE flags (M27's vulnerability data updates continuously, M31's MBOM components update only when a new MBOM is built) must be made observable to operators — a MBOM built six months ago may have components with subsequently discovered CVEs that M31 does not yet reflect. Recommend adding a `cve_flags_last_refreshed_at` timestamp to the MBOM component record, refreshed when `IVulnerabilityQueryPort` is polled.

### 4.4 M28 (Detection Engineering) — SOUND WITH CLARIFICATION

`IDetectionRuleQueryPort` is used for AI-specific detection rule existence checks that inform threat profile completeness (does a detection rule exist for this AI threat category?). This is a read-only reference query — M31 never modifies M28 content. The boundary stated in ADR-M31-002 is architecturally correct.

**Important clarification for implementation:** M28's `DetectionFinding` event stream must **never** be subscribed to by `ai_agent_governance` for deviation evaluation. The freeze explicitly prohibits this (`EnvelopeComplianceEvaluationService` does not receive M28 `DetectionFinding` events as input). Any implementation that routes M28 findings into the deviation evaluation pipeline is an architectural violation. Recommend adding this prohibition to the Phase 4 code review checklist.

### 4.5 M24 (Compliance) — SOUND

`IComplianceQueryPort` for EU AI Act / NIST AI RMF / ISO 42001 control resolution follows the same pattern as M24's integration with other milestones. The distinction between machine-evaluable and attestation-required controls (Hardening Review §8) requires that M24's compliance framework catalog carries this classification per control. This must be verified against M24's actual data model before Phase 5 compliance mapping implementation begins — if M24 does not carry the `requires_human_attestation` flag per control, Phase 5 will need either to extend M24's catalog data (a coordination dependency) or to maintain a M31-local mapping table for which controls require attestation.

### 4.6 M29/M30 — NO DUPLICATION CONFIRMED

M31 does not introduce any capability that overlaps with M29 (engagement governance, execution, evidence) or M30 (campaign orchestration, task graphs, evaluation). The AI-SPM domain is additive. The Security Graph extensions (new node/edge types) correctly extend the existing ontology without redefining existing nodes.

---

## 5. Risk Assessment

### Risk R01 — AIThreatProfile Dual Positioning (Medium)

As noted in §3.1, the freeze document positions `AIThreatProfile` simultaneously as a nested entity and as a standalone aggregate root. If implementation teams interpret this differently across phases (Phase 2 authors and Phase 5 read-model authors), the data access patterns will diverge mid-implementation.

**Resolution:** Adopt the standalone aggregate root pattern (separate from `AISystemAsset`). Clarify this in a pre-Phase-2 architecture note before Phase 2 work begins. No freeze-level redesign required.

### Risk R02 — Large Model Artifact Provenance Policy Deferred (High if Unresolved Before Phase 3)

The Hardening Review (§12.3) identifies that for foundation models with multi-hundred-GB weight files, streaming checksum computation carries significant cost and latency. The three policy options (provider-attested signature only, partial artifact sampling, full retrieval) have materially different security guarantees and cost profiles. If this decision is deferred to the first enterprise customer encounter in production, it will require a policy retrofit under customer-facing deadline pressure.

**Resolution:** Make the policy decision before Phase 3 implementation begins, not after. Recommendation: for models above a configurable size threshold (default: 10 GB), use `SignatureChainRef`-based verification with explicit documentation that this is trust-delegated to the provider rather than independently computed. For models below the threshold, use independent checksum computation. Document this threshold and its security implications in the AI Supply Chain Integrity Report template.

### Risk R03 — Path Convention Discrepancy (Medium)

M31 Implementation Plan (Phase 1) specifies files at `aivar-redforge/backend/src/redforge/domain/ai_posture/` (under the `redforge` monolith module). M30 (and M29/M28) use a top-level context module pattern (`backend/src/campaign/`, `backend/src/taskgraph/`, etc.) outside the `redforge` module. If M31 follows the `redforge/domain/` path, it diverges from the established M28–M30 modular pattern and re-enters the earlier monolith structure.

**Resolution:** Before Phase 1, confirm which path convention applies to M31. If M31 follows the M28–M30 top-level module pattern (strongly recommended for consistency), the expected files in the Implementation Plan should be updated to reflect paths like `backend/src/ai_posture/`, `backend/src/ai_supply_chain/`, `backend/src/ai_agent_governance/`. This is a layout decision, not an architectural one — but it must be made explicitly, not left to implementation-time improvisation.

### Risk R04 — Discovery Scan First-Run Triage Volume (Medium)

Hardening Review §9 correctly identifies that the first M31 scan against a large enterprise may produce hundreds of `ShadowAIAlert` records. The bulk triage capability is required but its phase assignment is ambiguous ("Phase 5 or Phase 1 if volume concerns are significant"). Given that large enterprises are M31's primary target, bulk triage should be scoped into Phase 1, not deferred to Phase 5 — it is a prerequisite for the product being usable, not a post-launch enhancement.

**Resolution:** Move bulk shadow AI triage capability to Phase 1 scope, or at minimum Phase 2, with Phase 3's discovery scan coordinator blocked from production deployment until bulk triage is available.

### Risk R05 — MCP Server Discovery Protocol Stability (Low-Medium)

The MCP server discovery protocol is early-stage. `IMCPServerDiscoveryPort` is exposed as a named discovery source. Protocol breaking changes could require adapter rework.

**Resolution:** The port interface is correctly designed as a thin adapter (Hardening Review §12.2 acknowledges this). Keep the adapter thin, avoid deep coupling to any specific MCP protocol version in the discovery implementation, and version the adapter separately from the rest of Phase 3 so it can be patched independently.

### Risk R06 — AIComplianceMapping Machine-vs-Attestation Boundary (Medium)

As noted in §4.5, if M24 does not carry per-control attestation classification, Phase 5 will need to maintain this mapping locally in M31. This is a coordination dependency between M24 and M31 teams that could produce a mid-Phase-5 scope surprise.

**Resolution:** Confirm M24's data model for `requires_human_attestation` per control before Phase 5 begins. Add this to the Phase 5 pre-conditions list.

### Risk R07 — Scoring Model Versioning Across `ScoreInputVersion` Changes (Low)

`AIRiskScoreSnapshotRepository.ScoreInputVersion` enables reproducibility tracking across scoring model changes. When the scoring weights change, existing snapshots carry the old `ScoreInputVersion`. Dashboards that compare scores across snapshots without displaying `ScoreInputVersion` may present apples-to-oranges comparisons silently.

**Resolution:** All read models that display trend data across multiple `AIRiskScoreSnapshot` records must surface the `ScoreInputVersion` alongside the score, or explicitly warn when multiple versions are present in the trend window. Document this as a Phase 5 read model constraint.

### Risk R08 — Cross-Context Dependency Direction Integrity (Low, Preventive)

The architecture correctly states that `ai_posture` depends on `ai_supply_chain` and `ai_agent_governance` (one-way), and those supporting contexts never call back into `ai_posture`. This is the correct direction for a core/supporting domain relationship. The risk is that during Phase 4 implementation of `ai_agent_governance`, a developer adds a direct call back to `ai_posture`'s `AIRiskScoringService` to trigger re-scoring on `AgentDeviationConfirmed`, rather than using the correct event-driven path (publish `AgentDeviationConfirmed` event → `ai_posture` subscribes → triggers re-scoring).

**Resolution:** Add to the Phase 4 code review checklist: "`ai_agent_governance` domain and application code must not import from `ai_posture` in any form." Re-scoring on deviation confirmation is event-driven, not a direct call.

---

## 6. Recommended Improvements

### I01 — Resolve AIThreatProfile Positioning Before Phase 2 (Pre-Phase-2 Required)

Explicitly confirm in a pre-Phase-2 architecture note that `AIThreatProfile` is a standalone aggregate root with its own repository, not a nested entity within `AISystemAsset`. Remove the ambiguity in the freeze document by adding a clarifying note.

### I02 — Move Bulk Shadow AI Triage to Phase 1 (Phase Reordering)

Scope bulk triage into Phase 1 alongside the `ShadowAIAlert` aggregate, rather than deferring to Phase 5. This ensures the product is usable on first production deployment without a triage backlog crisis.

### I03 — Confirm Path Convention Before Phase 1 (Pre-Phase-1 Required)

Decide: does M31 follow the `backend/src/<context>/` top-level module pattern (M28–M30) or the `backend/src/redforge/domain/<context>/` path (M31 Implementation Plan §3)? Document the decision and update the Implementation Plan expected file paths accordingly.

### I04 — Large Model Artifact Policy Decision Before Phase 3 (Pre-Phase-3 Required)

Define the per-size-threshold policy for provenance verification (full checksum vs. signature-chain-only vs. sampling-rejected). Document in the Migration/Phase 3 kick-off notes. Do not leave this as an implementation-time decision.

### I05 — Confirm M24 `requires_human_attestation` Model Before Phase 5 (Pre-Phase-5 Required)

Verify M24's compliance framework catalog carries per-control attestation classification. If not, define where M31 will maintain this mapping, before Phase 5 compliance mapping implementation begins.

### I06 — Add cve_flags_last_refreshed_at to MBOM Component Storage (Phase 3)

Include a refresh timestamp on CVE flags in the MBOM component record so that operators can see when M27 data was last cross-referenced against their model's component list.

### I07 — Rename `mlsecops:engineer` to `ai_posture:engineer` (Pre-Phase-1, Low Priority)

Rename for naming convention symmetry. Expose `mlsecops:engineer` as a product-facing alias if needed in the UI. This affects RBAC configuration and audit log attribution — cleaner to standardize before the first migration.

### I08 — Kubernetes Admission Model Decision (Pre-Phase-3 Required)

Decide and document: M31 Phase 3 uses read-only access to existing Kubernetes admission records (not a deployed webhook). Scope the webhook model as a post-M31 enhancement.

---

## 7. Phase-by-Phase Implementation Plan

### Phase 1 — AI System Asset Foundation

**Scope:** `AISystemAsset` lifecycle, `ShadowAIAlert` (including bulk triage), `IInventoryQueryPort` and `IAssetRegistrationPort` ACL to M22.

**Bounded Contexts Activated:** `ai_posture` (core aggregate layer)

**Migrations:**
- `ai_system_assets` table: tenant-scoped, unique on `(tenant_id, asset_ref_id)`, lifecycle state indexed
- `shadow_ai_alerts` table: unique on `(tenant_id, discovery_source, fingerprint_hash)`

**APIs:**
- Register AI system asset (from existing M22 asset)
- Classify asset (assign `AISystemKind`)
- Assign business owner
- Approve asset registration
- Deprecate / decommission asset
- Triage shadow AI alert (single + bulk triage endpoint)
- Resolve shadow AI alert

**Events Published:**
- `AISystemAssetDiscovered`, `AISystemAssetClassified`, `AISystemAssetRegistered`, `AISystemAssetOwnerAssigned`, `AISystemAssetDeprecated`, `AISystemAssetDecommissioned`, `ShadowAIStatusAssigned`
- `ShadowAIAlertRaised`, `ShadowAIAlertTriaged`, `ShadowAIAlertConfirmed`, `ShadowAIAlertDismissedFalsePositive`, `ShadowAIAlertResolved`

**Tests:**
- Lifecycle state machine transitions and all stated invariants
- Cross-tenant `AssetRef` resolution returns hard error
- `ShadowAIAlert` requires human triage (no auto-confirm path)
- Bulk triage: verify N alerts of same source/type triage together
- ACL integration against M22 mock and integration fixture

**Dependencies:** M22 `AIAsset` operational; `AssetRef` ACL pattern confirmed compatible.

**Pre-Phase Conditions to Close:**
- [ ] M22 `AssetRef` ACL compatibility confirmed
- [ ] Path convention decided and implementation plan file paths updated
- [ ] `mlsecops:engineer` → `ai_posture:engineer` naming decision made

**Exit Criteria:**
- Full `AISystemAsset` lifecycle covered by tests, zero M22 data duplicated
- Bulk shadow AI triage operational
- ACL to M22 tested in both directions (read and stub-write)

---

### Phase 2 — AI Threat Profiling and Risk Scoring

**Scope:** `AIThreatProfile` (standalone aggregate root), `AIRiskScoreSnapshot`, `AIRiskScoringService` (asynchronous), `AIThreatAssessmentService`, staleness sweep job.

**Bounded Contexts:** `ai_posture` (threat and scoring layer)

**Migrations:**
- `ai_threat_profiles` table: one row per asset, JSONB for typed assessment structures
- `ai_risk_score_snapshots` table: append-only, partitioned monthly by `(tenant_id, computed_at)`, index on `(tenant_id, ai_system_asset_id, computed_at DESC)`

**APIs:**
- Trigger threat assessment for an asset
- Get current risk score for an asset (returns score + `computed_at` + `is_stale`)
- Get risk score history for an asset

**Events Published:**
- `AIThreatProfileCreated`, `ThreatCategoryAssessed`, `ExposureLevelChanged`, `ThreatProfileFlaggedStale`
- `AIRiskScoreComputed`, `AIRiskScoreStalenessExceeded`

**Events Consumed:**
- `AIThreatProfileUpdated` → triggers risk score recomputation (event-driven)

**Tests:**
- `AIThreatProfile` is a separate aggregate root with its own repository (not a nested entity)
- Applicable threat categories derived correctly per `AISystemKind`
- Risk score computation is deterministic given identical inputs and `ScoreInputVersion`
- No synchronous risk score computation in any request-path handler
- Staleness sweep identifies and recomputes only assets past `StalenessBound`
- Stale score API response carries `is_stale: true` and `computed_at`
- Event-driven recomputation on `AIThreatProfileUpdated` uses guaranteed-delivery path

**Dependencies:** Phase 1 complete; `ICloudDiscoveryQueryPort` (M26) and `IDetectionRuleQueryPort` (M28) ACL stubs ready for integration tests.

**Pre-Phase Conditions:**
- [ ] `AIThreatProfile` aggregate-root positioning explicitly confirmed (I01)

**Exit Criteria:**
- Risk scoring is entirely async; zero request-path score computations
- Staleness model verified with integration tests covering both sweep-driven and event-driven recomputation
- Stale score surfaced to API consumers, never served without metadata

---

### Phase 3 — Model Provenance, MBOM, and Discovery Scanning

**Scope:** `ai_supply_chain` bounded context: `ModelProvenance`, `ModelBillOfMaterials`, `ProvenanceVerificationService`, `ModelBillOfMaterialsBuilder`, `AIDiscoveryScanCoordinator`, five provider port implementations, `ShadowAIDetectionService` wiring to Phase 1's `ShadowAIAlert`.

**Bounded Contexts Activated:** `ai_supply_chain`

**Migrations:**
- `model_provenance` table: with `ProvenanceIntegrityStatus` as an indexed column
- `provenance_chain_entries` table: **database-level append-only enforcement** (INSERT-only RLS or trigger) — mandatory per Hardening Review §7
- `model_bill_of_materials_components` table: JSONB per component, with `cve_flags_last_refreshed_at` column (I06)
- `ai_discovery_scan_runs` table: append-only, per-run summary with partition results

**APIs:**
- Trigger provenance verification (on-demand)
- Get provenance chain for a model
- Get MBOM for a model
- Trigger discovery scan (admin-only)
- Get discovery scan run history

**Events Published:**
- `ModelProvenanceRecorded`, `ProvenanceChainEntryAdded`, `ChecksumVerified`, `ProvenanceIntegrityMismatchDetected`, `ModelBillOfMaterialsCompleted`, `ModelBillOfMaterialsComponentAdded`
- `AIDiscoveryScanStarted`, `AIDiscoveryScanPartitionFailed`, `AIDiscoveryScanCompleted`, `AIAssetReconciliationResultProduced`

**Events Consumed:**
- `AIDiscoveryScanCompleted` → `ShadowAIDetectionService` → raises `ShadowAIAlertRaised`
- `ProvenanceIntegrityMismatchDetected` → `AIRiskScoringService` event-driven recomputation (via M31 internal event bus)

**Tests:**
- All four `ProvenanceIntegrityStatus` transitions including: `VerificationFailed → retry → Verified` (legitimate) and `VerificationFailed → retry → Mismatched` (tampered)
- `ModelOrigin = Unknown` caps status at `Unverified` regardless of checksum match
- `ProvenanceChainEntry` append-only enforcement: attempted update/delete raises error at DB level, not only application level
- Database-level immutability verified by integration test that directly attempts SQL UPDATE on `provenance_chain_entries`
- All five provider ports implemented against fakes with passing integration tests
- Discovery scan partition isolation: one-source failure does not block others; `partial: true` result recorded
- Shadow AI alert deduplication across repeated scans
- `AssetRegistrationPort` invoked correctly for new discovered service

**Dependencies:** Phase 1 and 2 complete; M26 credential vault confirmed accessible for provider port credentials (pre-condition Hardening Review §12.1); large-model provenance policy decided (I04); Kubernetes admission model decided (I08).

**Pre-Phase Conditions:**
- [ ] Phase 3 credential management model confirmed (M26 vault reuse)
- [ ] Large-model artifact size threshold and policy documented
- [ ] Kubernetes integration model confirmed as read-only admission record access

**Exit Criteria:**
- Database-level append-only enforcement verified on `provenance_chain_entries`
- All five provider port adapters tested against fakes
- Discovery scan partition fault isolation verified
- `ProvenanceIntegrityMismatchDetected` event triggers risk score recomputation via event bus (not direct call)

---

### Phase 4 — AI Agent Operational Envelope and Deviation Detection

**Scope:** `ai_agent_governance` bounded context: `AgentOperationalEnvelope` (versioned rows), `AgentDeviationEvent`, `EnvelopeComplianceEvaluationService`, `EnvelopeRevisionAdvisoryService`, `ReportAgentAction` application service.

**Bounded Contexts Activated:** `ai_agent_governance`

**Migrations:**
- `agent_operational_envelopes` table: versioned rows, no hard delete on revision; index on `(tenant_id, ai_system_asset_id, envelope_version DESC)` and `(tenant_id, ai_system_asset_id, approved_at DESC)` for point-in-time query
- `agent_deviation_events` table: partitioned monthly by `(tenant_id, detected_at)`

**APIs:**
- Draft agent envelope
- Approve agent envelope
- Revise agent envelope (creates new version row)
- Suspend / retire agent envelope
- Report agent action (batch endpoint, async ingestion, idempotent by action fingerprint)
- Review agent deviation (single deviation)
- Get deviation history for an agent

**Events Published:**
- `AgentOperationalEnvelopeDrafted`, `AgentOperationalEnvelopeApproved`, `AgentOperationalEnvelopeRevised`, `AgentOperationalEnvelopeSuspended`, `AgentOperationalEnvelopeRetired`
- `AgentDeviationDetected`, `AgentDeviationReviewed`, `AgentDeviationConfirmed`, `AgentDeviationDismissedBenign`

**Events Consumed:**
- `AgentDeviationConfirmed` → `ai_posture` event-driven risk score recomputation (via event bus, not direct call from `ai_agent_governance`)

**Tests:**
- Envelope active-version lookup uses `envelope_version DESC LIMIT 1`, not `WHERE state = Active`
- Point-in-time lookup: action reported against a superseded envelope version evaluates against that version's envelope, not the current
- `AgentDeviationEvent` evaluation against current envelope version is a failing test (proves the invariant)
- `RequiredApprovalBypassed` deviation → `Severity ≥ High` enforced
- `ReviewState = EnvelopeUpdated` requires linked `AgentOperationalEnvelopeRevised` event
- `ConfirmedBenign` classification requires non-nullable `ReviewNotes`
- Envelope suspension requires `ai_posture:approver` role (enforced at application service, not only API)
- Advisory service does not auto-apply revision recommendations

**Dependencies:** Phase 2 complete (for ACL to `AIRiskScoringService` via event bus); Phase 1 complete (for `AISystemAsset` agent kind validation).

**Exit Criteria:**
- Versioned envelope history correctness verified under revision-during-evaluation scenario
- `ai_agent_governance` code imports nothing from `ai_posture` domain layer (event-driven only)
- Deviation severity enforcement tested for all `DeviationType` values

---

### Phase 5 — Compliance Mapping, Security Graph, and Read Models

**Scope:** `AIComplianceMapping`, `AIComplianceMappingService`, M24 ACL, all Security Graph node/edge implementations, six read models, full end-to-end integration.

**Bounded Contexts:** `ai_posture` (compliance layer) + all three contexts (Security Graph projection, read models)

**Migrations:**
- `ai_compliance_mappings` table: indexed on `(tenant_id, ai_system_asset_id, framework_ref)`
- Projection/read-model tables for all six read models (AI Asset Inventory Dashboard, AI Risk Register, Shadow AI Discovery Report, AI Compliance Posture, AI Supply Chain Integrity Report, AI Agent Deviation Report)

**APIs (Read Models):**
- AI Asset Inventory Dashboard endpoint
- AI Risk Register endpoint
- Shadow AI Discovery Report endpoint (with coverage scope section mandatory, per Hardening Review §2)
- AI Compliance Posture endpoint (per framework)
- AI Supply Chain Integrity Report endpoint
- AI Agent Deviation Report endpoint

**Events Published:**
- `AIComplianceMappingRecorded`, `AIComplianceGapIdentified`

**Events Consumed:**
- All M31 domain events → Security Graph node/edge projection writers
- All M31 domain events → respective read model projection updaters

**Security Graph:**
All nodes and edges from Architecture Freeze §13:
- `AISystemNode`, `ModelProvenanceNode`, `AIAgentNode`, `AIThreatNode`
- `EXTENDS_ASSET`, `DEPENDS_ON_MODEL`, `TRAINED_ON_DATA`, `SERVES_INFERENCE`, `AGENT_AUTHORIZED_FOR`, `HAS_AI_THREAT`, `DEVIATED_FROM_ENVELOPE`, `MAPPED_TO_CONTROL`

**Tests:**
- `AIComplianceMappingService`: machine-evaluable vs. attestation-required distinction enforced
- `AIComplianceGapIdentified` raised for `Gap` status
- At least two framework evaluations (EU AI Act + NIST AI RMF) with mock M24 data
- All Security Graph writes idempotent under event replay
- All six read models rebuild correctly from event replay
- Shadow AI Discovery Report: coverage scope section present; `partial: true` scans flagged
- AI Risk Register: `is_stale` surfaced on stale scores; `ScoreInputVersion` displayed on trend views (I07)
- CISO persona end-to-end: onboard tenant → run discovery → verify AI Asset Inventory populated → compliance report generated

**Pre-Phase Conditions:**
- [ ] M24 `requires_human_attestation` per-control classification confirmed (I05)

**Exit Criteria:**
- All six read models implemented, registered in projection registry, idempotent under replay
- At least one compliance attestation end-to-end from fixture data
- All Security Graph extensions operational and queryable
- All milestone completion criteria (Architecture Freeze §milestone completion) met against integration data

---

## 8. Final Architecture Verdict

The M31 AI-SPM architecture is sound. It correctly identifies the right domain concepts for securing enterprise AI infrastructure, partitions them into three well-bounded contexts, integrates cleanly with M22/M24/M26/M27/M28 without duplication, applies the platform's established patterns (ACL ports, multi-tenancy, event-driven, human approval gates, evidence integrity), and anticipates the primary operational risks with documented hardening requirements.

The identified issues (AIThreatProfile dual positioning, path convention discrepancy, bulk triage deferral, unresolved pre-Phase-3 design decisions) are all solvable within the existing frozen design — they are implementation clarification items, not architectural defects. None require a redesign of any aggregate, bounded context boundary, or ACL relationship.

The eight ADRs are complete, internally consistent, and correctly capture the design decision space. The Implementation Plan's five-phase structure is logical, phase dependencies are clean, and exit criteria are measurable.

The Hardening Review's four pre-conditions must be explicitly closed with named owners and completion dates before Phase 1 begins. These are not optional process steps — they are gates that prevent rework in Phases 3 and 5.

---

**M31 Architecture Approved for Implementation.**

---

*This document is documentation only. No code, API definitions, repository declarations, database schemas, or implementation artifacts are produced by this review.*
