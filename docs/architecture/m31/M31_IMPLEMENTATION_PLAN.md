# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Implementation Plan

**Status:** READY FOR REVIEW
**Milestone:** M31
**Date:** 2026-07-21
**Architecture Ref:** M31_ARCHITECTURE_FREEZE.md
**Prerequisite:** M22 fully operational (inventory + `AIAsset`); M26 cloud discovery operational; M27 vulnerability correlation operational; M28 detection rule catalog operational (strongly recommended, not hard-blocking)

---

## Overview

M31 depends on M22 as its foundation — no `AISystemAsset` can exist without a resolvable M22 `AIAsset`. M31 is divided into five phases. Phase 1 establishes the `ai_posture` core aggregate and its ACL to M22. Phase 2 adds AI threat profiling and risk scoring. Phase 3 establishes `ai_supply_chain` (provenance, MBOM, discovery scanning). Phase 4 establishes `ai_agent_governance`. Phase 5 delivers compliance mapping, Security Graph integration, and all read models.

Repository path convention follows the existing `redforge` backend layout (`aivar-redforge/backend/src/redforge/{domain,application,infrastructure,api}/<context>/...`), matching the pattern used by `inventory`, `campaigns`, `posture`, and `compliance`.

---

## Phase 1 — AI System Asset Foundation

### Objectives
Establish the `ai_posture` bounded context's core aggregate: `AISystemAsset`, its lifecycle, its ACL to M22 inventory, and shadow AI alert scaffolding (without discovery scan automation, which lands in Phase 3).

### Scope
**Aggregates:** `AISystemAsset`, `ShadowAIAlert`
**Repositories:** `IAISystemAssetRepository`, `IShadowAIAlertRepository`
**Application Services:** `RegisterAISystemAsset`, `ClassifyAISystemAsset`, `AssignAssetOwner`, `ApproveAISystemAssetRegistration`, `DeprecateAISystemAsset`, `DecommissionAISystemAsset`, `TriageShadowAIAlert`, `ResolveShadowAIAlert`
**Domain Services:** `AISystemClassificationService`
**ACL:** `IInventoryQueryPort` (M22 asset resolution), `IAssetRegistrationPort` (M22 stub asset creation)

### Expected Files
- `aivar-redforge/backend/src/redforge/domain/ai_posture/entity.py` — `AISystemAsset`, `ShadowAIAlert`
- `aivar-redforge/backend/src/redforge/domain/ai_posture/value_objects.py` — `AISystemKind`, `AISystemLifecycleState`, `RegistrationStatus`, `DataSensitivityClassification`, `AlertState`, `ResolutionAction`, `DiscoveredServiceFingerprint`
- `aivar-redforge/backend/src/redforge/domain/ai_posture/events.py`
- `aivar-redforge/backend/src/redforge/domain/ai_posture/identity.py`
- `aivar-redforge/backend/src/redforge/domain/ai_posture/exceptions.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/ai_system_asset_service.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/shadow_ai_alert_service.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_posture/repositories.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_posture/acl/inventory_acl.py` — translates M22 `AIAsset` ↔ `AssetRef`
- `aivar-redforge/backend/src/redforge/api/v1/ai_posture.py` — read/command endpoints for asset registration and shadow AI triage

### Tests
- Unit: lifecycle state machine transitions and invariants (owner required before Registered, sealed after Decommissioned, ShadowAI blocks Registered)
- Unit: `AssetRef` resolution failure handling (cross-tenant, non-existent M22 asset)
- Unit: `ShadowAIAlert` state machine (Open → UnderTriage mandatory before Confirmed*; Resolved requires ResolutionAction)
- Integration: ACL round-trip against M22 inventory (mock and real): create `AISystemAsset` from an existing `AIAsset`; attempt creation against non-existent asset fails cleanly
- Integration: cross-tenant `AssetRef` resolution returns hard error, not empty result

### Migrations (conceptual)
- New tables: `ai_system_assets`, `shadow_ai_alerts` — both tenant-scoped, `ai_system_assets` unique on `(tenant_id, asset_ref_id)`, `shadow_ai_alerts` unique on `(tenant_id, discovery_source, fingerprint_hash)`
- Foreign key relationship to M22's asset table is logical (via `asset_ref_id`), not a hard DB foreign key across bounded-context schemas — consistent with existing ACL boundary conventions in this codebase (M27/M28/M29/M30 reference `AssetRef` the same way)

### Validation Steps
- Register an `AISystemAsset` against a real M22 `AIAsset` fixture; verify full lifecycle to `Registered`
- Attempt to register without `BusinessOwnerRef`; verify rejection
- Raise a `ShadowAIAlert` manually (no discovery automation yet); triage to `ConfirmedShadowAI`; resolve via `RegisteredAsAsset`; verify `LinkedAISystemAssetRef` populated

### Exit Criteria
- [ ] `AISystemAsset` full lifecycle covered by passing tests
- [ ] `ShadowAIAlert` full lifecycle covered by passing tests
- [ ] ACL to M22 verified against both mock and integration fixture
- [ ] No AI-SPM code path duplicates M22 asset identity or ownership data

---

## Phase 2 — AI Threat Profiling and Risk Scoring

### Objectives
Implement `AIThreatProfile` assessment and the asynchronous `AIRiskScoringService` producing `AIRiskScoreSnapshot`.

### Scope
**Aggregates:** `AIThreatProfile`, `AIRiskScoreSnapshot`
**Repositories:** `IAIThreatProfileRepository`, `IAIRiskScoreSnapshotRepository`
**Domain Services:** `AIThreatAssessmentService`, `AIRiskScoringService`
**ACL:** `ICloudDiscoveryQueryPort` (M26, system configuration signals for assessment), `IDetectionRuleQueryPort` (M28, rule-coverage-informed threat profile completeness)

### Expected Files
- `aivar-redforge/backend/src/redforge/domain/ai_posture/threat_profile.py` — `AIThreatProfile`, assessment value objects
- `aivar-redforge/backend/src/redforge/domain/ai_posture/risk_score.py` — `AIRiskScoreSnapshot`, `ScoreComponents`
- `aivar-redforge/backend/src/redforge/application/ai_posture/threat_assessment_service.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/risk_scoring_service.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_posture/acl/cloud_discovery_acl.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_posture/acl/detection_rule_acl.py`
- `aivar-redforge/backend/src/redforge/infrastructure/scheduler/ai_risk_score_staleness_sweep.py` — scheduled staleness sweep job

### Tests
- Unit: `ApplicableThreatCategories` derivation per `AISystemKind`
- Unit: exposure-level assignment logic for each of the three named assessments (prompt injection, model extraction, training data leakage)
- Unit: staleness flagging at configurable threshold
- Unit: `AIRiskScoringService` composite score determinism given identical `ScoreComponents` + `ScoreInputVersion`
- Integration: end-to-end score computation pulling from ACL mocks for M26/M28 (and stub ACLs for ai_supply_chain/ai_agent_governance until Phases 3–4 land — use interface-level fakes)
- Integration: staleness sweep identifies and recomputes assets past `StalenessBound`; verifies no recomputation for fresh snapshots (idempotent no-op)

### Migrations (conceptual)
- New tables: `ai_threat_profiles` (one row per asset, with nested assessment structure as JSONB for the three typed assessments plus generic category assessments), `ai_risk_score_snapshots` (append-only, partitioned monthly by `(tenant_id, computed_at)`)
- Index: `ai_risk_score_snapshots (tenant_id, ai_system_asset_id, computed_at DESC)` for latest-snapshot lookup

### Validation Steps
- Compute a risk score for a fixture asset with a known threat profile; verify score components sum/weight correctly per documented formula
- Simulate `AIThreatProfileUpdated` event; verify event-driven recomputation triggers (not just staleness-sweep-driven)
- Verify a computation failure (ACL dependency down) leaves the prior snapshot intact and flags staleness rather than erroring the read path

### Exit Criteria
- [ ] Threat profile assessment logic covered for all three named assessment types
- [ ] Risk score computation is deterministic and reproducible given fixed inputs
- [ ] Staleness sweep verified via integration test
- [ ] No synchronous risk score computation exists anywhere in a request-path read handler

---

## Phase 3 — Model Provenance, MBOM, and Discovery Scanning

### Objectives
Implement the `ai_supply_chain` bounded context: `ModelProvenance` with cryptographic checksum verification, `ModelBillOfMaterials`, and `AIDiscoveryScanCoordinator` batch discovery scanning feeding shadow AI detection.

### Scope
**Aggregates:** `ModelProvenance` (with `ModelBillOfMaterials` as owned entity)
**Repositories:** `IModelProvenanceRepository`, `IModelBillOfMaterialsRepository`
**Domain Services:** `ProvenanceVerificationService`, `ModelBillOfMaterialsBuilder`, `AIDiscoveryScanCoordinator`, `ShadowAIDetectionService` (wires Phase 1's `ShadowAIAlert` to real discovery output)
**Outbound Ports:** `IHuggingFaceHubProviderPort`, `ICloudAIServiceProviderPort`, `IModelRegistryProviderPort`, `IMCPServerDiscoveryPort`, `IKubernetesAdmissionQueryPort`
**ACL:** `IVulnerabilityQueryPort` (M27, CVE flagging for MBOM components)

### Expected Files
- `aivar-redforge/backend/src/redforge/domain/ai_supply_chain/entity.py` — `ModelProvenance`, `ProvenanceChainEntry`, `ModelBillOfMaterials`
- `aivar-redforge/backend/src/redforge/domain/ai_supply_chain/value_objects.py`
- `aivar-redforge/backend/src/redforge/domain/ai_supply_chain/events.py`
- `aivar-redforge/backend/src/redforge/application/ai_supply_chain/provenance_verification_service.py`
- `aivar-redforge/backend/src/redforge/application/ai_supply_chain/mbom_builder_service.py`
- `aivar-redforge/backend/src/redforge/application/ai_supply_chain/discovery_scan_coordinator.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/providers/huggingface_hub_provider.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/providers/cloud_ai_service_provider.py` (SageMaker/Vertex/Azure OpenAI/Bedrock adapters)
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/providers/model_registry_provider.py` (MLflow/DVC/W&B adapters)
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/providers/mcp_server_discovery_provider.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/providers/kubernetes_admission_provider.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_supply_chain/acl/vulnerability_acl.py`
- `aivar-redforge/backend/src/redforge/infrastructure/scheduler/ai_discovery_scan_job.py`

### Tests
- Unit: checksum comparison logic; `Unverified → Verified/VerificationFailed`, `Verified → Mismatched`, never a silent auto-revert
- Unit: `ModelOrigin = Unknown` caps status at `Unverified` regardless of checksum match
- Unit: `ProvenanceChainEntry` append-only enforcement (edit/delete attempts raise invariant errors)
- Unit: MBOM completeness rule (requires ≥1 `BaseModel` component)
- Integration: each provider port against a fake/mock implementation (real provider credentials are out of scope for this milestone's automated test suite — live E2E is a separate operational validation task, per this repo's existing pattern for external provider integrations)
- Integration: `AIDiscoveryScanCoordinator` partition-level partial failure — one source fails, others complete, `partial: true` result recorded, failed partition retried on next run
- Integration: `ShadowAIDetectionService` raises `ShadowAIAlert` for a discovered fingerprint with no matching `AISystemAsset`; deduplicates on re-scan
- Integration: `AssetRegistrationPort` invoked correctly for a genuinely new discovered AI service (creates M22 stub asset, then `AISystemAsset` extension)

### Migrations (conceptual)
- New tables: `model_provenance`, `provenance_chain_entries` (append-only), `model_bill_of_materials_components` (JSONB or normalized component table, per component type)
- Discovery scan bookkeeping table: `ai_discovery_scan_runs` (per-run summary: sources scanned, partitions failed, duration) for Observability §18 metrics backing

### Validation Steps
- Verify checksum for a fixture model artifact end-to-end (compute → compare → status transition → event)
- Run a full discovery scan against fixture provider mocks covering all five discovery source types; verify reconciliation output and resulting shadow AI alerts
- Deliberately fail one provider mock mid-scan; verify partial result handling and no impact on other partitions

### Exit Criteria
- [ ] All five provider port adapters implemented against fakes with passing integration tests
- [ ] Checksum verification never trusts unverified metadata as `Verified`
- [ ] Discovery scan partition isolation verified under simulated partial failure
- [ ] Shadow AI alert deduplication verified across repeated scans

---

## Phase 4 — AI Agent Operational Envelope and Deviation Detection

### Objectives
Implement the `ai_agent_governance` bounded context: envelope authoring/approval, versioned envelope history, and deviation evaluation against reported agent actions.

### Scope
**Aggregates:** `AgentOperationalEnvelope`, `AgentDeviationEvent`
**Repositories:** `IAgentOperationalEnvelopeRepository`, `IAgentDeviationEventRepository`
**Domain Services:** `EnvelopeComplianceEvaluationService`, `EnvelopeRevisionAdvisoryService`
**Application Services:** `DraftAgentEnvelope`, `ApproveAgentEnvelope`, `ReviseAgentEnvelope`, `SuspendAgentEnvelope`, `RetireAgentEnvelope`, `ReportAgentAction`, `ReviewAgentDeviation`

### Expected Files
- `aivar-redforge/backend/src/redforge/domain/ai_agent_governance/entity.py` — `AgentOperationalEnvelope`, `AgentDeviationEvent`
- `aivar-redforge/backend/src/redforge/domain/ai_agent_governance/value_objects.py`
- `aivar-redforge/backend/src/redforge/domain/ai_agent_governance/events.py`
- `aivar-redforge/backend/src/redforge/application/ai_agent_governance/envelope_service.py`
- `aivar-redforge/backend/src/redforge/application/ai_agent_governance/deviation_evaluation_service.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_agent_governance/repositories.py`
- `aivar-redforge/backend/src/redforge/api/v1/ai_agent_governance.py`

### Tests
- Unit: envelope invariants — cannot go `Active` without ≥1 `AuthorizedAction` and `EnvelopeApprovedBy`; `RequiresHumanApprovalFor` removal requires `ai_posture:admin`
- Unit: envelope versioning — deviation evaluation pins the version active at action timestamp, verified with a fixture where the envelope was revised between two reported actions
- Unit: `RequiredApprovalBypassed` deviations always assigned `Severity ≥ High`
- Unit: `ReviewState = EnvelopeUpdated` requires linked `AgentOperationalEnvelopeRevised` event
- Integration: full flow — draft envelope → approve → report compliant action (no deviation) → report violating action (deviation raised) → review → confirm → advisory service surfaces revision recommendation after repeated confirmed-benign deviations of the same type

### Migrations (conceptual)
- New tables: `agent_operational_envelopes` (versioned rows, no hard delete on revision), `agent_deviation_events` (partitioned monthly by `(tenant_id, detected_at)`)

### Validation Steps
- Verify an action reported against a superseded envelope version is evaluated against the version active at its timestamp, not the current version
- Verify `Suspended` envelope state is reflected in `AISystemAsset` risk score component via ACL (coordinate with Phase 2's `AIRiskScoringService` — requires Phase 2 complete)

### Exit Criteria
- [ ] Envelope versioning correctness verified under revision-during-evaluation scenario
- [ ] Deviation severity assignment rules covered by tests
- [ ] `ai_posture:approver`+ gating on envelope suspension enforced

---

## Phase 5 — Compliance Mapping, Security Graph, and Read Models

### Objectives
Implement `AIComplianceMapping`, wire all Security Graph ontology extensions, and deliver all M31 read models.

### Scope
**Domain Services:** `AIComplianceMappingService`
**Repositories:** `IAIComplianceMappingRepository`
**ACL:** `IComplianceQueryPort` (M24)
**Security Graph:** All new nodes/edges from Architecture Freeze §13
**Read Models:** AI Asset Inventory Dashboard, AI Risk Register, Shadow AI Discovery Report, AI Compliance Posture, AI Supply Chain Integrity Report, AI Agent Deviation Report

### Expected Files
- `aivar-redforge/backend/src/redforge/domain/ai_posture/compliance_mapping.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/compliance_mapping_service.py`
- `aivar-redforge/backend/src/redforge/infrastructure/ai_posture/acl/compliance_acl.py`
- `aivar-redforge/backend/src/redforge/application/platform/projections/ai_posture_projection.py` — Security Graph node/edge writers
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/ai_asset_inventory_dashboard.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/ai_risk_register.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/shadow_ai_discovery_report.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/ai_compliance_posture.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/ai_supply_chain_integrity_report.py`
- `aivar-redforge/backend/src/redforge/application/ai_posture/read_models/ai_agent_deviation_report.py`

### Tests
- Unit: `ComplianceControlStatus` evaluation logic for each status value given fixture evidence combinations
- Unit: `AIComplianceGapIdentified` raised correctly for `Gap` status
- Integration: full mapping flow against M24 mock for at least EU AI Act and NIST AI RMF
- Integration: Security Graph writes for all new node/edge types; idempotent under event replay (matching M30's established pattern)
- Integration: each read model rebuilds correctly from event replay
- Integration (end-to-end): CISO-persona flow — onboard a tenant, run discovery scan, verify AI asset inventory dashboard reflects full estate within test-equivalent of "one day" (i.e., single scan cycle), per roadmap success criterion

### Migrations (conceptual)
- New table: `ai_compliance_mappings`, indexed on `(tenant_id, ai_system_asset_id, framework_ref)`
- Projection/read-model tables per read model, following the existing `platform/projections` pattern

### Validation Steps
- Produce a compliance attestation report for at least one framework (EU AI Act or NIST AI RMF) end-to-end from fixture data, satisfying the roadmap's success criterion
- Verify Shadow AI Discovery Report surfaces at least one previously-unknown AI deployment from a fixture scan scenario, satisfying the roadmap's success criterion
- Verify all six read models are reachable via API and render correctly against seeded fixture data

### Exit Criteria
- [ ] All Security Graph nodes/edges implemented and idempotent under replay
- [ ] All six read models implemented and registered in the projection registry
- [ ] At least one compliance framework produces an end-to-end attestation report
- [ ] Full milestone success criteria (Architecture Freeze roadmap §23) demonstrably met against fixture/integration data

---

## Milestone Completion Criteria

- [ ] All five phases passed quality gates and exit criteria
- [ ] `AISystemAsset` never duplicates M22 `AIAsset` identity data — verified by code review checklist, not just tests
- [ ] End-to-end: cloud account onboarded → discovery scan → assets registered/shadow AI flagged → threat profile assessed → risk score computed → compliance mapping produced
- [ ] Model provenance checksum verification demonstrated against at least one real or realistic fixture artifact with a deliberately introduced mismatch
- [ ] Agent envelope deviation detection demonstrated with a version-pinned evaluation scenario
- [ ] Security graph AI-SPM ontology populated and queryable
- [ ] No P0 architecture debts open at milestone close
