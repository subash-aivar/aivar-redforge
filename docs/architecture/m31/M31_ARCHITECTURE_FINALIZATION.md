# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Architecture Finalization Record

**Status:** FROZEN — IMPLEMENTATION READY
**Milestone:** M31
**Date:** 2026-07-21
**Preceded By:**
- `M31_ARCHITECTURE_FREEZE.md` — frozen domain model
- `M31_ADR.md` — ADR-M31-001 through ADR-M31-008
- `M31_HARDENING_REVIEW.md` — APPROVED WITH CONDITIONS
- `M31_ARCHITECTURE_REVIEW.md` — APPROVED FOR IMPLEMENTATION

**Purpose:** Resolve all seven outstanding observations from the Architecture Review. All decisions herein are final and supersede any ambiguity in the source documents. This record requires no further approval — it closes all open items identified before implementation begins.

**Constraint:** This document contains no code, no API definitions, no repository implementations, no schema declarations, and no implementation artifacts. It is a finalization-only architecture document.

---

## Contents

1. Decision 1 — AIThreatProfile Aggregate Position
2. Decision 2 — Module Path Convention
3. Decision 3 — Role Naming Convention
4. Decision 4 — Shadow AI Triage Phase Assignment
5. Decision 5 — Model Provenance Verification Policy
6. Decision 6 — Kubernetes Admission Integration Model
7. Decision 7 — Hardening Items Disposition
8. ADR Updates Required (ADR-M31-009 through ADR-M31-012)
9. Architecture Corrections to Source Documents
10. Implementation Impact Summary
11. Updated Phase Plan
12. Final Frozen Decisions Register

---

## 1. Decision 1 — AIThreatProfile Aggregate Position

### The Ambiguity

`M31_ARCHITECTURE_FREEZE.md §8.2` contains a dual positioning of `AIThreatProfile`:

**Position A (Nested Entity):**
The `AISystemAsset` aggregate's entity list includes "AIThreatProfile — the threat surface assessment for this system." This framing implies `AIThreatProfile` is an entity child of `AISystemAsset`, loaded with the asset aggregate, mutated via `AISystemAsset` command handlers, and persisted by `IAISystemAssetRepository`.

**Position B (Independent Aggregate Root):**
The same section §8.2 immediately follows with an "AIThreatProfile Aggregate Root" header. It declares:
- Its own identity: `AIThreatProfileId` — one per `AISystemAsset`
- Its own value objects and assessment entities
- Its own aggregate invariants
- Its own domain events: `AIThreatProfileCreated`, `ThreatCategoryAssessed`, `ExposureLevelChanged`, `ThreatProfileFlaggedStale`

Additionally, `§11 Repository Interfaces` declares `IAIThreatProfileRepository` with methods including `find_stale(threshold_days: int, tenant: TenantId) → List[AIThreatProfile]` — a cross-asset query that cannot be expressed through `IAISystemAssetRepository` without loading every asset into memory.

These two positions are mutually exclusive and must be resolved before Phase 2 begins.

---

### Final Decision: Option B — Independent Aggregate Root

**`AIThreatProfile` is an independent aggregate root with its own repository.**

`AISystemAsset` holds an `AIThreatProfileRef` value object (containing `AIThreatProfileId`) as a reference, not as an embedded entity or child.

---

### Rationale

**Evidence from the domain model itself:**

| Signal | Interpretation |
|---|---|
| `IAIThreatProfileRepository.find_stale(threshold_days, tenant)` | Cross-asset query; impossible to express without loading every `AISystemAsset`. Requires its own repository with its own indexed table. |
| `AIThreatProfileId` as declared identity | Aggregates have stable identities because they are independently addressable and independently lifecycle-managed. A nested entity does not need a repository-facing identity. |
| Four distinct domain events on `AIThreatProfile` | Domain events are owned by the aggregate root that produces them. These events have nothing to do with `AISystemAsset`'s lifecycle. A nested entity publishes events through its parent aggregate root — but the parent aggregate root's events (`AISystemAssetDiscovered`, `AISystemAssetRegistered`, etc.) are completely disjoint from `AIThreatProfile`'s events. Two separate clusters of events = two separate aggregates. |
| Staleness domain logic lives entirely within `AIThreatProfile` | The `RequiresReassessment` flag, the `LastAssessedAt` field, and the staleness threshold are internal to threat profile — `AISystemAsset` has no meaningful opinion about them. Pushing staleness domain logic into a parent aggregate violates the aggregate's cohesion principle. |
| `AIThreatAssessmentService` operates on `AIThreatProfile` independently | The domain service creates and updates threat profiles, runs in async assessment jobs, and queries profiles by staleness — all without touching `AISystemAsset` lifecycle state. If `AIThreatProfile` were a nested entity, `AIThreatAssessmentService` would need to load the full `AISystemAsset` aggregate for every profile update, creating unnecessary loading overhead and coupling. |

**Platform precedent:**

The identical pattern appears in M30:
- `CampaignEvaluation` is a separate aggregate root from `CampaignInstance`, even though each campaign instance has exactly one evaluation
- `TaskGraphExecution` is a separate aggregate root from `CampaignInstance`
- In both cases, the parent aggregate holds a reference ID value object, not an embedded entity

`AIThreatProfile` follows the same structural reasoning: one-to-one cardinality does not imply nesting. Independent lifecycle, independent query patterns, and independent domain events are the governing criteria — not cardinality.

---

### Ownership Corrections

#### Repository Ownership

| Repository | Owns | Does Not Own |
|---|---|---|
| `IAISystemAssetRepository` | `AISystemAsset` aggregate state | `AIThreatProfile` data |
| `IAIThreatProfileRepository` | `AIThreatProfile` aggregate state | `AISystemAsset` data |

`IAISystemAssetRepository` is never used to save or load `AIThreatProfile`. Queries for threat profile data go through `IAIThreatProfileRepository.find_by_asset(asset_id)`.

#### Domain Event Ownership

Events produced by `AIThreatProfile` aggregate:
- `AIThreatProfileCreated`
- `ThreatCategoryAssessed`
- `ExposureLevelChanged`
- `ThreatProfileFlaggedStale`

The event `AIThreatProfileUpdated` listed in `AISystemAsset`'s domain event list (§8.2) is **reclassified** as follows:
- It is removed from `AISystemAsset`'s event list
- `AIThreatProfile` publishes `ExposureLevelChanged` or `ThreatCategoryAssessed` as appropriate when its content changes
- `AISystemAsset` does **not** publish a notification on threat profile content changes — consumers who need threat profile data subscribe to `AIThreatProfile` events directly or query `IAIThreatProfileRepository`
- `AIRiskScoringService` subscribes to `ExposureLevelChanged` as the trigger for event-driven risk score recomputation (not to a now-deleted `AIThreatProfileUpdated` on the asset)

#### Lifecycle Ownership

| Lifecycle Concern | Owner |
|---|---|
| When a threat profile is created | `AIThreatProfile` aggregate (on `AIThreatProfileCreated` event); created by `AIThreatAssessmentService` after `AISystemAsset` reaches `UnderReview` or `Registered` state |
| When a threat profile is flagged stale | `AIThreatProfile` aggregate (on `ThreatProfileFlaggedStale` event); `staleness_sweep` background job |
| When a threat profile is retired | `AIThreatProfile` aggregate; triggered when `AISystemAsset` reaches `Decommissioned` terminal state via domain event subscription |
| Sealing of threat profile on asset decommission | `AIThreatProfile` aggregate subscribes to `AISystemAssetDecommissioned` event; on receipt, transitions to a sealed `Archived` state (no further assessment mutations permitted) |

#### ACL Ownership

Within `ai_posture`, when `AIRiskScoringService` requires threat profile data:
- It calls `IAIThreatProfileRepository.find_by_asset(asset_id)` — same bounded context, no ACL required
- The result is `AIThreatProfile` — an `ai_posture` aggregate, not a foreign type

When anything outside `ai_posture` needs threat profile data (e.g., a Security Graph projection, or a read model):
- They receive `ExposureLevelChanged` events from the event bus
- They do not call into `ai_posture`'s domain layer directly — they consume events and maintain their own read-model state

#### Value Object Correction in AISystemAsset

`AISystemAsset` aggregate's value object list is updated:

**Remove:** `AIThreatProfile` from the entity list

**Add:** `AIThreatProfileRef` as a value object — a typed wrapper around `AIThreatProfileId`, nullable until `AIThreatAssessmentService` creates the profile (it is null in the `Discovered` → `PendingClassification` window, non-null from `UnderReview` onward)

---

## 2. Decision 2 — Module Path Convention

### The Ambiguity

`M31_IMPLEMENTATION_PLAN.md §3` specifies file paths such as:
```
aivar-redforge/backend/src/redforge/domain/ai_posture/aggregates/ai_system_asset.py
aivar-redforge/backend/src/redforge/infrastructure/ai_posture/repositories/...
```

This places M31 under the `redforge` monolith module (`backend/src/redforge/`), which is the pre-M28 architecture.

M28, M29, M30, and all their bounded contexts follow a different pattern:
```
backend/src/campaign/domain/aggregates/...
backend/src/taskgraph/domain/services/...
backend/src/evaluation/infrastructure/repositories/...
backend/src/scenario/application/services/...
backend/src/campaignexecution/domain/ports/...
```

These are top-level bounded context modules directly under `backend/src/`, outside the `redforge/` module.

---

### Final Decision: Top-Level Context Modules

**M31 follows the M28–M30 top-level module convention.**

The three bounded contexts are placed at:
```
backend/src/ai_posture/
backend/src/ai_supply_chain/
backend/src/ai_agent_governance/
```

Each follows the established internal layout:
```
backend/src/{context}/
  domain/
    aggregates/
    value_objects/
    services/
    events/
    ports/
  application/
    services/
    commands/
    queries/
  infrastructure/
    repositories/
    acl/
    adapters/
    container.py
  tests/ (or backend/tests/{context}/)
```

---

### Rationale

| Factor | `backend/src/redforge/domain/ai_posture/` | `backend/src/ai_posture/` |
|---|---|---|
| **DDD compliance** | Bounded contexts co-mingled under a monolith module prefix | Each bounded context is a clearly demarcated module; no implicit coupling through shared parent namespace |
| **M28–M30 consistency** | Diverges from all recent milestones | Consistent with `campaign/`, `taskgraph/`, `evaluation/`, `scenario/`, `campaignexecution/` |
| **Dependency enforcement** | Python import paths cross through `redforge.*` namespace; harder to enforce isolation | Violations of context isolation are immediately visible as cross-module imports |
| **Future scalability** | Monolith path complicates extraction of a bounded context to a separate service | Top-level modules are extraction-ready; a context can be moved to a separate service with a predictable import change |
| **Test path symmetry** | Would require `backend/tests/redforge/domain/ai_posture/...` — inconsistent with `backend/tests/campaign/...` | `backend/tests/ai_posture/`, `backend/tests/ai_supply_chain/`, `backend/tests/ai_agent_governance/` — consistent |
| **git blame and searchability** | Context-specific code mixed in a deep path tree | `grep -r "ai_posture" backend/src/ai_posture/` — unambiguous |

**The `backend/src/redforge/` path for M31 was an error in the Implementation Plan, not an intentional design decision.** The Implementation Plan file paths are corrected in §9 (Architecture Corrections) below.

---

### Path Convention Rule (Permanent)

All bounded contexts from M28 onward use the top-level module pattern: `backend/src/{context_name}/`. No bounded context code belongs under `backend/src/redforge/domain/`. The `backend/src/redforge/` module is reserved for platform-level shared infrastructure (event store, projection engine, DLQ, health engine) that is not domain-specific.

---

## 3. Decision 3 — Role Naming Convention

### The Ambiguity

`M31_ARCHITECTURE_FREEZE.md §14 Authorization Model` defines six roles including `mlsecops:engineer`, while all other roles follow the `ai_posture:<role>` convention. The inconsistency:

```
ai_posture:reader      ← ai_posture prefix
ai_posture:analyst     ← ai_posture prefix
mlsecops:engineer      ← mlsecops prefix  ← INCONSISTENT
ai_posture:approver    ← ai_posture prefix
ai_posture:admin       ← ai_posture prefix
ai_posture:auditor     ← ai_posture prefix
```

---

### Final Decision: `ai_posture:engineer` — Canonical RBAC Role Name

**The permanent, canonical RBAC role name is `ai_posture:engineer`.**

`mlsecops:engineer` is permitted as a product-layer display alias only — in UI labels, onboarding documentation, and user-facing descriptions where the "MLSecOps Engineer" persona name is meaningful to the user. It must not appear in:
- RBAC permission evaluation
- Authorization policy definitions
- Audit log attribution
- API responses containing role claims
- Database role records
- Domain model code

---

### Rationale

**Platform naming convention:** The platform uses `<context>:<function>` as its RBAC naming convention throughout all implemented milestones:
- `campaign:engineer`, `campaign:approver`, `campaign:admin`, `campaign:auditor`
- `engagement:approver`, `engagement:auditor`
- `redteam:operator`, `redteam:approver`

`mlsecops` is a **team/persona name**, not a bounded context name. The bounded context is `ai_posture`. Mixing persona names with context names in the RBAC namespace creates:
1. Audit log ambiguity — `mlsecops:engineer` in an audit record does not self-evidently indicate which system capability was used
2. Role management confusion — operators who manage `ai_posture:*` roles in their IDP need to also remember a separate `mlsecops:engineer` entry
3. Future extension problems — if M32 or M35 requires a role for the same persona class in a different context, the `mlsecops:` prefix becomes either overloaded or abandoned

**Consistency is a security property.** Role names that follow a predictable pattern are harder to forge or mistake in policy configurations.

---

### Complete Canonical Role Set

| Canonical RBAC Role | Product Display Alias (UI Only) | Permissions |
|---|---|---|
| `ai_posture:reader` | AI Posture Viewer | Read AI system assets, threat profiles, risk scores, compliance mappings, shadow AI alerts (read-only, no triage) |
| `ai_posture:analyst` | AI Security Analyst | All reader + triage shadow AI alerts, annotate threat assessments, review compliance gaps |
| `ai_posture:engineer` | MLSecOps Engineer | All analyst + register/classify AI system assets, author threat assessments, author Model Bill of Materials, define agent operational envelope drafts, trigger on-demand provenance verification |
| `ai_posture:approver` | AI Security Approver | All engineer + approve AI system asset registration, approve agent operational envelopes, confirm shadow AI resolution, suspend agent envelopes |
| `ai_posture:admin` | AI Posture Administrator | All approver + manage discovery source configuration, manage risk scoring weights/versions, remove `RequiresHumanApprovalFor` categories from an envelope (requires explicit approval action), decommission AI system assets |
| `ai_posture:auditor` | AI Posture Auditor | Read-only full audit trail: provenance chain history, compliance mapping history, deviation event history, risk score history, envelope revision history |

---

### Correction to Authorization Model (§14 of Freeze Document)

The freeze document's §14 table row for `mlsecops:engineer` is corrected to `ai_posture:engineer`. This is a naming correction only — the permissions definition is unchanged.

---

## 4. Decision 4 — Shadow AI Triage Phase Assignment

### The Ambiguity

`M31_HARDENING_REVIEW.md §9` identifies the triage bottleneck risk and states bulk triage capability should be scoped into "Phase 5 or Phase 1 if first-scan volume concerns are significant." `M31_IMPLEMENTATION_PLAN.md` does not explicitly assign bulk triage to a specific phase, leaving it ambiguous.

The Architecture Review recommended moving both individual and bulk triage to Phase 1.

---

### Final Decision: Phase 1 — Both Individual and Bulk Triage

**Individual and bulk `ShadowAIAlert` triage are Phase 1 scope, not deferred.**

---

### Rationale

**Functional completeness argument:** `ShadowAIAlert` is Phase 1's primary deliverable aggregate (alongside `AISystemAsset`). An aggregate whose only operational affordance — triage — is deferred to a later phase produces a database that fills with unactionable records. Phase 1 cannot be called complete if operators cannot act on the records it produces.

**Discovery precedes alert, but registration precedes discovery:** Discovery scans (Phase 3) are the main source of high-volume shadow AI alerts. However, `ManualRegistration` (a valid `AIAssetDiscoverySource`) is in scope from Phase 1 — operators manually registering existing AI services will encounter the `ShadowAI` status pathway and need triage capability immediately.

**Dependency analysis:** Bulk triage has no dependency on Phase 2 (threat profiling), Phase 3 (discovery coordinator), or Phase 4 (agent governance). It depends only on `ShadowAIAlert` aggregate and the role model — both Phase 1.

**Operational reality at first deployment:** Enterprise deployments of AI-SPM begin with a known gap: hundreds of AI services already running without registration. The first operator action after deploying M31 is frequently a bulk registration sweep of known services. Deferring bulk triage means the product is unusable on first deployment against a realistic estate.

**Hardening Review language clarification:** The conditional "Phase 5 or Phase 1 if first-scan volume concerns are significant" was written before the Implementation Plan's phase structure was fully assessed. Given that M31's target market is large enterprises (where significant first-scan volume is the expected case, not an edge case), the condition resolves to Phase 1.

---

### Phase 1 Triage Scope

| Triage Capability | Scope | Role Required |
|---|---|---|
| Individual alert triage (single alert `Open → UnderTriage`) | Phase 1 | `ai_posture:analyst` |
| Individual alert resolution (confirm shadow AI, confirm false positive, resolve) | Phase 1 | `ai_posture:analyst` |
| Bulk triage by pattern (source + account + service type pattern, `Open → UnderTriage` batch) | Phase 1 | `ai_posture:analyst` |
| Bulk resolution (confirm all bulk-triaged as shadow AI or false positive, batch) | Phase 1 | `ai_posture:approver` |
| "Discovery-only mode" initial sweep (report without alert records) | Phase 1 configuration option | `ai_posture:admin` |
| Triage backlog age metric (`shadow_ai_triage_backlog_age_days` gauge) | Phase 1 observability | — |

**Invariant unchanged:** No bulk triage path bypasses the human triage gate. Bulk triage moves N alerts from `Open` to `UnderTriage` (requires `ai_posture:analyst`). Bulk confirmation from `UnderTriage` to a terminal state (requires `ai_posture:approver`) is a separate action. The two-step structure is preserved in batch form.

---

## 5. Decision 5 — Model Provenance Verification Policy

### The Ambiguity

`M31_HARDENING_REVIEW.md §12.3 (Open Question 3)` identifies that for foundation models with hundreds-of-gigabytes weight files, streaming checksum computation may incur significant time and egress cost. Three options were identified:
- (a) Provider-attested signatures only (`SignatureChainRef`-based)
- (b) Partial artifact sampling (rejected by the Hardening Review parenthetical: "note: partial hashing is not a standard integrity guarantee")
- (c) Accept full retrieval cost

The open question requires a permanent policy decision before Phase 3 begins.

---

### Final Decision: Size-Threshold Verification Policy

**Option (b) is rejected — partial hashing is not a valid integrity guarantee and will not be implemented.**

**The permanent policy is a configurable size threshold separating two verification tiers:**

---

### Tier 1: Independent Hash Verification

**Applies to:** Model artifacts ≤ configured size threshold (default: **10 GB**)

**Method:** Full artifact retrieved and independently hashed. `ProvenanceIntegrityStatus = Verified` requires `current_checksum` computed from the full artifact bytes using `ChecksumAlgorithm ∈ {SHA256, SHA512}`.

**`VerificationMethod` value:** `IndependentHash`

**Characteristics:**
- RedForge computes the hash independently, not trusting any provider-reported value
- Streaming computation (never fully loaded into memory)
- Egress costs are incurred and accepted for this tier
- Provides the strongest integrity guarantee available

---

### Tier 2: Provider Attestation Verification

**Applies to:** Model artifacts > configured size threshold (default: **10 GB**)

**Method:** Verification relies on the provider's published cryptographic artifact signature. RedForge verifies the provider's signature against the provider's public signing key (not against an independently computed hash). `SignatureChainRef` records the provider's signing certificate chain and the specific signature artifact location (e.g., Hugging Face `.sha256` sidecar file, HuggingFace Hub model card `sha256` field, cloud provider model registry checksum attestation).

**`VerificationMethod` value:** `ProviderAttestation`

**Critical distinction:** `ProvenanceIntegrityStatus = Verified` under Tier 2 is a **trust-delegated** claim. The verification record must carry an explicit `trust_delegation_note` field in the `ProvenanceChainEntry` recording: "Verification is trust-delegated to [provider name]. Independent hash not computed due to size threshold ([size] GB exceeds [threshold] GB). Provider signature verified against [signing key fingerprint]."

**Consumers of `ProvenanceIntegrityStatus = Verified`** must be able to distinguish Tier 1 from Tier 2 verification. `VerificationMethod` is exposed on all read model outputs and API responses that include provenance status.

---

### Policy Governance

| Attribute | Value |
|---|---|
| Default size threshold | 10 GB |
| Threshold configurability | Per-tenant, configurable by `ai_posture:admin` |
| Threshold minimum | 1 GB (floor; threshold below 1 GB is rejected as operationally unreasonable) |
| `VerificationMethod` field location | `ProvenanceChainEntry` (every status change records the method used) |
| AI Compliance Report labeling | All Tier 2 verifications are labeled "Provider-Attested" in compliance reports — never presented as equivalent to independent hash verification |
| Security Graph edge property | `ModelProvenanceNode` carries `verification_method` as a node property |

---

### Failure Handling Policy

| Failure Type | `ProvenanceIntegrityStatus` | Action |
|---|---|---|
| Artifact retrieval error (timeout, 503, network failure) | `VerificationFailed` | Scheduled retry with exponential backoff |
| Checksum computation fails (disk full, OOM) | `VerificationFailed` | Operational alert; retry after resource recovery |
| Checksum computed, does NOT match `LastVerifiedChecksum` | `Mismatched` | Security alert immediately; no retry suppresses this |
| Provider signature invalid or revoked | `Mismatched` | Security alert immediately; treated as Tier 1 `Mismatched` |
| Provider signature endpoint unreachable (Tier 2) | `VerificationFailed` | Scheduled retry — unreachability ≠ tampering |
| Three (3) consecutive `VerificationFailed` for same model | `VerificationFailed` (maintained) | Operational alert distinct from security alert; human investigation triggered |
| N > 3 consecutive `VerificationFailed` without resolution | `VerificationFailed` (permanent until manual reset) | `ai_posture:engineer` must manually investigate and reset; no automatic recovery beyond 3 retries |

**The critical invariant from Hardening Review §1 is preserved:** `VerificationFailed` → retry → `Verified` path goes through the **identical** full verification computation as first-time verification. There is no shortcut recovery path that restores `Verified` without recomputing and comparing the actual hash or re-verifying the provider signature.

---

### Egress Cost Management

- Tier 1 verifications are scheduled off-peak by default (configurable per tenant)
- Tier 1 verification jobs are rate-limited per provider (same `per-cloud-account-per-provider` rate limiting as discovery scans per Hardening Review §5)
- Per-tenant monthly egress budget for provenance verification is configurable; once exhausted, pending verifications are queued and `ai_posture:admin` is alerted — verification is not silently skipped
- A paused-due-to-budget state is distinct from `VerificationFailed`: it uses a `VerificationPaused` operational status separate from `ProvenanceIntegrityStatus` (which reflects the last actual verification result, not the scheduling state)

---

## 6. Decision 6 — Kubernetes Admission Integration Model

### The Ambiguity

`M31_HARDENING_REVIEW.md §12.4 (Open Question 4)` identifies two integration models for `IKubernetesAdmissionQueryPort`:

**Option A:** Read access to Kubernetes admission controller logs or audit records from the cloud provider's managed K8s audit log stream (EKS CloudWatch Logs, GKE audit logs, AKS diagnostic logs). RedForge reads from cloud-side log APIs — no deployment into customer clusters.

**Option B:** Deploying a RedForge admission webhook into the customer's Kubernetes cluster. The webhook is invoked by the K8s API server on every pod admission event; RedForge captures AI workload indicators at admission time. Requires cluster-admin privileges to register.

---

### Final Decision: Option A — Read-Only Audit Log Access for M31

**For M31, `IKubernetesAdmissionQueryPort` is implemented as read-only access to cloud provider Kubernetes audit logs. No RedForge admission webhook is deployed into customer clusters.**

**Option B (admission webhook) is deferred as a post-M31 enhancement**, available if customers with specific real-time admission detection requirements request it.

---

### Rationale

**Security posture of Option B:**

Deploying an admission webhook into a customer cluster requires:
- `ClusterRoleBinding` to a `ClusterRole` with `admissionregistration.k8s.io/webhookconfigurations` create/update permissions
- Webhook endpoint that is in the cluster's API server critical path (admission webhooks are called synchronously; failures can block pod scheduling)
- TLS certificate management for the webhook endpoint
- Availability SLA that matches the cluster's own availability requirements

This is a significant operational trust grant that has customer-by-customer negotiation requirements and requires a RedForge-provided K8s operator or Helm chart. It is out of scope for M31 and premature for a posture management milestone that emphasizes read-side discovery over write-side infrastructure deployment.

**Security posture of Option A:**

Cloud provider K8s audit logs are already produced by EKS, GKE, and AKS for compliance reasons. Accessing them requires:
- EKS: CloudWatch Logs read access to the `/aws/eks/{cluster}/cluster` log group (`kube-apiserver-audit` logs)
- GKE: Cloud Audit Logs API read access (`cloudaudit.googleapis.com/activity` entries for K8s admission events)
- AKS: Azure Monitor Logs read access (AKS `kube-audit` diagnostic logs)

These are read-only, non-critical-path access grants. They can be provisioned through the same M26 cloud account credential model used for other discovery sources. Failure does not affect cluster operation.

**Discovery adequacy:** The AI workload indicators captured from admission records (pod image tags, resource requests indicating GPU/accelerator use, known AI framework labels) are sufficient for M31's shadow AI discovery use case. M31's goal is posture discovery and inventory, not real-time behavioral interception — Option A provides sufficient signal for this goal.

**Port interface stability:** `IKubernetesAdmissionQueryPort` is implemented as a cloud-audit-log adapter for M31. If Option B is added post-M31, the same port interface is satisfied by a new adapter implementation — no domain model changes required.

---

### IKubernetesAdmissionQueryPort Implementation Scope for M31

| Provider | Data Source | Access Method |
|---|---|---|
| EKS (AWS) | CloudWatch Logs, `/aws/eks/{cluster}/cluster` audit log group | CloudWatch Logs API (read-only), via M26 credential vault |
| GKE (Google Cloud) | Cloud Audit Logs API | Cloud Audit Logs API (read-only), via M26 credential vault |
| AKS (Azure) | Azure Monitor Logs, AKS diagnostic settings | Azure Monitor Query API (read-only), via M26 credential vault |
| On-premise / self-managed K8s | Not in scope for M31 | Post-M31: requires direct cluster API access model; deferred |

**Phase 3 pre-condition update (supersedes Architecture Review I08):**
Before Phase 3 begins, the cloud audit log access models for each supported provider must be verified as accessible through M26's credential vault. The verification covers read-only IAM policy requirements, not webhook deployment.

---

### Post-M31 Admission Webhook Path

If Option B (admission webhook) is pursued post-M31, it will be delivered as a separately versioned K8s operator with its own security review, customer trust model documentation, and compatibility matrix. It will implement the same `IKubernetesAdmissionQueryPort` interface but with a different adapter. No M31 domain model changes will be required.

---

## 7. Decision 7 — Hardening Items Disposition

Each hardening finding from `M31_HARDENING_REVIEW.md` is reviewed and given a final disposition: **Accept**, **Reject**, or **Defer**. All accepted items are mandatory for the phase in which they are assigned.

---

### §1 — Provenance Verification Failure Must Not Mask Tampering (CRITICAL)

**Disposition: ACCEPT — All four required hardenings, Phase 3**

| Hardening Requirement | Decision |
|---|---|
| `Verified` requires explicit `ChecksumVerified` event with `current_checksum` recorded — no silent status promotion | ACCEPT. Implementation violation: setting status without the event is a code review blocker. |
| `VerificationFailed → Verified` path must go through full recomputation — no shortcut recovery | ACCEPT. Explicitly documented in Decision 5 Failure Handling Policy above. |
| All `ProvenanceIntegrityStatus` transitions backed by append-only `ProvenanceChainEntry` — no silent column update | ACCEPT. Database-level enforcement (§7 below). |
| Automated tests for: (a) `Verified→Failed→retry→Verified` (legitimate) and (b) `Verified→Failed→retry→Mismatched` (tampered) | ACCEPT. Both scenarios are mandatory Phase 3 integration tests, not edge-case tests. |

**Justification for full acceptance:** Supply chain tampering is a high-impact, hard-to-detect attack class. A single implementation shortcut (auto-restoring `Verified` on retry) would make the integrity claim meaningless. No part of this hardening is negotiable.

---

### §2 — Shadow AI Discovery Completeness Is Bounded, Not Absolute (HIGH)

**Disposition: ACCEPT — All four required hardenings, split Phase 1 and Phase 5**

| Hardening Requirement | Phase | Decision |
|---|---|---|
| AI Asset Inventory Dashboard must display: last-scan timestamp, configured discovery sources, "coverage scope" indicator | Phase 5 (Read Models) | ACCEPT |
| Shadow AI Discovery Report must include "scope of this report" section with sources + last-successful-scan timestamps | Phase 5 (Read Models) | ACCEPT |
| `AIDiscoveryScan` partial results must be visibly flagged in reports with list of failed partitions | Phase 5 (Read Models) | ACCEPT |
| Operator onboarding documentation must state coverage scope limitations | Documentation (any phase) | ACCEPT — included in platform documentation deliverables |

**Justification:** The batch discovery model's coverage limitation is an honest operational constraint. Hiding it would produce false assurance. All four items are accepted as non-optional.

---

### §3 — AI Risk Score Staleness Must Not Produce Silent False Confidence (HIGH)

**Disposition: ACCEPT — All four required hardenings, Phase 2**

| Hardening Requirement | Decision |
|---|---|
| Every API response returning a risk score must include `computed_at` and `is_stale` | ACCEPT. Missing these fields in any risk score API response is a code review blocker. |
| `AIRiskScoreStalenessExceeded` event must be published when `StalenessBound` is exceeded | ACCEPT. This event feeds the Observability staleness gauge. |
| Event-driven recomputation on `ProvenanceIntegrityMismatchDetected` uses guaranteed-delivery outbox pattern | ACCEPT. Fire-and-forget is prohibited for this path. |
| Stale score alerts suppressed during known scoring service outage and re-evaluated on recovery | ACCEPT. Prevents alert storm; uses the same operational-outage suppression pattern as M26 and M28. |

**Justification:** The cache-first model is architecturally sound. These hardenings ensure it is operationally honest — consumers always know what they are receiving.

---

### §4 — Agent Operational Envelope Revision Must Not Be an Evasion Path (HIGH)

**Disposition: ACCEPT — All four required hardenings, Phase 4**

| Hardening Requirement | Decision |
|---|---|
| `ConfirmedBenign` requires non-nullable `ReviewNotes` | ACCEPT. Enforced at domain aggregate level, not only API validation. Null `ReviewNotes` on `ConfirmedBenign` is a domain invariant violation. |
| `ReviewState = EnvelopeUpdated` requires linked `AgentOperationalEnvelopeRevised` event | ACCEPT. Link must be verified at the time of review state transition — cannot be added retroactively. |
| `RequiresHumanApprovalFor` categories removable only by `ai_posture:admin`, not `ai_posture:engineer` | ACCEPT. Role separation is enforced at application service boundary, not only API gateway. |
| Audit read model must show full `RequiresHumanApprovalFor` change history | ACCEPT. Phase 5 audit read model scope. |

**Justification:** Governance theater — where the envelope documentation trails observed behavior rather than constraining it — is the primary operational risk of the agent governance context. All four hardenings directly address this risk.

---

### §5 — Discovery Scan Rate Limiting and Cloud API Cost Management (HIGH)

**Disposition: ACCEPT — All four required hardenings, Phase 3**

| Hardening Requirement | Decision |
|---|---|
| Per-cloud-account, per-provider request rate limits configurable; deferred partitions enqueued, not dropped | ACCEPT. "Not dropped" is the critical semantic — deferred partitions appear in `partial: true` scan records with explicit retry scheduling. |
| Per-scan-run API call budget caps configurable; budget exhaustion marks run `partial: true` | ACCEPT. Budget tracking is mandatory infrastructure for `AIDiscoveryScanCoordinator`. |
| Bounded-concurrency fan-out for large tenant account enumeration (default 5 concurrent, configurable) | ACCEPT. Default of 5 is conservative and appropriate for initial deployments; configurable upward by `ai_posture:admin`. |
| 429/503 provider responses retried with exponential backoff with jitter; unretried failures recorded | ACCEPT. Unretried failures are partition failures, not silently swallowed. |

**Justification:** Cost and throttle management failures in a large enterprise environment can generate significant unexpected spend and degrade partner relationships with cloud providers. All four items are accepted as mandatory.

---

### §6 — ACL Boundary Enforcement: M22 Types Must Never Appear in AI-SPM Domain (MEDIUM)

**Disposition: ACCEPT — Permanent architectural rule**

| Hardening Requirement | Decision |
|---|---|
| Only `infrastructure/{context}/acl/` files may import from foreign domain layers | ACCEPT. This is the existing platform-wide ACL discipline; M31 follows it without exception. |
| Code review checklist: "Does any domain or application layer file import from `redforge.domain.inventory`?" | ACCEPT. Added to all three bounded context code review checklists. |
| Same constraint for M26, M27, M28 foreign types in their respective ACL files | ACCEPT. No cross-exception. |

**Justification:** This is the foundational DDD anti-corruption layer discipline. Accepting it without exception preserves the bounded context isolation that makes the platform's long-term evolution tractable.

---

### §7 — Provenance Chain Entry Immutability Must Be Database-Level Enforced (MEDIUM)

**Disposition: ACCEPT — Phase 3 migration requirement**

| Hardening Requirement | Decision |
|---|---|
| `provenance_chain_entries` table: database-level immutability via PostgreSQL RLS (INSERT-only for application user) or trigger | ACCEPT. **RLS approach is preferred** — it is enforced at the database connection level, not the application layer. The migration that creates `provenance_chain_entries` must include the RLS policy or trigger. |
| `ModelBillOfMaterials` component additions: same append-only database-level protection | ACCEPT. Same mechanism applied to MBOM component table. |
| Backups: `provenance_chain_entries` with explicit retention policy | ACCEPT. Documented in operations runbook; table tagged with `legally_significant_audit_trail: true` in migration comment. |

**Implementation note (non-code guidance):** The PostgreSQL RLS approach revokes `UPDATE` and `DELETE` on `provenance_chain_entries` from the application database user at the role level. The application user holds only `INSERT` and `SELECT`. Administrative operations (compliance investigations, legal hold) use a separate elevated role with explicit audit logging. This is not a migration implementation — it is an operational requirement documented here for the Phase 3 implementer.

**Justification:** Application-layer-only enforcement of immutability is insufficient for a legally significant audit trail. A bug, a migration error, or a direct database access by a developer can destroy the chain if the database permits it.

---

### §8 — Compliance Mapping Must Not Be Over-Automated (MEDIUM)

**Disposition: ACCEPT — Phase 5 scope**

| Hardening Requirement | Decision |
|---|---|
| Distinguish machine-evaluable vs. attestation-required controls per framework | ACCEPT. This distinction is carried as `requires_human_attestation: bool` per control entry in M24's compliance framework catalog. |
| `AIComplianceMapping` carries `requires_human_attestation` flag derived from M24 | ACCEPT. Flag is not authored by M31 — it is resolved via `IComplianceQueryPort` and stored on the mapping record. |
| Attestation reports label auto-evaluated vs. human-attested controls with attesting identity and date | ACCEPT. This is a Phase 5 read model requirement for the AI Compliance Posture report. |

**Phase 5 pre-condition (updated from Architecture Review I05):** Before Phase 5 begins, verify that M24's compliance framework catalog carries `requires_human_attestation` per control for EU AI Act, NIST AI RMF, and ISO 42001. If M24 does not carry this flag, M31 will maintain a local mapping table (`AIComplianceControlClassification`) that supplies this flag for each framework+control reference. The decision on which approach to use must be made before Phase 5 implementation begins, with a named owner responsible for the verification.

**Justification:** Automated satisfaction of attestation-required controls would make compliance reports legally meaningless for audit purposes. This is a correctness requirement, not a quality preference.

---

### §9 — ShadowAIAlert Triage Bottleneck Risk (MEDIUM)

**Disposition: ACCEPT — Phase assignment changed to Phase 1**

This finding is fully addressed by Decision 4 above. Bulk triage is Phase 1 scope. The "triage backlog age" metric is Phase 1 observability scope. Initial deployment "discovery-only mode" is a Phase 1 configuration option.

No additional items to resolve beyond Decision 4.

---

### §10 — Agent Action Reporting Transport Is Out of Scope but Must Be Designed For (MEDIUM)

**Disposition: ACCEPT — Phase 4 design constraints**

| Hardening Requirement | Decision |
|---|---|
| `ReportAgentAction` accepts action batches, not only single actions | ACCEPT. Service interface accepts `List[AgentActionReport]`; minimum batch size is 1 (supports single-action callers). |
| `ReportAgentAction` is idempotent by `(agent_asset_id, action_fingerprint, timestamp)` | ACCEPT. Duplicate delivery from retry-capable transports is absorbed without duplicate `AgentDeviationEvent` records. |
| `EnvelopeComplianceEvaluationService` processes actions asynchronously regardless of transport | ACCEPT. The service contract is "evaluate and record" — it does not block the transport caller. |
| Transport contract documented for agent runtime integrators before M36 | ACCEPT. The `ReportAgentAction` API schema (request/response model) is produced as a Phase 4 documentation deliverable alongside the Phase 4 implementation. |

**Justification:** M36 (AI-native autonomous operations) depends on this transport infrastructure being operational and well-understood by integrators. Deferring the contract documentation to post-M31 would produce an M36 dependency risk.

---

### §11 — Technical Debt Prevention Rules

**Disposition: ACCEPT — All 7 rules, permanent**

All seven technical debt prevention rules from Hardening Review §11 are accepted as permanent architectural rules:

| Rule | Decision |
|---|---|
| `AISystemAsset` never duplicates M22 data | ACCEPT. Any PR adding asset name, ownership, cloud account, environment, or business criticality to `AISystemAsset` is rejected. |
| Risk score never computed synchronously | ACCEPT. Any request-path handler calling `AIRiskScoringService.compute()` inline is rejected. |
| Checksum verification never reads metadata as substitute for artifact hash | ACCEPT. Confirmed by Decision 5 policy. |
| `AgentDeviationEvent` evaluation always against the envelope version active at action timestamp | ACCEPT. Testing this against current version is a mandatory failing test in Phase 4. |
| `ShadowAIAlert` never auto-transitions without human action | ACCEPT. Automated triage assistance is permitted; automated terminal-state transition is not. |
| Discovery scan never runs without a per-account rate limit | ACCEPT. `None`/unlimited is rejected at configuration validation. |
| Compliance attestation for attestation-required controls is never automated | ACCEPT. Confirmed by disposition of §8 above. |

---

### §12 — Open Questions

All four open questions are resolved by decisions above:

| Open Question | Resolution |
|---|---|
| Q1: Provider credential management | **RESOLVED.** M26 credential vault is the credential management mechanism for all M31 provider ports. M31 does not introduce a separate credential store. Pre-condition: confirmed before Phase 3. |
| Q2: MCP server discovery protocol stability | **RESOLVED.** `IMCPServerDiscoveryPort` is implemented as a thin adapter. The adapter is versioned separately from the rest of Phase 3 scope and can be patched independently as the MCP protocol evolves. No deep coupling to a specific protocol version. |
| Q3: Large model artifact retrieval for provenance | **RESOLVED.** Decision 5 (size-threshold verification policy) above. Sampling is rejected. Tier 1 (independent hash) for ≤10 GB; Tier 2 (provider attestation) for >10 GB with explicit `VerificationMethod` labeling. |
| Q4: Kubernetes admission integration | **RESOLVED.** Decision 6 above. Read-only cloud audit log access for M31. Admission webhook deferred post-M31. |

---

### §13 — Future Considerations

**Disposition: Acknowledged, no action for M31**

All three future considerations (M32 `AIRiskScore` consumption model, M36 real-time agent monitoring, regulatory evolution of EU AI Act / NIST AI RMF) are noted, not actioned. They do not require M31 architecture changes — the existing extension points (see Architecture Freeze §22) and the transport-agnostic `EnvelopeComplianceEvaluationService` interface cover them.

---

### §13 — Hardening Pre-Conditions Update

The four pre-conditions from the Hardening Review are updated with this record:

| Pre-Condition | Original Status | Resolution |
|---|---|---|
| M22 `AIAsset` `AssetRef` ACL pattern reviewed and confirmed compatible | [ ] Unverified | Must be verified by a named owner before Phase 1 begins. Decision 2 confirms the module path; this pre-condition requires live verification of M22's repository implementation. |
| Database-level immutability for `provenance_chain_entries` confirmed as implementable | [ ] Unverified | RESOLVED: PostgreSQL RLS (preferred) or trigger is confirmed implementable via the existing Alembic migration toolchain. Documented in §7 disposition above. |
| Phase 3 provider credential management model confirmed | [ ] Unverified | RESOLVED: M26 credential vault (Open Question Q1 above). Must be operationally verified before Phase 3 begins. |
| Bulk shadow AI triage scoped (Phase 1 or Phase 5) | [ ] Ambiguous | RESOLVED: Phase 1 (Decision 4 above). |

**Pre-condition 1 (M22 AssetRef compatibility) remains the only open pre-condition requiring external verification.** It must be closed with a named owner and a completion date before Phase 1 kick-off.

---

## 8. ADR Updates Required

Four new ADRs are required. The existing ADR-M31-001 through ADR-M31-008 are unchanged. New ADRs extend the record without modifying prior decisions.

---

### ADR-M31-009: AIThreatProfile as Independent Aggregate Root

**Status:** ACCEPTED
**Supersedes:** The ambiguous dual-positioning in Architecture Freeze §8.2
**Decision:** `AIThreatProfile` is an independent aggregate root with its own `AIThreatProfileId` identity and `IAIThreatProfileRepository`. `AISystemAsset` holds an `AIThreatProfileRef` value object as a reference.

**Consequences:**
- `AISystemAsset`'s entity list removes `AIThreatProfile`
- `AISystemAsset`'s domain event `AIThreatProfileUpdated` is removed; `AIThreatProfile` publishes its own events (`ExposureLevelChanged`, `ThreatCategoryAssessed`)
- `AIThreatAssessmentService` operates on `IAIThreatProfileRepository` without loading `AISystemAsset`
- `IAIRiskScoringService` subscribes to `ExposureLevelChanged` for event-driven recomputation

**Alternatives considered:** Nested entity (Option A) — rejected because the `find_stale()` cross-asset query and the independent domain event cluster are definitive signals of a separate aggregate.

---

### ADR-M31-010: Top-Level Module Path Convention

**Status:** ACCEPTED
**Supersedes:** The `backend/src/redforge/domain/ai_posture/` paths in Implementation Plan §3
**Decision:** All M31 bounded contexts use top-level module paths: `backend/src/ai_posture/`, `backend/src/ai_supply_chain/`, `backend/src/ai_agent_governance/`.

**Consequences:**
- Implementation Plan §3 file paths are corrected (see §9 below)
- `backend/src/redforge/` is not used for M31 domain or application code
- Test paths follow: `backend/tests/ai_posture/`, `backend/tests/ai_supply_chain/`, `backend/tests/ai_agent_governance/`

**Alternatives considered:** `backend/src/redforge/domain/ai_posture/` — rejected because it re-enters the pre-M28 monolith structure and diverges from M28/M29/M30's established pattern.

---

### ADR-M31-011: Model Provenance Size-Threshold Verification Policy

**Status:** ACCEPTED
**Decision:** Two-tier verification policy. Tier 1 (≤10 GB): independent hash verification (SHA-256/SHA-512). Tier 2 (>10 GB): provider-attested signature verification. Partial hashing (sampling) is rejected. `VerificationMethod` value object distinguishes `IndependentHash` from `ProviderAttestation` in all records and outputs.

**Consequences:**
- `ModelProvenance` aggregate gains `VerificationMethod` value object and `size_threshold_gb` configuration reference
- `ProvenanceChainEntry` records include `verification_method` and, for Tier 2, `trust_delegation_note`
- Compliance reports label Tier 2 verifications as "Provider-Attested" — never as equivalent to independent hash verification
- `ProvenanceVerificationService` implements size check before dispatching to the appropriate verification adapter

**Alternatives considered:** (a) Provider attestation only for all models — rejected because it eliminates independent verification for models where it is feasible. (b) Sampling — rejected because partial hashing is not a recognized integrity guarantee standard. (c) Full retrieval for all models — rejected because hundreds-of-GB egress per weekly verification run is operationally impractical and cost-prohibitive at scale.

---

### ADR-M31-012: Kubernetes Admission Integration Model — Read-Only Audit Logs

**Status:** ACCEPTED
**Decision:** `IKubernetesAdmissionQueryPort` for M31 is implemented as read-only access to cloud provider Kubernetes audit logs (EKS CloudWatch Logs, GKE Cloud Audit Logs, AKS diagnostic logs). No RedForge admission webhook is deployed into customer clusters for M31.

**Consequences:**
- Phase 3 implementation of `IKubernetesAdmissionQueryPort` uses cloud audit log APIs via M26 credential vault
- On-premise and self-managed K8s clusters are not in scope for M31 K8s discovery
- Post-M31 admission webhook model (Option B) is a separate design decision, will implement the same port interface

**Alternatives considered:** Admission webhook deployment (Option B) — deferred because it requires cluster-admin trust grants, introduces a critical-path availability dependency, and is premature for a posture discovery milestone. The read-only audit log approach provides sufficient AI workload discovery signal for M31's scope.

---

## 9. Architecture Corrections to Source Documents

### Correction C1 — Architecture Freeze §8.2: AISystemAsset Entity List

**File:** `docs/architecture/m31/M31_ARCHITECTURE_FREEZE.md`
**Section:** §8.2, `AISystemAsset Aggregate Root`, Entities list
**Remove:** `AIThreatProfile — the threat surface assessment for this system`
**Add:** No new entity. `AIThreatProfileRef` is added to the Value Objects list.

**Corrected Value Objects list includes (addition only):**
- `AIThreatProfileRef` — reference to the tenant's `AIThreatProfile` for this asset; null until `AIThreatAssessmentService` initializes the profile (during `UnderReview` or `Registered` lifecycle state)

### Correction C2 — Architecture Freeze §8.2: AISystemAsset Domain Events

**Remove from `AISystemAsset`'s domain event list:** `AIThreatProfileUpdated`
**No replacement on `AISystemAsset`.** Consumers subscribe to `AIThreatProfile`'s events directly.

### Correction C3 — Architecture Freeze §14: Authorization Model

**Row for `mlsecops:engineer`:**
- **Was:** `mlsecops:engineer`
- **Corrected:** `ai_posture:engineer` (product display alias: MLSecOps Engineer)

### Correction C4 — Implementation Plan §3: File Paths

All file paths in Implementation Plan §3 that begin with `backend/src/redforge/domain/ai_posture/` are corrected to `backend/src/ai_posture/`.

All file paths that begin with `backend/src/redforge/infrastructure/ai_posture/` are corrected to `backend/src/ai_posture/infrastructure/`.

All file paths that begin with `backend/src/redforge/domain/ai_supply_chain/` are corrected to `backend/src/ai_supply_chain/`.

All file paths that begin with `backend/src/redforge/domain/ai_agent_governance/` are corrected to `backend/src/ai_agent_governance/`.

Test paths: `backend/tests/redforge/` → `backend/tests/{context_name}/` per context.

### Correction C5 — Hardening Review Pre-Conditions: Bulk Triage Assignment

The Hardening Review pre-condition:
> "Bulk shadow AI triage capability scoped into Phase 5 (or Phase 1 if first-scan volume concerns are significant)"

Is corrected to:
> "Bulk shadow AI triage capability scoped into **Phase 1**."

Status: RESOLVED by Decision 4.

---

## 10. Implementation Impact Summary

| Observation | Impacted Phases | Net Change |
|---|---|---|
| AIThreatProfile as independent aggregate root | Phase 2 (primary), Phase 5 (read models) | `AISystemAsset` removes entity child; adds `AIThreatProfileRef` value object. Domain event `AIThreatProfileUpdated` removed from `AISystemAsset`; `AIThreatProfile` publishes `ExposureLevelChanged`. No change to repository interfaces — `IAIThreatProfileRepository` was already declared separately. |
| Module path correction | All phases | Correct file paths before any Phase 1 file is created. No domain model impact. |
| Role naming correction | All phases | `mlsecops:engineer` → `ai_posture:engineer` in all RBAC definitions, migrations, API responses, and audit log attributions. No permission changes. |
| Bulk triage moved to Phase 1 | Phase 1 (adds scope), Phase 5 (removes scope) | Phase 1 adds: bulk triage API endpoint, bulk resolution API endpoint, triage backlog age metric, discovery-only mode configuration. Phase 5 removes these items from its scope. Net: same total work, earlier delivery. |
| Model provenance size-threshold policy | Phase 3 | `ModelProvenance` aggregate gains `VerificationMethod` value object. `ProvenanceVerificationService` gains size-check dispatch logic. `ProvenanceChainEntry` gains `trust_delegation_note` field for Tier 2 records. Read models and compliance reports gain `VerificationMethod` display. |
| Kubernetes read-only audit log model | Phase 3 | `IKubernetesAdmissionQueryPort` implementation scoped to cloud audit log adapters (3 providers). No cluster deployment scope. Phase 3 pre-condition: cloud audit log access confirmed via M26 credential vault. |
| Hardening acceptances | All phases | All 12 hardening items accepted. No items rejected or indefinitely deferred. Four open questions resolved. |

**Total aggregate model changes:** 2 (corrections to `AISystemAsset` entity list and event list)
**Total new value objects:** 2 (`AIThreatProfileRef`, `VerificationMethod`)
**Total new ADRs:** 4 (ADR-M31-009 through ADR-M31-012)
**Total role name changes:** 1 (`mlsecops:engineer` → `ai_posture:engineer`)
**Total phase scope changes:** Bulk triage moves from Phase 5 to Phase 1

---

## 11. Updated Phase Plan

All changes from the seven decisions are reflected. Only the delta from `M31_IMPLEMENTATION_PLAN.md` is described; items not mentioned are unchanged.

### Phase 1 — AI System Asset Foundation (Updated)

**Additions to scope (from Decision 4):**
- Bulk triage endpoint: triage N alerts matching a source/account/service-type pattern in one operation (`ai_posture:analyst`)
- Bulk resolution endpoint: confirm or dismiss a bulk-triaged set (`ai_posture:approver`)
- Discovery-only mode: `AIDiscoveryScanCoordinator` configuration flag that produces a draft report without raising `ShadowAIAlert` records; toggled by `ai_posture:admin` for first-deployment surveys
- Triage backlog age metric: `shadow_ai_triage_backlog_age_days` gauge (count of `Open` alerts by days-in-open-state bucket)

**Corrections to scope:**
- Module paths: all files under `backend/src/ai_posture/` (not `backend/src/redforge/domain/ai_posture/`)
- Role: `ai_posture:engineer` (not `mlsecops:engineer`) in all RBAC definitions and migrations
- `AISystemAsset` value objects: replace `AIThreatProfile` entity reference with `AIThreatProfileRef` value object (nullable)

**Pre-conditions (updated):**
- [ ] M22 `AIAsset` `AssetRef` ACL compatibility verified (named owner assigned, completion date set)
- [ ] Module path convention confirmed (RESOLVED by Decision 2 — `backend/src/ai_posture/`)
- [ ] Role naming confirmed (RESOLVED by Decision 3 — `ai_posture:engineer`)
- [ ] Bulk triage confirmed as Phase 1 scope (RESOLVED by Decision 4)

---

### Phase 2 — AI Threat Profiling and Risk Scoring (Updated)

**Corrections to scope:**
- `AIThreatProfile` is an independent aggregate root (RESOLVED by Decision 1; ADR-M31-009)
- `IAIThreatProfileRepository` is used by `AIThreatAssessmentService` independently — no `AISystemAsset` loading required for threat profile operations
- `AIRiskScoringService` subscribes to `ExposureLevelChanged` (from `AIThreatProfile`) for event-driven recomputation trigger — not to `AIThreatProfileUpdated` (which no longer exists)
- `AISystemAsset` receives `AIThreatProfileRef` on first threat profile creation (via `AIThreatProfileCreated` event handler)

**Mandatory new test:**
- `AIThreatProfile` is confirmed as a separate aggregate root: instantiating an `AIThreatProfile` does not require loading its `AISystemAsset`
- `IAIRiskScoreSnapshotRepository.find_stale()` triggers recompute only from `ExposureLevelChanged`, not from a now-absent `AIThreatProfileUpdated` event

**Pre-conditions (updated):**
- [ ] Decision 1 corrections implemented in Phase 1: `AISystemAsset` uses `AIThreatProfileRef` value object; test confirms aggregate separation

---

### Phase 3 — Model Provenance, MBOM, and Discovery Scanning (Updated)

**Additions to scope (from Decisions 5 and 6):**
- `VerificationMethod` value object: `IndependentHash | ProviderAttestation` — added to `ModelProvenance` aggregate and `ProvenanceChainEntry`
- `trust_delegation_note` field on `ProvenanceChainEntry` for Tier 2 (ProviderAttestation) records
- Size-threshold enforcement in `ProvenanceVerificationService`: checks artifact size before dispatching to hash-computation adapter or signature-verification adapter
- Tier 1 egress rate limiting: per-provider Tier 1 verification jobs rate-limited and scheduled off-peak
- `IKubernetesAdmissionQueryPort` implementation: cloud audit log adapters for EKS, GKE, AKS (not cluster webhook deployment)
- Provenance verification budget tracking: per-tenant monthly egress budget; budget-exhaustion alert distinct from `VerificationFailed`

**Mandatory new tests (from Decision 5 and Hardening §1):**
- `Verified→VerificationFailed→retry→Verified` path recomputes the full hash (does not shortcut to Verified)
- `Verified→VerificationFailed→retry→Mismatched` produces `Mismatched` and security alert
- Tier 1 model (≤10 GB): `VerificationMethod = IndependentHash`; `ProvenanceIntegrityStatus = Verified` requires `ChecksumVerified` event with recorded hash
- Tier 2 model (>10 GB): `VerificationMethod = ProviderAttestation`; `ProvenanceIntegrityStatus = Verified` requires `SignatureChainRef` and `trust_delegation_note`
- `ModelOrigin = Unknown` caps status at `Unverified` regardless of tier or checksum match
- Database-level immutability: integration test directly issues SQL `UPDATE` against `provenance_chain_entries` and confirms error

**Pre-conditions (updated):**
- [ ] M26 credential vault confirmed accessible for: cloud AI provider ports, cloud K8s audit log ports
- [ ] Large model provenance policy documented (RESOLVED — Decision 5 above)
- [ ] Kubernetes audit log access model confirmed (RESOLVED — Decision 6 above): cloud audit log APIs for EKS/GKE/AKS via M26 credential vault

---

### Phase 4 — AI Agent Operational Envelope and Deviation Detection (Unchanged except corrections)

**Corrections:**
- Role `mlsecops:engineer` → `ai_posture:engineer` in all role-check assertions
- Code review checklist addition (from Hardening §6): "`ai_agent_governance` domain and application code imports nothing from `ai_posture` domain or application layer. Cross-context communication is event-driven only."

No scope changes. All Phase 4 decisions were settled by the original freeze and confirmed by Hardening §4 and §10 acceptance.

---

### Phase 5 — Compliance Mapping, Security Graph, and Read Models (Updated)

**Removals from scope (moved to Phase 1):**
- Individual and bulk `ShadowAIAlert` triage (moved to Phase 1 by Decision 4)
- Triage backlog age metric (moved to Phase 1)

**Additions to scope (from hardening acceptances and Decision 5):**
- AI Compliance Posture report: `requires_human_attestation` flag per control; attesting identity + date for attestation-required controls; clear labeling of auto-evaluated vs. human-attested
- AI Supply Chain Integrity Report: `VerificationMethod` displayed per model; Tier 2 records labeled "Provider-Attested"
- AI Asset Inventory Dashboard: last-scan timestamp, configured discovery sources, coverage scope indicator
- Shadow AI Discovery Report: "scope of this report" section; `partial: true` scan flags
- Audit read model: full `RequiresHumanApprovalFor` change history per envelope

**Pre-conditions (updated):**
- [ ] M24 `requires_human_attestation` per-control classification confirmed before Phase 5 begins (named owner, completion date)

---

## 12. Final Frozen Decisions Register

| # | Decision | Final Answer | Effective Phase |
|---|---|---|---|
| D1 | AIThreatProfile aggregate position | **Independent Aggregate Root** (Option B); `AISystemAsset` holds `AIThreatProfileRef` value object | Phase 2 |
| D2 | Module path convention | **`backend/src/ai_posture/`** (and `ai_supply_chain/`, `ai_agent_governance/`); not `backend/src/redforge/domain/` | All phases |
| D3 | RBAC role naming | **`ai_posture:engineer`** canonical; `mlsecops:engineer` UI display alias only | Phase 1 |
| D4 | Shadow AI triage phase | **Phase 1** — individual and bulk triage, discovery-only mode, triage backlog age metric | Phase 1 |
| D5 | Model provenance verification policy | **Size-threshold two-tier policy**: Tier 1 (≤10 GB) independent hash; Tier 2 (>10 GB) provider attestation; sampling rejected; `VerificationMethod` in all records | Phase 3 |
| D6 | Kubernetes admission integration | **Read-only cloud audit logs** (EKS/GKE/AKS) for M31; admission webhook deferred post-M31 | Phase 3 |
| D7a | Hardening §1 (Provenance masking) | **Accept** — all four requirements, Phase 3 | Phase 3 |
| D7b | Hardening §2 (Discovery completeness) | **Accept** — all four requirements, Phase 5 | Phase 5 |
| D7c | Hardening §3 (Score staleness) | **Accept** — all four requirements, Phase 2 | Phase 2 |
| D7d | Hardening §4 (Envelope evasion) | **Accept** — all four requirements, Phase 4 | Phase 4 |
| D7e | Hardening §5 (Rate limiting) | **Accept** — all four requirements, Phase 3 | Phase 3 |
| D7f | Hardening §6 (ACL enforcement) | **Accept** — permanent rule, all phases | All phases |
| D7g | Hardening §7 (DB immutability) | **Accept** — PostgreSQL RLS preferred; Phase 3 migration | Phase 3 |
| D7h | Hardening §8 (Compliance automation) | **Accept** — attestation controls never auto-satisfied; Phase 5 | Phase 5 |
| D7i | Hardening §9 (Triage bottleneck) | **Accept** — resolved by D4; Phase 1 | Phase 1 |
| D7j | Hardening §10 (Transport design) | **Accept** — batch + idempotent; Phase 4 | Phase 4 |
| D7k | Hardening §11 (Debt prevention) | **Accept** — all 7 rules, permanent | All phases |
| D7l | Hardening Q1 (Credential mgmt) | **Resolved** — M26 credential vault; pre-condition before Phase 3 | Pre-Phase 3 |
| D7m | Hardening Q2 (MCP stability) | **Resolved** — thin adapter, version separately | Phase 3 |
| D7n | Hardening Q3 (Large model policy) | **Resolved** — Decision D5 | Phase 3 |
| D7o | Hardening Q4 (K8s model) | **Resolved** — Decision D6 | Phase 3 |

---

**All seven outstanding architectural observations from the M31 Architecture Review are resolved.**

**All hardening items are dispositioned (Accept/Resolve — none rejected or indefinitely deferred).**

**All four Hardening Review pre-conditions are addressed (one remains requiring external verification: M22 AssetRef ACL compatibility).**

**Four new ADRs (ADR-M31-009 through ADR-M31-012) are specified.**

**Five source document corrections are identified (C1 through C5).**

---

**M31 Architecture Freeze Complete.**

---

*This document is documentation only. No code, API definitions, repository implementations, migration files, or implementation artifacts are produced by this record. No production files have been modified.*
