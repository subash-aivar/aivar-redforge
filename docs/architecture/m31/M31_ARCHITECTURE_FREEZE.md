# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Architecture Freeze

**Status:** FROZEN
**Milestone:** M31
**Date:** 2026-07-21
**Depends On:** M22 (Inventory), M24 (Compliance), M26 (Cloud), M27 (Vulnerability), M28 (Detection Engineering)

---

## 1. Product Vision

The platform that secures the AI systems enterprises have already deployed — not hypothetical future AI, but the LLMs, ML inference APIs, training pipelines, vector databases, and AI agent frameworks running in production right now. AI-SPM makes the security posture of enterprise AI infrastructure visible, measurable, and continuously managed.

AI-SPM is a posture and governance layer. It does not run AI systems, does not build models, and does not intercept inference traffic. It discovers, inventories, assesses, and continuously monitors the AI systems an enterprise operates, and gives security teams the same operational visibility into AI risk that they already have into cloud and vulnerability risk.

---

## 2. Business Problem

Enterprises have deployed hundreds of AI systems — foundation models via API, custom-trained models, RAG pipelines, LLM-based automation agents — with virtually no security visibility. AI assets are not in traditional asset inventories. AI-specific attack surfaces (prompt injection, model extraction, training data poisoning, inference API abuse, supply chain model tampering) are not covered by any existing security control. Security teams are responsible for securing AI systems they cannot enumerate, cannot assess, and have no tooling to monitor.

---

## 3. Goals

- Discover and continuously inventory AI assets: models, inference APIs, training pipelines, vector stores, embedding services, AI agents, MCP servers
- Assess AI-specific attack surfaces: prompt injection exposure, model extraction risk, training data leakage, supply chain integrity
- Compute a composite AI risk score per AI system, cacheable with defined staleness tolerance
- Monitor AI agent behavior against a declared, authorized operational envelope and detect deviation
- Map AI systems to AI governance frameworks (EU AI Act, NIST AI RMF, ISO/IEC 42001) and produce compliance attestation evidence
- Detect shadow AI: AI services running in the enterprise's cloud estate without formal registration
- Govern AI supply chain integrity: model provenance, checksum-verified model registry entries, Model Bill of Materials
- Extend M22 inventory with AI-specific risk attributes — never duplicate or fork the canonical asset store

---

## 4. Non-Goals

- Not a model development security tool
- Not a data science platform
- Not a runtime prompt firewall
- Not an LLM observability platform
- Not a model training framework
- Not replacing M22 inventory
- Not a unified cross-domain exposure aggregator (that is M32 — M31 produces `AIRiskScore` as one input signal; it does not correlate across vulnerability, detection, and cloud domains itself)
- Not a telemetry-based real-time detection engine (that is M28 — M31 governs declared operational envelopes and evaluates deviation from periodic/reported behavior, it does not ingest and correlate raw telemetry streams)

---

## 5. Architecture Principles

- **AI-SPM extends inventory, never duplicates it.** `AISystemAsset` is a bounded extension record keyed 1:1 to an M22 `AIAsset`. AI-SPM never stores its own copy of asset identity, name, or ownership — it stores AI-specific risk and governance attributes referenced by `AssetRef`.
- **Model provenance is tamper-evident, not merely recorded.** Provenance and checksum data is captured with cryptographic integrity (content-hash + signature chain), following the same evidentiary philosophy as M29's execution evidence chain. Metadata-only trust (e.g., "the registry said so") is insufficient for a supply chain integrity claim.
- **Shadow AI discovery is batch, not real-time.** Cloud-wide AI service enumeration is a scheduled reconciliation process, not a continuous stream. Real-time discovery is cost-prohibitive and unnecessary for the governance use case this milestone serves.
- **AI risk scoring is asynchronous and cache-bearing.** Risk score computation may involve model inference and multi-source correlation; it is never computed synchronously in the request path. Consumers read a cached score with an explicit staleness bound.
- **Behavioral envelope governance is declarative, not inferential.** `AgentOperationalEnvelope` is authored and authorized by a human (MLSecOps engineer / architect); M31 evaluates reported/observed agent actions against this declared envelope. M31 does not infer "normal" agent behavior from telemetry baselines — that pattern belongs to M28/M20 behavioral detection.
- **AI taxonomy is extensible without redesign.** New AI asset subtypes, threat surface types, and framework integrations are additive enum/registry extensions, never breaking changes to aggregate shape.
- **Governance requires a human in the loop.** Risk classification, shadow AI triage, and compliance attestation always pass through an explicit human review gate before being treated as authoritative for audit purposes.
- **Every AI-SPM boundary context is a translator, not an owner, of foreign data.** All cross-milestone data (M22 assets, M26 cloud accounts, M27 CVEs, M28 rules, M24 controls) crosses through an ACL port and is translated into AI-SPM's own value objects; foreign aggregate types never appear inside AI-SPM's domain model.

---

## 6. Bounded Contexts

| Context | Type | Owns |
|---|---|---|
| `ai_posture` | Core Domain | AI system asset extension, AI threat profiling, AI risk scoring, shadow AI discovery, compliance mapping |
| `ai_supply_chain` | Supporting Domain | Model provenance, model integrity verification, Model Bill of Materials |
| `ai_agent_governance` | Supporting Domain | AI agent operational envelope definition, deviation detection, agent authorization |

---

## 7. Ubiquitous Language

| Term | Definition |
|---|---|
| **AISystemAsset** | The `ai_posture` extension record for an M22 `AIAsset`; carries AI-specific risk attributes, threat profile ref, and compliance status. Never duplicates asset identity data owned by M22. |
| **AISystemKind** | Classification of the underlying AI system: FoundationModelAPI, CustomTrainedModel, RAGPipeline, AIAgent, VectorStore, EmbeddingService, MCPServer, InferenceEndpoint |
| **ModelProvenance** | The recorded origin, training data lineage, and checkpoint integrity chain for a model, verified with cryptographic checksums |
| **ProvenanceIntegrityStatus** | Whether a model's current checksum matches its last-verified provenance record: Verified, Mismatched, Unverified, VerificationFailed |
| **AIThreatProfile** | The AI-specific threat surface applicable to a given `AISystemKind`: which threat categories apply and their assessed exposure |
| **AIThreatCategory** | A named class of AI-specific attack surface: PromptInjection, ModelExtraction, TrainingDataLeakage, SupplyChainTampering, InferenceAPIAbuse, DataPoisoning, AgentPrivilegeAbuse |
| **PromptInjectionExposureAssessment** | The evaluated exposure of a system to prompt injection: input surface, sanitization posture, downstream action capability |
| **ModelExtractionRiskAssessment** | The evaluated exposure of a model-serving system to extraction via repeated query/inference abuse |
| **TrainingDataLeakageAssessment** | The evaluated risk that a model's outputs may leak sensitive training data |
| **AgentOperationalEnvelope** | The declared, authorized bounds of behavior for an `AIAgentNode`: permitted actions, permitted resources, permitted data classifications, rate ceilings |
| **AgentDeviationEvent** | A recorded instance where observed/reported agent behavior fell outside its `AgentOperationalEnvelope` |
| **AIRiskScore** | The composite, cacheable AI-specific risk metric for an `AISystemAsset`, computed from threat profile, provenance integrity, compliance gaps, and agent deviation history |
| **AIRiskScoreStaleness** | The declared maximum age of a cached `AIRiskScore` before it must be recomputed |
| **ShadowAIAlert** | A detected AI service running in a monitored cloud account with no corresponding `AISystemAsset` registration |
| **AIAssetDiscoverySource** | The origin of an AI asset discovery signal: CloudProviderScan, HuggingFaceHub, ModelRegistryProtocol (MLflow/DVC/W&B), MCPServerDiscovery, KubernetesAdmission, ManualRegistration |
| **AIComplianceMapping** | A mapping from an `AISystemAsset` to one or more AI governance framework controls (EU AI Act article, NIST AI RMF subcategory, ISO/IEC 42001 clause), with an evidenced pass/fail/gap status |
| **AIComplianceFrameworkRef** | Reference to the specific framework and control being mapped (ACL to M24) |
| **ModelBillOfMaterials** | The AI-domain equivalent of a software SBOM: a structured manifest of a model's constituent components — base model, fine-tuning datasets, adapters/LoRA layers, dependent frameworks, and their versions |
| **MBOMComponent** | A single entry in a `ModelBillOfMaterials`: component type, name, version, source, checksum |
| **AIDiscoveryScan** | A scheduled batch run that enumerates AI services across registered discovery sources and reconciles against known `AISystemAsset` records |
| **AIAssetReconciliationResult** | The outcome of one `AIDiscoveryScan`: newly discovered assets, confirmed-registered assets, and shadow AI candidates |

---

## 8. Bounded Context: `ai_posture`

### 8.1 Purpose

The core domain. Owns the AI-specific extension to inventoried assets, the AI threat profile per system, the composite AI risk score, shadow AI discovery, and the mapping of AI systems to compliance frameworks.

### 8.2 Aggregates

#### `AISystemAsset` Aggregate Root

**Identity:** `AISystemAssetId` (tenant-scoped UUID)

**Entities:**
- `AISystemAsset` (root)
- `AIThreatProfile` — the threat surface assessment for this system
- `AIComplianceMapping` — one or more per governing framework

**Value Objects:**
- `AISystemAssetId`
- `AssetRef` — reference to the M22 `AIAsset` this record extends (ACL boundary; never the M22 entity itself)
- `AISystemKind` — enum: FoundationModelAPI | CustomTrainedModel | RAGPipeline | AIAgent | VectorStore | EmbeddingService | MCPServer | InferenceEndpoint | TrainingPipeline
- `AISystemLifecycleState` — enum: Discovered | PendingClassification | UnderReview | Registered | Deprecated | Decommissioned
- `RegistrationStatus` — enum: Unregistered | ShadowAI | FormallyRegistered | ExemptedByPolicy
- `AIRiskScoreRef` — reference to the current cached `AIRiskScore`
- `DataSensitivityClassification` — enum: Public | Internal | Confidential | Restricted (of data the system processes)
- `ModelProvenanceRef` — optional; present when this system serves a model (ACL to `ai_supply_chain`)
- `AgentEnvelopeRef` — optional; present when `AISystemKind = AIAgent` (ACL to `ai_agent_governance`)
- `DiscoverySourceRecord` — `AIAssetDiscoverySource` + first_seen timestamp + last_confirmed timestamp
- `BusinessOwnerRef` — accountable owner, required before `Registered` state
- `AIComplianceMappingId`
- `ComplianceControlStatus` — enum: Satisfied | PartiallySatisfied | Gap | NotApplicable | PendingEvidence

**Aggregate Invariants:**
- `AISystemAsset` may not exist without a valid `AssetRef` to an M22 `AIAsset`; creation is always driven by an M22 asset event or a discovery reconciliation that first ensures an M22 `AIAsset` exists
- `RegistrationStatus = FormallyRegistered` requires a non-null `BusinessOwnerRef`
- `AISystemLifecycleState` may not move to `Registered` while `RegistrationStatus = ShadowAI`
- A `Decommissioned` `AISystemAsset` is sealed: no further `AIThreatProfile` or `AIComplianceMapping` mutation
- `AgentEnvelopeRef` is required if and only if `AISystemKind = AIAgent`
- `ModelProvenanceRef` is required if and only if `AISystemKind ∈ {CustomTrainedModel, FoundationModelAPI, EmbeddingService}`

**Domain Events:**
- `AISystemAssetDiscovered`
- `AISystemAssetClassified`
- `AISystemAssetRegistered`
- `AISystemAssetOwnerAssigned`
- `AISystemAssetDeprecated`
- `AISystemAssetDecommissioned`
- `ShadowAIStatusAssigned`
- `AIThreatProfileUpdated`
- `AIComplianceMappingRecorded`
- `AIComplianceGapIdentified`

**Lifecycle State Machine:**
```
[Discovered]
  → [PendingClassification]   (discovery reconciliation completes)

[PendingClassification]
  → [UnderReview]              (AISystemKind assigned; RegistrationStatus evaluated)

[UnderReview]
  → [Registered]                (BusinessOwnerRef assigned; RegistrationStatus = FormallyRegistered)
  → [UnderReview]                (returned for further triage — ShadowAI candidate confirmed unregistered)

[Registered]
  → [Deprecated]                 (system marked end-of-life, still present)
  → [Decommissioned]             (system confirmed removed)

[Deprecated]
  → [Decommissioned]

[Decommissioned]  → (terminal, sealed)
```

---

#### `AIThreatProfile` Aggregate Root

**Identity:** `AIThreatProfileId` — one per `AISystemAsset`

**Entities:**
- `AIThreatProfile` (root)
- `PromptInjectionExposureAssessment`
- `ModelExtractionRiskAssessment`
- `TrainingDataLeakageAssessment`
- `ThreatCategoryAssessment` — one per applicable `AIThreatCategory` not covered by a specific assessment type above

**Value Objects:**
- `AIThreatProfileId`
- `AISystemAssetRef`
- `ApplicableThreatCategories` — the subset of `AIThreatCategory` relevant to this system's `AISystemKind` (derived from a maintained taxonomy mapping)
- `ExposureLevel` — enum: None | Low | Medium | High | Critical
- `PromptInjectionExposureAssessment` fields: `input_surface` (enum: UserFacingText | ToolOutputIngestion | RAGRetrievedContent | MultiModal), `sanitization_posture` (enum: None | Heuristic | ModelBased | Unknown), `downstream_action_capability` (enum: ReadOnly | WriteLimited | WriteUnrestricted | ExternalSideEffect), `exposure_level`
- `ModelExtractionRiskAssessment` fields: `query_rate_limiting_present` (bool), `output_verbosity` (enum: Minimal | Standard | Verbose), `watermarking_present` (bool), `exposure_level`
- `TrainingDataLeakageAssessment` fields: `training_data_sensitivity` (`DataSensitivityClassification`), `memorization_testing_performed` (bool), `output_filtering_present` (bool), `exposure_level`
- `LastAssessedAt`
- `AssessmentEvidenceRefs` — list of evidence references supporting the assessed exposure levels

**Aggregate Invariants:**
- `AIThreatProfile` may only assess categories present in `ApplicableThreatCategories`
- An `ExposureLevel` of `Critical` requires at least one `AssessmentEvidenceRef`
- Assessments older than a configurable staleness threshold (default 90 days) are flagged `RequiresReassessment` by `AIThreatAssessmentService`, not silently trusted

**Domain Events:**
- `AIThreatProfileCreated`
- `ThreatCategoryAssessed`
- `ExposureLevelChanged`
- `ThreatProfileFlaggedStale`

---

#### `ShadowAIAlert` Aggregate Root

**Identity:** `ShadowAIAlertId`

**Purpose:** A discrete, actionable record produced when `AIDiscoveryScan` reconciliation finds an AI service with no corresponding registered `AISystemAsset`.

**Value Objects:**
- `ShadowAIAlertId`
- `AIAssetDiscoverySource`
- `DiscoveredServiceFingerprint` — cloud account, resource identifier, service type, region (structured, source-specific)
- `AlertState` — enum: Open | UnderTriage | ConfirmedShadowAI | ConfirmedFalsePositive | Resolved
- `ResolutionAction` — enum: RegisteredAsAsset | ExemptedByPolicy | Decommissioned | AwaitingOwnerResponse
- `FirstDetectedAt`
- `LastConfirmedAt`
- `LinkedAISystemAssetRef` — set once triage produces or matches an `AISystemAsset`
- `TriageNotes`

**Aggregate Invariants:**
- `AlertState = Resolved` requires a non-null `ResolutionAction`
- `ConfirmedFalsePositive` requires a documented reason (feeds discovery source tuning; see Failure Recovery §19)
- A `ShadowAIAlert` cannot skip `UnderTriage`; automated confirmation is not permitted — a human must transition `Open → UnderTriage → {Confirmed*}`

**Domain Events:**
- `ShadowAIAlertRaised`
- `ShadowAIAlertTriaged`
- `ShadowAIAlertConfirmed`
- `ShadowAIAlertDismissedFalsePositive`
- `ShadowAIAlertResolved`

---

#### `AIRiskScoreSnapshot` Aggregate Root

**Identity:** `AIRiskScoreSnapshotId`

**Purpose:** An immutable, timestamped computation of `AIRiskScore` for one `AISystemAsset`. `AISystemAsset.AIRiskScoreRef` always points at the latest snapshot; history is retained for trend analysis.

**Value Objects:**
- `AIRiskScoreSnapshotId`
- `AISystemAssetRef`
- `CompositeScore` — float 0–100
- `ScoreComponents` — structured breakdown: `threat_exposure_component`, `provenance_integrity_component`, `compliance_gap_component`, `agent_deviation_component` (the last only for `AISystemKind = AIAgent`)
- `ComputedAt`
- `StalenessBound` — the declared max age before recomputation is required (default 24h, configurable per tenant)
- `ScoreInputVersion` — version tag of the scoring model/weights used, for reproducibility

**Aggregate Invariants:**
- A snapshot is immutable once created
- `CompositeScore` is deterministic given identical `ScoreComponents` and `ScoreInputVersion` — no manual override
- `AISystemAsset.AIRiskScoreRef` may only point to a non-stale snapshot for authoritative dashboards; stale snapshots are visibly flagged, not silently served (see §22 Performance Considerations)

**Domain Events:**
- `AIRiskScoreComputed`
- `AIRiskScoreStalenessExceeded`

---

### 8.3 Domain Services

**`AISystemClassificationService`**
Assigns `AISystemKind` to a `Discovered` `AISystemAsset` based on `DiscoverySourceRecord` metadata and, where available, provider-reported service type (e.g., SageMaker endpoint type, Hugging Face pipeline tag). Produces `ApplicableThreatCategories` via the maintained taxonomy mapping. Human-reviewable; classification is a suggestion until confirmed at `UnderReview → Registered` transition.

**`AIThreatAssessmentService`**
Runs the per-category assessment logic (prompt injection, model extraction, training data leakage, and generic `ThreatCategoryAssessment` for other categories) against an `AISystemAsset`'s configuration and metadata pulled via ACL from M22/M26. Flags assessments exceeding the staleness threshold.

**`AIRiskScoringService`**
Computes `AIRiskScore` from: `AIThreatProfile` exposure levels, `ModelProvenance.ProvenanceIntegrityStatus` (via ACL to `ai_supply_chain`), `AIComplianceMapping` gap count, and — for agents — recent `AgentDeviationEvent` frequency (via ACL to `ai_agent_governance`). Runs asynchronously; writes a new `AIRiskScoreSnapshot`. Never invoked synchronously from a read path.

**`ShadowAIDetectionService`**
Consumes `AIAssetReconciliationResult` from a completed `AIDiscoveryScan` (produced in `ai_supply_chain`'s sibling discovery infrastructure — see §9.3) and raises `ShadowAIAlert` for any discovered service fingerprint with no matching `AISystemAsset`. Deduplicates against open alerts for the same fingerprint.

**`AIComplianceMappingService`**
For a given `AISystemAsset` and target framework, resolves applicable controls via `IComplianceQueryPort` (ACL to M24) and evaluates `ComplianceControlStatus` from available evidence (threat assessments, provenance verification, envelope definition presence). Produces `AIComplianceGapIdentified` for any `Gap` status.

---

## 9. Bounded Context: `ai_supply_chain`

### 9.1 Purpose

Owns model origin, training data lineage, checkpoint integrity, and the Model Bill of Materials. Provides the tamper-evident supply chain record that `ai_posture` references but does not own.

### 9.2 Aggregates

#### `ModelProvenance` Aggregate Root

**Identity:** `ModelProvenanceId`

**Entities:**
- `ModelProvenance` (root)
- `ProvenanceChainEntry` — one per recorded lifecycle event in the model's history (created, fine-tuned, checkpointed, published, re-verified)
- `ModelBillOfMaterials` — the structured component manifest for this model

**Value Objects:**
- `ModelProvenanceId`
- `AISystemAssetRef` (backreference for query convenience; ownership is `ai_supply_chain`)
- `ModelOrigin` — enum: InternallyTrained | FineTunedFromFoundation | ThirdPartyVendor | OpenSourceRegistry | Unknown
- `SourceRegistryRef` — provider-specific identifier (Hugging Face model ID, internal MLflow run ID, vendor SKU)
- `TrainingDataLineageRef` — reference/description of training data sources (does not store the training data itself)
- `ChecksumAlgorithm` — enum: SHA256 | SHA512 | ProviderSignature
- `CurrentChecksum` — the last-computed checksum of the model artifact
- `LastVerifiedChecksum` — the checksum recorded at last successful verification
- `ProvenanceIntegrityStatus` — enum: Verified | Mismatched | Unverified | VerificationFailed
- `SignatureChainRef` — optional; cryptographic signature chain reference if the source registry supports signed artifacts
- `LastVerifiedAt`
- `MBOMComponent` fields: `component_type` (enum: BaseModel | FineTuningDataset | AdapterLayer | Framework | Tokenizer | EmbeddingModel), `name`, `version`, `source`, `checksum`

**Aggregate Invariants:**
- `ProvenanceIntegrityStatus = Verified` requires `CurrentChecksum == LastVerifiedChecksum` at `LastVerifiedAt`, computed via cryptographic hash — never inferred from registry metadata (e.g., a matching filename or reported version string) alone
- A checksum mismatch immediately transitions status to `Mismatched` and raises `ProvenanceIntegrityMismatchDetected`; this transition is never suppressed or auto-resolved
- `ProvenanceChainEntry` records are append-only; no entry may be edited or deleted once recorded
- A `ModelBillOfMaterials` must list at least one `BaseModel` component before it may be marked complete
- `ModelOrigin = Unknown` caps `ProvenanceIntegrityStatus` at `Unverified` — an unknown origin cannot be claimed Verified regardless of checksum match

**Domain Events:**
- `ModelProvenanceRecorded`
- `ProvenanceChainEntryAdded`
- `ChecksumVerified`
- `ProvenanceIntegrityMismatchDetected`
- `ModelBillOfMaterialsCompleted`
- `ModelBillOfMaterialsComponentAdded`

**Lifecycle State Machine (`ProvenanceIntegrityStatus`):**
```
[Unverified]
  → [Verified]              (checksum computed and matches declared source checksum)
  → [VerificationFailed]    (verification attempted; source unreachable or checksum uncomputable)

[Verified]
  → [Mismatched]            (subsequent verification finds checksum divergence)

[Mismatched]
  → [Verified]              (re-verification after confirmed remediation, e.g., re-published clean artifact)
  (Mismatched never silently reverts; requires explicit re-verification event)

[VerificationFailed]
  → [Unverified]            (retry scheduled)
  → [Verified]               (retry succeeds)
```

---

### 9.3 Domain Services

**`ProvenanceVerificationService`**
Computes `CurrentChecksum` for a model artifact (via provider-specific ACL — Hugging Face Hub, MLflow, cloud AI service model registries) and compares against `LastVerifiedChecksum`. Runs on a schedule (default weekly, configurable) and on-demand. Never trusts a provider-reported checksum without independent computation where the artifact is directly retrievable; where only provider-attested signatures are available (e.g., closed foundation model APIs), records `SignatureChainRef`-based verification and flags the distinction in `ProvenanceIntegrityStatus` evidence.

**`ModelBillOfMaterialsBuilder`**
Assembles `MBOMComponent` entries from provider metadata (base model, fine-tuning dataset refs, adapter layers, framework/tokenizer versions) at model registration and on each `ProvenanceChainEntry` addition. Cross-references `IVulnerabilityQueryPort` (ACL to M27) to flag components with known CVEs (e.g., a vulnerable Transformers library version).

**`AIDiscoveryScanCoordinator`**
Runs scheduled `AIDiscoveryScan` batches against registered discovery sources (cloud AI service APIs, Hugging Face Hub, internal model registries, MCP server discovery, Kubernetes admission records). Produces `AIAssetReconciliationResult`, which is consumed by `ai_posture`'s `ShadowAIDetectionService` via published event, and by `ModelBillOfMaterialsBuilder` for newly discovered models. Rate-limited and cost-bounded per tenant per cloud account (see §21 Scalability).

---

## 10. Bounded Context: `ai_agent_governance`

### 10.1 Purpose

Owns the declared operational envelope for AI agent systems and the detection of deviation from that envelope. Distinct from M28 detection engineering: M28 is telemetry-based, real-time technical detection across the whole security estate; `ai_agent_governance` is declarative behavioral-boundary governance scoped specifically to AI agents, evaluated against reported/observed agent actions on a periodic or event-reported basis. See ADR-M31-002 for the full boundary rationale.

### 10.2 Aggregates

#### `AgentOperationalEnvelope` Aggregate Root

**Identity:** `AgentOperationalEnvelopeId` — one per `AISystemAsset` where `AISystemKind = AIAgent`

**Entities:**
- `AgentOperationalEnvelope` (root)
- `AuthorizedAction` — a permitted action class (e.g., "read from CRM", "send email", "execute shell command")
- `AuthorizedResourceScope` — a permitted resource/target boundary (e.g., specific systems, data classifications, network segments)

**Value Objects:**
- `AgentOperationalEnvelopeId`
- `AISystemAssetRef`
- `EnvelopeState` — enum: Draft | Active | UnderRevision | Suspended | Retired
- `AuthorizedActionCategory` — enum: DataRead | DataWrite | ExternalCommunication | CodeExecution | ToolInvocation | FinancialTransaction | SystemAdministration
- `MaxAuthorizedDataSensitivity` — `DataSensitivityClassification`
- `RateCeiling` — max actions per category per time window
- `RequiresHumanApprovalFor` — set of `AuthorizedActionCategory` values that always require human-in-the-loop approval regardless of envelope authorization (e.g., FinancialTransaction always requires approval even if authorized)
- `EnvelopeApprovedBy` — approver identity; required before `Active`
- `EnvelopeVersion` — incremented on each revision

**Aggregate Invariants:**
- `AgentOperationalEnvelope` may only be `Active` if it has at least one `AuthorizedAction` and `EnvelopeApprovedBy` is set
- A `Suspended` envelope blocks all deviation-clean status for its `AISystemAsset` — the associated agent is treated as unauthorized to operate until reactivated
- `RequiresHumanApprovalFor` categories are never removable by envelope revision alone; removal requires `ai_posture:approver`-equivalent sign-off (`ai_posture:admin` in the AI-SPM role model)
- Envelope revision creates a new `EnvelopeVersion`; prior versions are retained for deviation-evaluation historical accuracy (an action must be evaluated against the envelope version active at the time it occurred)

**Domain Events:**
- `AgentOperationalEnvelopeDrafted`
- `AgentOperationalEnvelopeApproved`
- `AgentOperationalEnvelopeRevised`
- `AgentOperationalEnvelopeSuspended`
- `AgentOperationalEnvelopeRetired`

---

#### `AgentDeviationEvent` Aggregate Root

**Identity:** `AgentDeviationEventId`

**Purpose:** A recorded instance where a reported or observed agent action fell outside the `AgentOperationalEnvelope` active at the time.

**Value Objects:**
- `AgentDeviationEventId`
- `AgentOperationalEnvelopeRef` (with `EnvelopeVersion` pinned)
- `AISystemAssetRef`
- `DeviationType` — enum: UnauthorizedActionCategory | ResourceScopeViolation | DataSensitivityExceeded | RateCeilingExceeded | RequiredApprovalBypassed
- `ObservedAction` — structured description of the action that triggered the deviation
- `Severity` — enum: Informational | Low | Medium | High | Critical
- `DetectedAt`
- `ReviewState` — enum: Unreviewed | UnderReview | ConfirmedDeviation | ConfirmedBenign | EnvelopeUpdated
- `ReviewNotes`

**Aggregate Invariants:**
- `RequiredApprovalBypassed` deviations are always `Severity ≥ High` — this is a governance control failure, not a soft signal
- `ReviewState = EnvelopeUpdated` requires a linked `AgentOperationalEnvelopeRevised` event — closing a deviation by loosening the envelope must be explicit and auditable, never implicit
- A deviation event is immutable once created; only `ReviewState` and `ReviewNotes` are mutable, and only forward through the review state machine (no reverting from a terminal review state)

**Domain Events:**
- `AgentDeviationDetected`
- `AgentDeviationReviewed`
- `AgentDeviationConfirmed`
- `AgentDeviationDismissedBenign`

---

### 10.3 Domain Services

**`EnvelopeComplianceEvaluationService`**
Given a reported agent action (ingested via ACL from whatever agent runtime/orchestration reports it — out of scope for M31 to define the transport) and the `AgentOperationalEnvelope` version active at the action's timestamp, evaluates compliance and raises `AgentDeviationEvent` on violation. This is a pure evaluation function against a declared envelope — it performs no behavioral baselining or anomaly inference.

**`EnvelopeRevisionAdvisoryService`**
When repeated `ConfirmedBenign` deviations of the same `DeviationType` accumulate against the same envelope, surfaces an advisory recommendation to revise the envelope (human decision only — never auto-applied).

---

## 11. Repository Interfaces

```
IAISystemAssetRepository
  save(a: AISystemAsset) → void
  find_by_id(id: AISystemAssetId, tenant: TenantId) → Option<AISystemAsset>
  find_by_asset_ref(asset_ref: AssetRef, tenant: TenantId) → Option<AISystemAsset>
  find_by_registration_status(status: RegistrationStatus, tenant: TenantId) → Page<AISystemAsset>
  find_by_kind(kind: AISystemKind, tenant: TenantId) → Page<AISystemAsset>
  find_without_owner(tenant: TenantId) → List<AISystemAsset>

IAIThreatProfileRepository
  save(p: AIThreatProfile) → void
  find_by_asset(asset_id: AISystemAssetId) → Option<AIThreatProfile>
  find_stale(threshold_days: int, tenant: TenantId) → List<AIThreatProfile>

IShadowAIAlertRepository
  save(a: ShadowAIAlert) → void
  find_by_id(id: ShadowAIAlertId) → Option<ShadowAIAlert>
  find_open_by_tenant(tenant: TenantId) → List<ShadowAIAlert>
  find_by_fingerprint(fingerprint: DiscoveredServiceFingerprint, tenant: TenantId) → Option<ShadowAIAlert>

IAIRiskScoreSnapshotRepository
  save(s: AIRiskScoreSnapshot) → void
  find_latest_by_asset(asset_id: AISystemAssetId) → Option<AIRiskScoreSnapshot>
  find_history_by_asset(asset_id: AISystemAssetId, limit: int) → List<AIRiskScoreSnapshot>
  find_stale(staleness_bound: Duration, tenant: TenantId) → List<AISystemAssetId>

IModelProvenanceRepository
  save(p: ModelProvenance) → void
  find_by_id(id: ModelProvenanceId) → Option<ModelProvenance>
  find_by_asset(asset_id: AISystemAssetId) → Option<ModelProvenance>
  find_mismatched(tenant: TenantId) → List<ModelProvenance>

IModelBillOfMaterialsRepository
  save(m: ModelBillOfMaterials) → void
  find_by_provenance(provenance_id: ModelProvenanceId) → Option<ModelBillOfMaterials>
  find_components_with_known_cve(tenant: TenantId) → List<MBOMComponent>

IAgentOperationalEnvelopeRepository
  save(e: AgentOperationalEnvelope) → void
  find_by_id(id: AgentOperationalEnvelopeId) → Option<AgentOperationalEnvelope>
  find_by_asset(asset_id: AISystemAssetId) → Option<AgentOperationalEnvelope>
  find_active_version_at(asset_id: AISystemAssetId, at: DateTime) → Option<AgentOperationalEnvelope>

IAgentDeviationEventRepository
  save(d: AgentDeviationEvent) → void
  find_by_id(id: AgentDeviationEventId) → Option<AgentDeviationEvent>
  find_unreviewed_by_tenant(tenant: TenantId) → List<AgentDeviationEvent>
  find_by_asset(asset_id: AISystemAssetId, limit: int) → List<AgentDeviationEvent>

IAIComplianceMappingRepository
  save(m: AIComplianceMapping) → void
  find_by_asset(asset_id: AISystemAssetId) → List<AIComplianceMapping>
  find_gaps_by_framework(framework_ref: AIComplianceFrameworkRef, tenant: TenantId) → List<AIComplianceMapping>
```

---

## 12. Outbound Ports

```
IEventPublisher

IInventoryQueryPort (ACL to M22)
  — Resolves AssetRef; source of truth for asset identity, ownership metadata, business criticality
  — AI-SPM never writes to M22 inventory directly except to create a new AIAsset stub on discovery of
    a genuinely new AI service (via IAssetRegistrationPort, below)

IAssetRegistrationPort (ACL to M22)
  — Registers a newly discovered AI service as a new M22 AIAsset (asset_type ∈ AI_* kinds)
  — Used by AIDiscoveryScanCoordinator reconciliation when a discovered service has no matching asset

ICloudDiscoveryQueryPort (ACL to M26)
  — Enumerates AI services present in registered cloud accounts (SageMaker, Vertex AI, Azure OpenAI,
    Bedrock endpoints, GPU compute instances running inference workloads)

IVulnerabilityQueryPort (ACL to M27)
  — Resolves known CVEs for AI framework/library components in a ModelBillOfMaterials

IDetectionRuleQueryPort (ACL to M28)
  — Resolves whether AI-specific detection rules exist for a given AIThreatCategory (informs threat
    profile completeness; does NOT feed a real-time detection stream into ai_agent_governance)

IComplianceQueryPort (ACL to M24)
  — Resolves applicable controls for EU AI Act / NIST AI RMF / ISO 42001 given an AISystemKind and
    DataSensitivityClassification

ISecurityGraphWritePort

IHuggingFaceHubProviderPort
  — Model card metadata, provenance signals, checksum/signature data for HF-hosted models

ICloudAIServiceProviderPort
  — Provider-specific discovery + metadata for SageMaker, Vertex AI, Azure OpenAI Service, AWS Bedrock

IModelRegistryProviderPort
  — MLflow, DVC, Weights & Biases: internal model registry protocol adapters

IMCPServerDiscoveryPort
  — Enumerates reachable MCP servers within registered network/cloud scope

IKubernetesAdmissionQueryPort
  — Detects AI workload pods via admission-controller-recorded metadata (image tags, resource
    requests indicating GPU/accelerator use, known AI framework labels)

INotificationPort
  — Shadow AI alert triage notifications, compliance gap notifications, deviation review notifications
```

---

## 13. Security Graph Ontology Extensions

### New Nodes

| Node Type | Key Properties |
|---|---|
| `AISystemNode` | ai_system_asset_id, ai_system_kind, registration_status, lifecycle_state |
| `ModelProvenanceNode` | provenance_id, model_origin, provenance_integrity_status |
| `AIAgentNode` | ai_system_asset_id, envelope_state, envelope_version |
| `AIThreatNode` | threat_category, exposure_level |

### New Edges

| Edge | From | To | Properties |
|---|---|---|---|
| `EXTENDS_ASSET` | `AISystemNode` | `AssetNode` (M22) | — (links AI-SPM extension record to canonical inventory asset) |
| `DEPENDS_ON_MODEL` | `AISystemNode` | `ModelProvenanceNode` | dependency_type |
| `TRAINED_ON_DATA` | `ModelProvenanceNode` | `DataSourceNode` (or generic reference node where no domain node exists) | lineage_confidence |
| `SERVES_INFERENCE` | `AISystemNode` | `AssetNode` (M22, e.g. an endpoint/host) | protocol |
| `AGENT_AUTHORIZED_FOR` | `AIAgentNode` | `AssetNode` (M22, in-scope resource) | authorized_action_category |
| `HAS_AI_THREAT` | `AISystemNode` | `AIThreatNode` | exposure_level, last_assessed_at |
| `DEVIATED_FROM_ENVELOPE` | `AIAgentNode` | `AIThreatNode` (AgentPrivilegeAbuse-typed) | deviation_severity, detected_at |
| `MAPPED_TO_CONTROL` | `AISystemNode` | `ComplianceControlNode` (M24) | control_status |

---

## 14. Authorization Model

| Role | Permissions |
|---|---|
| `ai_posture:reader` | Read AI system assets, threat profiles, risk scores, compliance mappings, shadow AI alerts (read-only, no triage) |
| `ai_posture:analyst` | All reader + triage shadow AI alerts, annotate threat assessments, review compliance gaps |
| `mlsecops:engineer` | All analyst + register/classify AI system assets, author threat assessments, author Model Bill of Materials, define agent operational envelope drafts |
| `ai_posture:approver` | All mlsecops:engineer + approve AI system asset registration, approve agent operational envelopes, confirm shadow AI resolution |
| `ai_posture:admin` | All approver + manage discovery source configuration, manage risk scoring weights/versions, remove `RequiresHumanApprovalFor` categories from an envelope, decommission AI system assets |
| `ai_posture:auditor` | Read-only: full provenance chain history, compliance mapping history, deviation event history, risk score history — for audit and attestation purposes |

Provenance verification triggering (`ProvenanceVerificationService` on-demand runs) requires `mlsecops:engineer` or above. Agent envelope suspension requires `ai_posture:approver` or above — this is a governance action with immediate operational impact on a running agent's authorized status.

---

## 15. Multi-Tenancy

- All `ai_posture`, `ai_supply_chain`, and `ai_agent_governance` aggregates are tenant-scoped
- `AISystemAsset.AssetRef` must resolve to an M22 `AIAsset` within the same tenant; cross-tenant `AssetRef` resolution is a hard error, not a silent no-op
- Discovery source configuration (cloud accounts, registry endpoints, MCP discovery scope) is tenant-scoped; no shared discovery infrastructure state crosses tenant boundaries
- `AIComplianceFrameworkRef` definitions (the framework/control taxonomy itself) may be platform-published and shared read-only across tenants, following the same distribution model as M28 detection packs and M30 scenario templates — but `AIComplianceMapping` records (the per-asset evaluated status) are always tenant-local
- Shadow AI discovery scans never enumerate resources outside a tenant's registered cloud account scope

---

## 16. Versioning, Concurrency, and Idempotency

### Versioning
- `AgentOperationalEnvelope` uses `EnvelopeVersion`; deviation evaluation always pins the version active at the action timestamp, not the current version
- `AIRiskScoreSnapshot.ScoreInputVersion` tags the scoring model/weights version for reproducibility across scoring model changes

### Concurrency
- `AISystemAsset` lifecycle transitions use optimistic locking
- `AIRiskScoreSnapshot` creation is append-only; no update-in-place, eliminating write contention on the hot read path
- `ShadowAIAlert` deduplication against `DiscoveredServiceFingerprint` uses a database unique constraint plus advisory lock during reconciliation writes to prevent duplicate alert creation from concurrent scan batches

### Idempotency
- `AIDiscoveryScanCoordinator` reconciliation is idempotent by `(discovery_source, external_identifier, tenant)` — re-running a scan against unchanged cloud state produces no duplicate `AISystemAsset` or `ShadowAIAlert` records
- `ProvenanceVerificationService` checksum verification is idempotent: re-verification with an unchanged artifact produces a `ChecksumVerified` event only if the prior status was not already `Verified` with the same checksum (avoids event noise)
- `EnvelopeComplianceEvaluationService` deduplicates deviation evaluation by `(agent_asset_id, action_fingerprint, timestamp)` to avoid duplicate `AgentDeviationEvent` records from retried action reports

---

## 17. Failure Recovery and Compensation

### Discovery Scan Partial Failure
- `AIDiscoveryScan` batches are partitioned per discovery source (per cloud account, per registry). A failure in one partition (e.g., Hugging Face Hub API timeout) does not block reconciliation of other partitions.
- Partial results are committed as `AIAssetReconciliationResult` with an explicit `partial: true` flag and a list of failed partitions; the scan is retried for failed partitions only on the next scheduled run (or on-demand retry)
- A discovery source with N consecutive full-partition failures raises an operational alert (source may be misconfigured or credentials expired) — see Observability §20

### Provenance Verification Failure
- `VerificationFailed` (source unreachable, artifact retrieval error) does not transition `ProvenanceIntegrityStatus` to `Mismatched` — that would be a false-positive supply chain alarm. It remains distinguishable from both `Verified` and `Mismatched`.
- Three consecutive `VerificationFailed` results for the same `ModelProvenance` raise an operational alert distinct from a `ProvenanceIntegrityMismatchDetected` security alert

### Shadow AI False Positive Handling
- `ShadowAIAlert` transitioning to `ConfirmedFalsePositive` requires a `TriageNotes` reason
- Recurring false positives from the same `AIAssetDiscoverySource` + fingerprint pattern feed back into discovery source configuration review (e.g., excluding a known non-AI service that matches a heuristic) — a manual tuning process, not automatic suppression, to avoid masking genuine shadow AI in the same pattern class

### Risk Score Computation Failure
- If `AIRiskScoringService` fails to compute a new snapshot (e.g., dependent ACL unavailable), the previously cached `AIRiskScoreSnapshot` remains the asset's current score but is flagged stale once `StalenessBound` is exceeded — never silently served as current
- Dashboards and read models must surface staleness explicitly; no AI risk score is presented without its computed-at timestamp

### Agent Envelope Evaluation Failure
- If `EnvelopeComplianceEvaluationService` cannot resolve the envelope version active at an action's timestamp (e.g., gap in envelope history), the action is recorded as `ReviewState = UnderReview` with a data-quality flag rather than silently passing or silently failing closed — a human resolves the ambiguity

---

## 18. Observability

### Metrics
- `ai_discovery_scan_duration_seconds` (per discovery source, per tenant)
- `ai_discovery_scan_partitions_failed_total`
- `ai_system_assets_discovered_total` / `ai_system_assets_registered_total` / `shadow_ai_alerts_raised_total`
- `ai_risk_score_computation_duration_seconds`
- `ai_risk_score_staleness_seconds` (gauge, per asset, exported as a distribution for tenant-wide staleness health)
- `model_provenance_verification_duration_seconds`
- `model_provenance_mismatch_total`
- `agent_deviation_events_total` (labeled by `DeviationType`, `Severity`)
- `ai_compliance_gap_total` (labeled by framework)

### Logging
- Every `AIDiscoveryScan` run logs a structured summary: sources scanned, partitions failed, assets discovered, shadow AI candidates raised
- Every `ProvenanceIntegrityMismatchDetected` logs at security-alert level with full checksum comparison detail (previous, current, algorithm) — this is a supply chain security event, not a routine log line
- Every `AgentDeviationEvent` with `Severity ≥ High` logs at security-alert level

### Tracing
- `AIDiscoveryScanCoordinator` scan runs are traced end-to-end per discovery source partition, correlating provider API calls with reconciliation outcomes
- `AIRiskScoringService` computation traces span all upstream ACL calls (M22, M27, M28, M24, ai_supply_chain, ai_agent_governance) to allow attribution of scoring latency and failures to a specific dependency

### Alerting
- Discovery source N-consecutive-failure alert (operational)
- Provenance verification N-consecutive-failure alert (operational)
- `ProvenanceIntegrityMismatchDetected` alert (security, immediate)
- `AgentDeviationEvent Severity = Critical` alert (security, immediate)
- Tenant-wide AI risk score staleness exceeding threshold for >X% of assets (operational health)

---

## 19. Database Strategy

| Aggregate | Storage | Notes |
|---|---|---|
| `AISystemAsset` | PostgreSQL | Moderate volume, scales with M22 inventory; frequent reads |
| `AIThreatProfile` | PostgreSQL | One per asset; moderate update frequency |
| `ShadowAIAlert` | PostgreSQL | Indexed on `(tenant_id, fingerprint)` unique constraint for dedup |
| `AIRiskScoreSnapshot` | PostgreSQL, time-series optimized, partitioned by `(tenant_id, computed_at)` monthly | Append-only; high write volume at scale; latest-snapshot query must be indexed for O(1) lookup |
| `ModelProvenance` | PostgreSQL | Provenance chain entries append-only; low-moderate volume |
| `ModelBillOfMaterials` | PostgreSQL (JSONB component list) | Component list as JSONB for schema flexibility across MBOM component types |
| `AgentOperationalEnvelope` | PostgreSQL | Low volume; versioned rows retained (no hard delete on revision) |
| `AgentDeviationEvent` | PostgreSQL, partitioned by `(tenant_id, detected_at)` monthly | Volume scales with agent action reporting frequency |
| `AIComplianceMapping` | PostgreSQL | Indexed by `(asset_id, framework_ref)` |

---

## 20. Performance Considerations

- **Discovery scans are asynchronous.** `AIDiscoveryScan` runs as a background scheduled job; it never blocks any request-path operation. Per-tenant scan frequency is configurable (default weekly for supply chain / cloud-wide shadow AI sweeps; daily option for high-change environments) with rate limiting and per-provider request budgets to control third-party API cost and avoid provider throttling.
- **AI risk scoring is cache-first with bounded staleness.** `AIRiskScoreSnapshot.StalenessBound` (default 24h, tenant-configurable) governs when `AIRiskScoringService` must recompute. Reads always serve the latest snapshot; recomputation is triggered by a scheduled sweep of assets whose snapshot exceeds `StalenessBound`, plus event-driven recomputation on `AIThreatProfileUpdated`, `ProvenanceIntegrityMismatchDetected`, and `AgentDeviationConfirmed` (events that materially change score inputs).
- **Provenance verification is bounded by artifact retrieval cost.** Large model artifact checksum computation (multi-GB weights files) is streamed, not loaded fully into memory; verification jobs are queued and rate-limited per provider to avoid egress cost spikes.
- **Deviation evaluation is designed for periodic/batch reporting, not a continuous stream.** `EnvelopeComplianceEvaluationService` accepts reported action batches; it is not architected as a low-latency streaming consumer — that pattern belongs to M28.

---

## 21. Scalability Model

### AI Asset Volume
- `AISystemAsset` inventory scales at the same rate as M22 inventory; no independent scaling ceiling is introduced by AI-SPM
- `IAISystemAssetRepository` queries are indexed on `(tenant_id, registration_status)` and `(tenant_id, ai_system_kind)` for dashboard read patterns

### Discovery Scan Cost Management
- Per-cloud-account, per-provider rate limits and request budgets are enforced by `AIDiscoveryScanCoordinator`; a tenant with many cloud accounts scans them in bounded-concurrency batches, not all at once
- Discovery scan partitioning (§17) allows horizontal parallelization across discovery sources without cross-partition coordination

### Provenance Chain Depth
- `ModelProvenanceRepository` chain traversal (fine-tuned-from-fine-tuned-from-base scenarios) is bounded to a configurable maximum depth (default 10 hops) to prevent unbounded graph traversal; deeper chains are truncated with a `chain_truncated: true` flag rather than causing unbounded query cost

### Risk Score Recomputation Throughput
- `AIRiskScoringService` is stateless and horizontally scalable behind a work queue; staleness-sweep recomputation is batched and rate-limited per tenant to avoid thundering-herd recomputation across a large asset estate at the same staleness-bound boundary

---

## 22. Extension Points

| Extension | Mechanism |
|---|---|
| New `AISystemKind` | Add enum value; extend `AISystemClassificationService` taxonomy mapping and `ApplicableThreatCategories` derivation |
| New `AIThreatCategory` | Add enum value; add assessment logic in `AIThreatAssessmentService`; add corresponding `ThreatCategoryAssessment` handling |
| New discovery source | Implement new provider port (follows `IHuggingFaceHubProviderPort` / `ICloudAIServiceProviderPort` pattern); register with `AIDiscoveryScanCoordinator` |
| New compliance framework | M24 extension; referenced via `AIComplianceFrameworkRef`; no ai_posture code change beyond mapping evaluation logic if the framework introduces novel control types |
| New `MBOMComponent` type | Add enum value; extend `ModelBillOfMaterialsBuilder` extraction logic |
| New `DeviationType` | Add enum value; add detection logic in `EnvelopeComplianceEvaluationService` |
| New risk scoring input | Add component to `ScoreComponents`; bump `ScoreInputVersion`; update `AIRiskScoringService` weighting |
| New `AuthorizedActionCategory` | Add enum value; extend envelope authoring UI/validation, no aggregate redesign required |
