# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Hardening Review

**Status:** APPROVED WITH CONDITIONS
**Milestone:** M31
**Date:** 2026-07-21

---

## Executive Summary

M31 introduces the AI-SPM domain across three bounded contexts (`ai_posture`, `ai_supply_chain`, `ai_agent_governance`) plus five new provider integrations. The primary risk categories are: (1) supply chain integrity failures masking a genuine tampering event as a transient infrastructure problem; (2) shadow AI discovery creating a false sense of completeness coverage; (3) AI risk score staleness producing security decisions based on outdated posture data; (4) agent governance becoming a compliance theater if the operational envelope is too permissive or too easily revised; and (5) discovery scan rate limiting and cost management failure. Each is addressed below.

---

## 1. Provenance Verification Failure Must Not Mask Tampering

**Severity: CRITICAL**

`ProvenanceIntegrityStatus` has three terminal or near-terminal states: `Verified`, `Mismatched`, and `VerificationFailed`. The critical risk is that an implementation error (or a deliberate system design shortcut) allows `VerificationFailed` to silently transition to `Verified` on retry without actually detecting a `Mismatched` state. A supply chain attacker who can cause artifact retrieval to transiently fail could theoretically exploit a retry-auto-verify path to avoid detection.

**Required Hardening:**
- `Verified` status requires the explicit event `ChecksumVerified` with `current_checksum` recorded. Any implementation that sets `ProvenanceIntegrityStatus = Verified` without a recorded `current_checksum` value is an architectural violation.
- The transition from `VerificationFailed` to `Verified` must go through the same full checksum computation and comparison path as any first-time verification. There is no shortcut code path that restores `Verified` without computing and comparing the actual hash.
- `ProvenanceIntegrityStatus` transitions must be backed by an append-only `ProvenanceChainEntry` — every status change is auditable, never a silent in-place update to the status column alone.
- Automated tests must cover the specific scenario: (a) `Verified` → `VerificationFailed` → retry → `Verified` after no artifact change (legitimate), and (b) `Verified` → `VerificationFailed` → retry → `Mismatched` (artifact changed between the failure and the retry). Both must produce the correct terminal state.

---

## 2. Shadow AI Discovery Completeness Is Bounded, Not Absolute

**Severity: HIGH**

The batch discovery model (ADR-M31-003) means M31's shadow AI detection is only as complete as the union of its configured discovery sources. An AI service running on hardware not represented in the configured cloud accounts, on a developer laptop, in an on-premise GPU cluster, or via a personal API key not routed through the organization's cloud accounts is invisible to M31's discovery scans.

**Required Hardening:**
- The AI Asset Inventory Dashboard must prominently display the last-scan timestamp, the configured discovery source set, and a "coverage scope" indicator (which cloud accounts, which registries, which Kubernetes clusters are in scope). The dashboard must never imply coverage beyond what was actually scanned.
- Shadow AI Discovery Report must include a "scope of this report" section enumerating discovery sources and their last-successful-scan timestamps. A report that omits its coverage scope is operationally misleading.
- `AIDiscoveryScan` partial results (`partial: true`) must be visibly flagged in the report alongside a list of failed partitions — operators must know which sources were not scanned in a given run.
- Operator onboarding documentation must clearly state: M31 discovers AI in registered cloud accounts and configured registries; it does not discover AI in unregistered on-premise or BYOD environments without additional configuration.

---

## 3. AI Risk Score Staleness Must Not Produce Silent False Confidence

**Severity: HIGH**

The cache-first risk score model (ADR-M31-006) carries an operational risk: a risk score computed before a material event (e.g., a new critical vulnerability in a model's framework, a provenance mismatch, a significant agent deviation) may be served to CISO dashboards for up to `StalenessBound` (default 24h) without appearing stale, if the event-driven recomputation trigger misfires.

**Required Hardening:**
- Every API endpoint that returns an AI risk score must include `computed_at` and `is_stale` (boolean, computed as `now() - computed_at > staleness_bound`) in the response. A client that does not receive these fields has no basis for trusting the score's freshness.
- `AIRiskScoreStalenessExceeded` domain event must be published when `StalenessBound` is exceeded and no new snapshot has been computed. This event feeds the Observability §18 `ai_risk_score_staleness_seconds` gauge.
- Event-driven recomputation on `ProvenanceIntegrityMismatchDetected` must use a guaranteed-delivery event bus path (same outbox pattern as other domain events), not a fire-and-forget notification. If the recomputation job is down when the mismatch event fires, the event must be held for delivery when the job recovers — not silently dropped.
- Stale score alerts (tenant-wide % of stale assets exceeding threshold) must be suppressed during a known scoring service outage and re-evaluated on recovery, to avoid alert storms on recovery.

---

## 4. Agent Operational Envelope Revision Must Not Be an Evasion Path

**Severity: HIGH**

`EnvelopeRevisionAdvisoryService` surfaces revision recommendations when repeated `ConfirmedBenign` deviations accumulate. A governance risk exists: an agent system operator under pressure to reduce deviation alert volume may classify deviations as `ConfirmedBenign` to generate advisory recommendations, then obtain an envelope revision that retroactively expands authorized behavior to cover previously-out-of-scope actions. This makes the envelope a documentation artifact that trails agent behavior rather than constraining it.

**Required Hardening:**
- `ConfirmedBenign` classification must require a documented reason (non-nullable `ReviewNotes`). This reason is retained in the `AgentDeviationEvent` aggregate permanently and is visible in the AI Agent Deviation Report and to auditors via the `ai_posture:auditor` role.
- `ReviewState = EnvelopeUpdated` (closing a deviation by revising the envelope) requires a linked `AgentOperationalEnvelopeRevised` event with the approver identity — closing a deviation ticket via envelope expansion is thus auditably linked to the specific approver who authorized the expansion. This is the same evidence-chain philosophy as M29.
- `RequiresHumanApprovalFor` categories (financial transactions, system administration) may not be removed from an envelope by `mlsecops:engineer` alone — they require `ai_posture:admin`. This role separation means the risk reduction step requires a more senior governance authority, providing a structural barrier to envelope weakening.
- Audit read model must show the full history of an envelope's `RequiresHumanApprovalFor` changes, not just the current state.

---

## 5. Discovery Scan Rate Limiting and Cloud API Cost Management

**Severity: HIGH**

`AIDiscoveryScanCoordinator` calls third-party cloud provider APIs (SageMaker, Vertex AI, Azure OpenAI, Bedrock) and Hugging Face Hub across all of a tenant's configured accounts. Without rate limiting and cost budgeting, a scan across a large enterprise with hundreds of cloud accounts could generate thousands of API calls per scan run, incurring unexpected cloud egress/API costs and potentially hitting provider throttles.

**Required Hardening:**
- Per-cloud-account, per-provider request rate limits must be configurable (per-tenant defaults, with per-source overrides). `AIDiscoveryScanCoordinator` must enforce these limits; scan partitions that would exceed the limit are deferred to the next scan window, not silently dropped.
- Per-scan-run API call budget caps must be enforced (configurable per tenant). If the budget is hit mid-scan, the run is marked `partial: true` and remaining partitions are enqueued for the next run.
- Cloud account enumeration for large tenants (hundreds of accounts) must use bounded-concurrency fan-out (configurable parallelism ceiling, default 5 concurrent account scans), not unlimited parallel dispatch.
- Provider API errors (throttle responses, 429/503) must be retried with exponential backoff with jitter. Unretried provider failures must be recorded as `VerificationFailed` or partition failure, never silently ignored.

---

## 6. ACL Boundary Enforcement: M22 Types Must Never Appear in AI-SPM Domain

**Severity: MEDIUM**

Every prior milestone (M27, M28, M29, M30) documents the same risk: developers taking the shortcut of importing a foreign aggregate directly into the domain layer rather than using the ACL port and translating it into a local value object. For M31 this means: M22's `AIAsset` entity must never be imported into `ai_posture` domain code.

**Required Hardening:**
- `infrastructure/ai_posture/acl/inventory_acl.py` is the only module allowed to import from the M22 domain layer. All other `ai_posture` domain and application code operates only on `AssetRef` (the local value object).
- Code review checklist for M31 implementation must include: "Does any domain or application layer file in `ai_posture`, `ai_supply_chain`, or `ai_agent_governance` import from `redforge.domain.inventory`?" If yes, it is an architectural violation.
- The same constraint applies to `ai_supply_chain` for M26 (`ICloudDiscoveryQueryPort`), M27 (`IVulnerabilityQueryPort`), and to `ai_agent_governance` for M28 (`IDetectionRuleQueryPort`). Only the ACL adapter files in `infrastructure/{context}/acl/` may touch foreign domain types.

---

## 7. Provenance Chain Entry Immutability Must Be Database-Level Enforced

**Severity: MEDIUM**

`ProvenanceChainEntry` records are declared append-only in the aggregate invariants. Application-layer enforcement alone is insufficient — a developer bug or a direct database operation could delete or update a chain entry, undermining the tamper-evident claim.

**Required Hardening:**
- The `provenance_chain_entries` table must have a database-level immutability mechanism: either (a) `INSERT`-only via a PostgreSQL row-level security policy that prohibits `UPDATE` and `DELETE` for the application database user, or (b) at minimum, a database trigger that raises an error on any `UPDATE`/`DELETE` against this table. The approach must be documented in the migration that creates this table.
- `ModelBillOfMaterials` component additions follow the same append-only pattern and require the same database-level protection.
- Backups must preserve this table separately with explicit retention policy, as it constitutes a legally-significant audit trail for supply chain integrity claims.

---

## 8. Compliance Mapping Must Not Be Over-Automated

**Severity: MEDIUM**

`AIComplianceMappingService` evaluates `ComplianceControlStatus` from available evidence. The risk is that automated evidence evaluation produces `Satisfied` status for controls that require human judgment and manual evidence review (e.g., EU AI Act Article 9 risk management system, which requires demonstrating an organizational process, not just the existence of a risk score field in a database).

**Required Hardening:**
- For each compliance framework and control, the architecture must distinguish between controls that are machine-evaluable (the system can determine Satisfied/Gap from data, e.g., "does an AIRiskScore exist for this asset?") and controls that require human attestation (e.g., "has an organizational risk management process been documented and reviewed?"). Machine-evaluable controls may be automatically classified; attestation-required controls must be presented for human review and signature before marking `Satisfied`.
- The `AIComplianceMapping` aggregate must carry a `requires_human_attestation: bool` flag per control mapping, derived from the control's definition in M24's compliance framework catalog.
- Compliance attestation reports produced for audit purposes must clearly label which controls were automatically evaluated and which required human attestation, with the attesting identity and date recorded.

---

## 9. ShadowAIAlert Triage Bottleneck Risk

**Severity: MEDIUM**

`ShadowAIAlert` requires human triage before it can be confirmed or dismissed. In a large enterprise environment with a broad discovery scope, the first scan run may produce hundreds of shadow AI alerts (every AI service that existed before M31 was deployed but was not formally registered). This triage volume could exceed the capacity of the MLSecOps team to process in a reasonable timeframe, leaving a large backlog of `Open` alerts that provide no actionable signal.

**Required Hardening:**
- A bulk triage capability is required: the `ai_posture:analyst` role must be able to bulk-triage a set of alerts sharing a common `AIAssetDiscoverySource` + cloud account + service type pattern (e.g., "all Bedrock endpoints in us-east-1 are known and should be bulk-registered as FormallyRegistered assets").
- M31 should produce a "triage backlog age" metric in the Observability output: how many `ShadowAIAlert` records have been in `Open` state for more than N days. This operational metric surfaces triage bottlenecks to platform administrators.
- Initial deployment guidance must recommend running the first shadow AI sweep in "discovery only" mode (producing a report without raising alert records) to allow operators to understand the scope before formal triage begins.

---

## 10. Agent Action Reporting Transport Is Out of Scope but Must Be Designed For

**Severity: MEDIUM**

M31's `ai_agent_governance` context accepts reported agent actions via `ReportAgentAction` application service. The transport by which actions arrive (webhook, message queue, polling, SDK instrumentation) is declared out of scope for M31. However, if the transport design is deferred entirely, implementations may default to synchronous HTTP calls from agent runtimes — producing tight coupling and availability risk.

**Required Hardening:**
- `ReportAgentAction` application service must be designed for asynchronous ingestion from day one. The service interface must accept batches of actions (not just single actions), and must be idempotent by `(agent_asset_id, action_fingerprint, timestamp)`.
- Even if the Phase 4 implementation uses a simple synchronous HTTP endpoint as the initial transport, the service layer must not assume synchronous delivery — `EnvelopeComplianceEvaluationService` processes actions in the same async manner regardless of how they arrived.
- The transport contract must be documented (e.g., in an API schema) so that agent runtime integrators know what to implement before M36 (which requires this infrastructure operational).

---

## 11. Technical Debt Prevention Rules

1. **`AISystemAsset` never duplicates M22 data.** No field in `ai_posture` stores asset name, ownership, cloud account, environment, or business criticality — all of these resolve via `IInventoryQueryPort`. Any PR that adds such a field to `AISystemAsset` is an architectural violation.
2. **Risk score never computed synchronously.** No request-path handler calls `AIRiskScoringService.compute()` inline. All risk score reads go through `IAIRiskScoreSnapshotRepository.find_latest_by_asset()`.
3. **Checksum verification never reads metadata as a substitute for artifact hash.** Any code path that sets `ProvenanceIntegrityStatus = Verified` without computing and comparing a cryptographic hash of the model artifact is an architectural violation.
4. **`AgentDeviationEvent` evaluation against current envelope version is forbidden.** Evaluation always resolves the envelope version active at `observed_action.timestamp`, not `envelope.latest_version`. Any implementation that uses the current version is incorrect.
5. **`ShadowAIAlert` never auto-transitions from `Open` to `ConfirmedShadowAI`.** Human triage is mandatory. Automated workflows may assist triage (e.g., "high confidence: this service has been running for 30 days and has no registration in any linked system") but may never complete the transition without a human action.
6. **Discovery scan never runs without a per-account rate limit configured.** A `None`/unlimited rate limit is not a valid configuration; if not explicitly set by the tenant, the platform default applies.
7. **Compliance attestation for attestation-required controls is never automated.** Machine-evaluable controls may be auto-classified; attestation controls always surface for human review before `Satisfied` status is recorded.

---

## 12. Open Questions

1. **Provider port credential management:** How are cloud provider API credentials (for SageMaker, Vertex AI, Azure OpenAI, Bedrock) stored and rotated for discovery scan use? This milestone assumes the credentials management infrastructure exists (likely from M26); the M31 implementation plan must verify M26's credential vault is usable for these new provider ports before Phase 3 begins.

2. **MCP server discovery protocol stability:** The MCP server discovery protocol is relatively new; the `IMCPServerDiscoveryPort` interface may need to be revised as the protocol matures. The port interface should be designed with this churn in mind — a thin adapter layer is preferable to deep coupling to a specific protocol version.

3. **Model artifact retrieval for large models:** For foundation models with hundreds-of-gigabytes weight files, streaming checksum computation may still take significant wall-clock time and egress cost. A policy decision is needed: for models above a configurable size threshold, should M31 (a) rely on provider-attested signatures only (`SignatureChainRef`-based), (b) sample a portion of the artifact (note: partial hashing is not a standard integrity guarantee), or (c) accept the full retrieval cost? This decision should be made with the first enterprise customer who operates models of this size, not deferred to an edge case.

4. **Kubernetes admission controller integration authority:** `IKubernetesAdmissionQueryPort` implies either (a) read access to Kubernetes admission controller logs/webhooks, or (b) deploying a RedForge admission webhook into the customer's clusters. The security posture of option (b) — deploying infrastructure into customer clusters — is a significant operational and security decision outside the scope of this architecture document. The implementation plan for Phase 3 must determine which model applies for M31.

---

## 13. Future Considerations

- **M32 integration:** M31's `AIRiskScore` per asset becomes one input signal into M32's unified exposure aggregation. The `AIRiskScoreSnapshot.CompositeScore` and its component breakdown should be designed with M32's consumption model in mind (M32 will consume a score + evidence refs, not raw threat profile data).
- **Real-time agent monitoring (M36):** The `ai_agent_governance` boundary is designed to be extensible toward a real-time streaming model in M36 (AI-native autonomous operations). The `EnvelopeComplianceEvaluationService` interface is transport-agnostic by design; a future streaming adapter would send action events to the same evaluation service without redesigning the domain model.
- **AI governance regulatory evolution:** EU AI Act implementation acts are still being published; NIST AI RMF profiles are being developed for specific sectors; ISO 42001 certification schemes are emerging. `AIComplianceMappingService` and `AIComplianceFrameworkRef` are designed for additive framework extension (via M24) without M31 code changes. However, the `AISystemKind` taxonomy and `ApplicableThreatCategories` mapping may require revision as regulatory scope becomes clearer — particularly around the EU AI Act's "high-risk AI system" classification criteria.
- **Model drift as a provenance signal:** A model whose behavior has significantly drifted from its registered state (even if the weights checksum is unchanged) represents a different kind of provenance concern — behavioral provenance vs. artifact integrity. This is a future capability; M31 owns artifact integrity; behavioral drift monitoring would require M28-level telemetry infrastructure and is out of scope.

---

## Hardening Review Verdict

**Status: APPROVED WITH CONDITIONS**

Pre-conditions before Phase 1 begins:
- [ ] M22 `AIAsset` `AssetRef` ACL pattern reviewed and confirmed compatible with M31's `AISystemAsset` extension model — no M22 schema changes required by M31
- [ ] Database-level immutability mechanism for `provenance_chain_entries` confirmed as implementable in this codebase's migration toolchain before Phase 3 begins
- [ ] Phase 3 provider credential management model confirmed (M26 credential vault reuse or alternative) before external provider port implementation begins
- [ ] Bulk shadow AI triage capability scoped into Phase 5 (or Phase 1 if first-scan volume concerns are significant) — not deferred post-milestone

All conditions enumerated. No blocking architectural flaws in the frozen design.
