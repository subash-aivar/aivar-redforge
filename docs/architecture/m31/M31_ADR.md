# M31 – Enterprise AI Security Posture Management (AI-SPM)
# Architecture Decision Records

**Status:** FROZEN
**Milestone:** M31
**Date:** 2026-07-21

---

## ADR-M31-001: AISystemAsset as Extension of M22 AIAsset, Never Duplication

### Status: ACCEPTED

### Context
`AISystemAsset` needs to carry AI-specific risk attributes (threat profile, compliance mapping, risk score, provenance ref, agent envelope ref) that do not belong in the general-purpose M22 inventory aggregate. Two design options exist: (a) extend M22's `AIAsset` by adding AI-SPM fields into the M22 aggregate, or (b) maintain a separate `AISystemAsset` record in the `ai_posture` context that references the M22 `AIAsset` by `AssetRef` and owns only the AI-SPM-specific data.

### Decision
`AISystemAsset` is a distinct aggregate in the `ai_posture` bounded context. It holds a reference (`AssetRef`) to the canonical M22 `AIAsset` and never duplicates asset identity data (name, ownership, cloud account, environment tags, business criticality) that M22 owns. The `AssetRef` is the ACL boundary: it carries only the fields required by AI-SPM consumers, translated from M22 by `IInventoryQueryPort`.

### Alternatives Considered

1. **Embed AI-SPM fields in M22 `AIAsset`:** M22 is already a generalized inventory aggregate covering AI, network, cloud, and application assets. Embedding AI-SPM-specific fields — threat profile, provenance integrity, agent envelope ref, AI compliance mapping — into M22 would violate M22's established principle (stated in M22 architecture) that `AIAsset` is a pure inventory concept, not a risk or posture concept. It would couple M22's schema evolution to every future AI-SPM model change, and would put AI-posture domain logic inside the inventory context. Rejected.

2. **Separate `AISystemAsset` aggregate in its own context referencing M22 by AssetRef (chosen):** Follows the same pattern established by M27 (`AssetRef` for vulnerability correlation), M28 (`AssetRef` for detection finding correlation), and M29/M30 (`TargetRef` for red team operations). AI-SPM is a consumer of M22 inventory, not an extension of it. Each context evolves independently. M31 schema changes never touch M22 migrations.

3. **Fork a separate AI asset inventory in M31 with no M22 relationship:** Creates two inventories for AI assets — M22 sees them as `AIAsset` records and M31 independently enumerates them. This produces a guaranteed divergence between the canonical inventory and the AI-SPM inventory, breaking the M22 single-source-of-truth principle and making asset deduplication a permanent operational burden. Explicitly prohibited by roadmap section 6 and section 7. Rejected.

### Consequences
- Every `AISystemAsset` requires a valid M22 `AIAsset` to exist first. Discovery flows that find a new AI service must create an M22 `AIAsset` stub (via `IAssetRegistrationPort`) before the `ai_posture` extension record is created.
- Queries that need both M22 inventory data (business criticality, owner) and AI-SPM data (risk score, threat profile) require a join via `AssetRef` — the application layer is responsible for composing these reads from both ACL and AI-SPM repositories. This is the same pattern already used by M27/M30 read models.
- M22 inventory decommission events must propagate to `ai_posture`: if an M22 `AIAsset` is decommissioned, the linked `AISystemAsset` must transition to `Decommissioned` (via event subscription, not a cascading DB delete).

---

## ADR-M31-002: AI Agent Behavioral Envelope Governance is Distinct from M28 Detection Engineering

### Status: ACCEPTED

### Context
Both M28 (Detection Engineering) and M31's `ai_agent_governance` context deal with "detecting bad AI agent behavior." This risks creating a blurred boundary, particularly since M28 already has the ability to define and evaluate detection rules that could in principle be applied to agent activity. The roadmap explicitly calls this out as a boundary risk (section 14, third bullet).

### Decision
`ai_agent_governance` owns declarative behavioral envelope governance: a human-authored, human-approved declaration of what an AI agent is authorized to do, against which reported/observed agent actions are evaluated. M28 owns telemetry-based technical detection: ingestion of real-time security event streams, rule-driven detection, and security finding production across the full enterprise estate.

The boundary is:
- **M28:** Sees telemetry (log events, network flows, process events), applies detection rules, produces `DetectionFinding` with MITRE ATT&CK technique mapping. Source-agnostic — it would process agent-produced events the same way it processes human-produced events. Operates at security-event granularity in near-real-time.
- **M31 `ai_agent_governance`:** Sees reported agent actions (what the agent said it did, or what its orchestration framework reported), evaluates them against a declared operational envelope specific to that agent system, and produces `AgentDeviationEvent` when the action falls outside the declared bounds. Operates at business-action granularity on a periodic/batch basis or on report receipt.

M28 may additionally have detection rules for AI-agent-specific MITRE ATT&CK techniques (e.g., prompt injection telemetry signatures). Those detections are M28's domain. M31 does not duplicate them; it references the M28 rule catalog via `IDetectionRuleQueryPort` to inform whether a threat category has detection coverage (for threat profile completeness), but never ingests the resulting `DetectionFinding` stream as input to deviation evaluation.

### Alternatives Considered

1. **Treat agent deviation detection as a subclass of M28 detection rules:** Define a new `DetectionRuleKind = AgentEnvelopeRule` in M28 and evaluate envelope compliance there. Rejected because: (a) M28 rules operate on telemetry, not on declared behavioral envelopes; the evaluation model is fundamentally different; (b) the envelope authoring and approval workflow (requiring `mlsecops:engineer` and `ai_posture:approver`) is a distinct governance flow from M28 detection pack publication; (c) envelope versioning and historical evaluation (evaluating an action against the envelope active at the time, not the current envelope) is a concern with no equivalent in M28's detection model.

2. **Merge `ai_agent_governance` into `ai_posture` as a subdomain without a separate context:** Possible for a small implementation, but the `AgentOperationalEnvelope` lifecycle, versioning, approval workflow, and deviation evaluation are sufficiently distinct from asset discovery, threat profiling, and risk scoring that merging them into a single aggregate root would produce an oversized `ai_posture` context with conflicting lifecycle concerns. Keeping it as a supporting context with its own aggregates and domain services is cleaner and matches the 3-context structure declared in the roadmap.

3. **Separate bounded context with its own dedicated telemetry integration (full streaming agent monitoring):** Would produce a proper real-time agent monitoring system, but this is out of scope for M31 and crosses into LLM observability platform territory — explicitly called out as non-goal in roadmap section 7. M31 monitors declared envelopes against reports; real-time telemetry monitoring is a future concern, potentially in M36 (AI-native autonomous operations).

### Consequences
- `EnvelopeComplianceEvaluationService` never directly receives M28 `DetectionFinding` events as input. If a future milestone requires coupling agent compliance to M28 detections, that is a new integration — not a revision of this decision.
- The transport by which agent actions are reported to M31 (the actual agent runtime, orchestration framework, MCP protocol events) is deliberately out of scope for M31. M31 defines the `ReportAgentAction` application service interface; the transport adapter is a Phase 4 implementation concern that may use polling, webhooks, or a message queue — but the domain model is transport-agnostic.
- M28 rules for AI-specific attack patterns (prompt injection signatures, inference API abuse rates) are M28's domain and are authored and managed there. M31 references M28 rule existence via ACL only, never modifying M28 content.

---

## ADR-M31-003: Shadow AI Discovery is Batch, Not Real-Time

### Status: ACCEPTED

### Context
Shadow AI discovery requires enumerating AI services across an enterprise's cloud accounts, Kubernetes clusters, model registries, and MCP server networks. Two architectural patterns are available: (a) continuous/streaming discovery that detects new AI service deployments as they happen, or (b) periodic batch discovery sweeps.

### Decision
Shadow AI discovery runs as a scheduled batch sweep (`AIDiscoveryScanCoordinator`). Default cadence is weekly for cost-bounded cloud-wide sweeps, with a daily option for high-change environments. There is no real-time continuous discovery stream in M31.

### Alternatives Considered

1. **Continuous real-time discovery via cloud provider event streams (e.g., CloudTrail for SageMaker endpoint creation):** Would detect shadow AI within minutes of deployment. However: (a) this requires persistent cloud event stream subscriptions and complex event routing — an infrastructure capability that M26 (Cloud Platform) owns; M31 is not positioned to own cloud event stream infrastructure; (b) the governance use case (CISO-level shadow AI visibility) does not require real-time detection — a weekly sweep satisfies the roadmap's success criterion ("identify at least one previously unknown AI deployment within the first week"); (c) real-time stream ingestion at cloud scale is orders of magnitude more expensive in API calls, compute, and storage than batch sweeps. Deferred to a future milestone or as an M26 integration enhancement.

2. **Periodic batch sweep (chosen):** Matches the "posture management" paradigm (point-in-time assessments on a schedule), is cost-bounded and rate-limitable, is simpler to implement reliably (no streaming infrastructure), and is sufficient for the stated business value. The discovery scan coordinator manages rate limiting, cost budgeting, and partial failure recovery — all tractable in a batch model.

3. **On-demand discovery only (no scheduled sweep):** Requires CISO to manually trigger sweeps; does not deliver continuous posture management. Rejected as insufficient for the product promise.

### Consequences
- A newly deployed AI service may not appear in the inventory for up to one scan cadence period (default 7 days). This is a known and acceptable latency for a posture management product; it must be documented in operator guidance.
- The `AIDiscoveryScan` lifecycle (started, partitions, results, partial failure) is a first-class domain concern with its own observability (see Architecture Freeze §18) precisely because a batch process's failure modes require operational visibility that a streaming consumer would not.
- If a tenant needs near-real-time shadow AI detection, the architectural extension point (§22) is: integrate with M26 cloud event streaming once M26 adds that capability, and publish `ShadowAIAlert` via that event path. The batch sweep remains the baseline path; the streaming path becomes an optional enhancement.

---

## ADR-M31-004: Model Provenance Integrity via Cryptographic Checksum, Not Metadata Trust

### Status: ACCEPTED

### Context
Establishing that a model artifact has not been tampered with can be done in two ways: (a) trust the provider-reported metadata (version string, model card hash, registry entry), or (b) independently compute a cryptographic checksum of the model artifact and compare it to the previously recorded (or provider-attested) checksum.

### Decision
Model provenance verification uses independent cryptographic checksum computation of model artifacts where the artifact is directly retrievable (SHA-256 or SHA-512 of the weights file(s)). Provider-reported metadata (filenames, version strings, registry claims) is recorded but never treated as a verification proof. Where a model artifact is not directly retrievable (e.g., a closed foundation model API with no downloadable weights), the provider's cryptographic signature chain is recorded as `SignatureChainRef`-based verification, and the verification evidence explicitly notes the provenance limitation.

This follows the same tamper-evidence philosophy as M29's execution evidence chain (append-only, cryptographically-grounded, human-auditable).

### Alternatives Considered

1. **Trust provider-reported metadata (filename, version, model card hash claimed by the provider):** Simple to implement; no artifact retrieval cost. However, this is trivially bypassable: a supply-chain attacker who controls a model registry entry can change the weights while keeping the version string intact. For a supply chain integrity claim, the provenance record must be grounded in evidence the attacker cannot trivially forge — hence cryptographic checksum. Rejected.

2. **Cryptographic checksum of model artifact (chosen):** Computationally expensive for large models (multi-GB weights files), but tractable with streaming hash computation and scheduled/asynchronous execution. Produces a non-forgeable integrity assertion. Consistent with established M29 evidence chain philosophy.

3. **Third-party model signing service (e.g., Sigstore for ML models):** Correct approach where available; recorded as `SignatureChainRef` in the data model. However, this capability is not universally available across the provider ecosystem today (Hugging Face Hub, SageMaker, Bedrock all have different and evolving attestation mechanisms). M31's model makes this additive: where a signature chain is available, it is recorded alongside the independently computed checksum; where it is not, the checksum is the sole verification mechanism.

### Consequences
- Checksum computation of large models requires streaming computation and is executed asynchronously in a background job (never in a request path).
- `VerificationFailed` (artifact retrieval failure, hash computation error) is explicitly distinguished from `Mismatched` (hash computed, mismatch found). A network outage produces a `VerificationFailed`; a tampered artifact produces a `Mismatched`. These are operationally and security-wise different events and must never be conflated.
- Providers that offer only closed APIs (no artifact download) receive `SignatureChainRef`-based verification with a documented trust-level caveat. This is the correct representation for the current state of AI supply chain tooling — overstating confidence in closed-API provenance would be architecturally dishonest.

---

## ADR-M31-005: Three Bounded Contexts Rather Than One or Five

### Status: ACCEPTED

### Context
M31 covers three related but distinct concerns: (1) AI asset posture and risk, (2) model supply chain integrity, and (3) AI agent behavioral governance. These could be structured as one monolithic context, as three contexts (as chosen), or as five or more finer-grained contexts.

### Decision
Three bounded contexts: `ai_posture` (core), `ai_supply_chain` (supporting), `ai_agent_governance` (supporting). This is the structure declared in the roadmap (section 8).

### Alternatives Considered

1. **One monolithic `ai_security` context:** Places `AISystemAsset`, `ModelProvenance`, `ModelBillOfMaterials`, `AgentOperationalEnvelope`, `AgentDeviationEvent`, `ShadowAIAlert`, `AIRiskScoreSnapshot`, and `AIComplianceMapping` in a single aggregate root or a single application service layer. Tractable at M31 scale but would create a context with 8+ aggregate roots, heterogeneous lifecycle concerns, conflicting update frequencies (risk scores update daily; envelopes update rarely; provenance chains update on model publication; deviation events update on agent action reports), and a very large set of outbound ports. By M32–M33 integration this would become an unmaintainable boundary. Rejected.

2. **Three contexts (chosen):** `ai_posture` owns the core asset-risk-compliance domain. `ai_supply_chain` owns the tamper-evident model origin and integrity domain — a distinct concern with its own providers, its own verification lifecycle, and its own audit trail requirements separate from general posture. `ai_agent_governance` owns the behavioral boundary and deviation domain — distinct governance workflow (envelope approval, version history, deviation review), distinct evaluation model (declarative vs. telemetry-based), and distinct personas (MLSecOps engineer vs. posture analyst).

3. **Five+ finer contexts (e.g., separate `ai_discovery`, `ai_risk_scoring`, `ai_compliance`, `model_provenance`, `model_mbom`, `agent_envelope`, `agent_deviation`):** Introduces excessive inter-context coupling: `ai_risk_scoring` would need to synchronously call `ai_compliance` and `ai_discovery` and `model_provenance` and `agent_deviation` to compute one score. The aggregation points — `AIRiskScore` composition, `AISystemAsset` lifecycle — naturally belong to `ai_posture` as the core context. Over-partitioning here would produce chatty, tightly-coupled micro-contexts that share more than they separate. Rejected.

### Consequences
- `ai_posture` depends on both `ai_supply_chain` and `ai_agent_governance` via ACL ports (no direct aggregate imports) for risk score computation inputs. The dependency direction is one-way: `ai_posture` → reads from `ai_supply_chain` and `ai_agent_governance`; those contexts never call back into `ai_posture`.
- `ai_supply_chain` has its own outbound provider ports (Hugging Face, cloud AI service APIs, model registries, MCP discovery, Kubernetes admission) — it does not route these through `ai_posture`. This is appropriate: supply chain data collection is a distinct integration concern from posture assessment.

---

## ADR-M31-006: AI Risk Score Is Cache-First with Event-Driven Recomputation on High-Signal Events

### Status: ACCEPTED

### Context
`AIRiskScore` computation requires calling multiple ACL-backed services: M22 (business criticality), M27 (MBOM CVE flags), M28 (detection rule coverage), `ai_supply_chain` (provenance integrity), `ai_agent_governance` (deviation frequency). Computing this on demand in a request path would introduce multi-service latency with cascading failure risk on every dashboard load. The question is how to make scores available at read time while ensuring freshness is bounded and observable.

### Decision
`AIRiskScoreSnapshot` is written asynchronously and served cache-first. Reads always return the latest stored snapshot. Freshness is governed by `StalenessBound` (default 24h, tenant-configurable). Recomputation is triggered by two mechanisms: (1) a scheduled staleness sweep that finds assets whose latest snapshot has exceeded `StalenessBound`, and (2) event-driven recomputation when a high-signal event occurs (`AIThreatProfileUpdated`, `ProvenanceIntegrityMismatchDetected`, `AgentDeviationConfirmed`). A stale score is surfaced as stale — never served without its `computed_at` timestamp and a staleness flag.

### Alternatives Considered

1. **Synchronous on-demand computation at read time:** No staleness problem; score always reflects current state. However, a single risk score read would block on 5+ ACL calls, each potentially 50–200ms; combined latency for an inventory dashboard of 100+ assets would be 5–20 seconds per load. Failure of any one dependency (M28 unreachable) would return a 503 to the CISO dashboard. Rejected.

2. **Cache-first with periodic staleness sweep only (no event-driven recomputation):** Simpler to implement. A critical event (`ProvenanceIntegrityMismatchDetected`) could take up to 24h to surface in the risk score — an unacceptably long lag for a security event. Rejected as insufficient for high-severity supply chain signals.

3. **Cache-first with event-driven recomputation on ALL events (chosen variant rejected):** Recomputing on every `AIComplianceMappingRecorded`, `ShadowAIAlertRaised`, etc. would produce near-continuous recomputation for active tenants. Rate limiting the event-driven path is possible but complicates the design. Instead: event-driven recomputation is triggered only for the defined high-signal event set that materially changes the score. Routine events (ownership changes, label updates) wait for the next staleness-sweep cycle.

4. **Cache-first with staleness sweep + high-signal event-driven recomputation (chosen):** Balances freshness requirements against compute cost. High-severity score-affecting events (threat profile change, provenance mismatch, confirmed agent deviation) trigger immediate recomputation. Routine updates wait for the scheduled sweep. The staleness flag on the snapshot ensures no score is silently stale.

### Consequences
- Every dashboard and read model that displays an AI risk score must display `computed_at` and a staleness flag alongside the score value. This is a UI/API contract requirement, not just a nice-to-have.
- `ScoreInputVersion` enables future score model upgrades: when the scoring weights change, existing snapshots' `ScoreInputVersion` differs from the new model — tenants can opt to recompute all assets or accept the mixed-version state temporarily. This is explicitly tracked in the snapshot aggregate.

---

## ADR-M31-007: AIDiscoveryScanCoordinator as a Domain Service, Not Infrastructure Scheduler

### Status: ACCEPTED

### Context
The `AIDiscoveryScan` batch process could be implemented as a pure infrastructure concern (a cron job or Celery task that calls provider APIs and inserts records). Alternatively, the scan's lifecycle, partitioning, and result records can be treated as domain concepts with their own events and governance.

### Decision
`AIDiscoveryScanCoordinator` is a domain service in `ai_supply_chain`, and `AIDiscoveryScan` runs are recorded as domain events. Scan lifecycle (started, partitions, partial/complete result, failed partitions) is observable via domain events, not only via infrastructure logs. The `ai_discovery_scan_runs` table (see Implementation Plan Phase 3) is a first-class persistence artifact, not a log table.

### Alternatives Considered

1. **Pure infrastructure scheduled task (Celery/APScheduler job with no domain events):** Simpler initially. However: (a) scan partial failures, retry tracking, and consecutive-failure alerting require persistent domain state; (b) the `ShadowAIDetectionService` in `ai_posture` needs to consume the reconciliation result — a clean consumption path requires a domain event, not a database trigger or direct repository call across bounded contexts; (c) operational visibility into discovery health (are scans running? are partitions failing?) requires the domain-event-backed metrics described in Observability §18. Without domain events, this visibility is only achievable via log parsing. Rejected.

2. **Domain service with scan lifecycle domain events (chosen):** Allows `ShadowAIDetectionService` to subscribe to `AIDiscoveryScanCompleted` event, enables retry tracking via `AIDiscoveryScanPartitionFailed` event, and provides the observability metrics backing. Consistent with how M29/M30 treat complex coordinated processes (engagement lifecycle, campaign execution) — they are always domain concerns, not infrastructure concerns.

### Consequences
- Discovery scan runs produce domain events consumable by any future subscriber, not only `ShadowAIDetectionService`. A future capability (e.g., M33 analytics platform wanting scan frequency and coverage metrics) can subscribe without modifying M31's implementation.
- The domain service nature of `AIDiscoveryScanCoordinator` means it has an associated outbox and its events participate in the same `IEventPublisher` infrastructure as all other bounded context events in this platform.

---

## ADR-M31-008: AgentOperationalEnvelope Uses Envelope Versioning, Not Event Sourcing for History

### Status: ACCEPTED

### Context
`AgentOperationalEnvelope` must retain historical versions so that `AgentDeviationEvent` evaluation can pin to the version active at the time of the observed action. Two mechanisms can provide this: (a) full event sourcing of the envelope aggregate (rehydrate from events to any point in time), or (b) explicit version rows (each revision is a new persisted row with `envelope_version` increment, old rows retained).

### Decision
Explicit version rows: each `AgentOperationalEnvelope` revision is persisted as a new row in the `agent_operational_envelopes` table with an incremented `EnvelopeVersion`. Rows are never hard-deleted. The active version is the highest `EnvelopeVersion` where `EnvelopeState = Active`. Historical versions remain queryable by `(asset_id, envelope_version)`.

### Alternatives Considered

1. **Full event sourcing of `AgentOperationalEnvelope`:** Clean for time-travel queries; consistent with the platform's general event sourcing pattern for aggregates where history is critical. However, envelope aggregates have very low mutation frequency (revisions are infrequent governance actions, not high-volume events) and the historical query pattern is simple (find the version active at a given timestamp, not arbitrary state reconstruction). Full event sourcing adds upcaster chain complexity for a low-frequency aggregate with a simple history need. Rejected.

2. **Explicit version rows (chosen):** Simpler, directly queryable by timestamp and version. `IAgentOperationalEnvelopeRepository.find_active_version_at(asset_id, at)` is a straightforward SQL query: `SELECT * FROM agent_operational_envelopes WHERE asset_id = ? AND approved_at <= ? ORDER BY envelope_version DESC LIMIT 1`. No rehydration required. Historical rows are never deleted (immutability guaranteed by a database-level policy, not application logic).

### Consequences
- The `EnvelopeState` column is meaningful only on the current row for `Active`/`Suspended`/`Retired` — historical rows will have `Active` in their row but are no longer the active version. Query logic must use `envelope_version DESC LIMIT 1` to find the current version, not `WHERE state = Active` (which would be ambiguous if the current state is `Suspended` but older rows had `Active`). This constraint is documented in the repository interface spec and enforced by the repository implementation.
- `EnvelopeRevisionAdvisoryService` queries only the current version's deviation history; it never needs to rehydrate historical envelope states.
