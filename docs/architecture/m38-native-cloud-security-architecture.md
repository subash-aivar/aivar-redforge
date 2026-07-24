# M38 — RedForge Native Cloud Security: Frozen Enterprise Architecture Specification

Status: **Architecture only. No code, migrations, APIs, or UI in this milestone.**

## 0. Vision

RedForge Cloud Security is a native CNAPP-class capability — not a wrapper around Wiz/Prisma Cloud/Defender for Cloud/Orca/Lacework — built on the same DDD/Clean-Architecture/CQRS/multi-tenant foundation already frozen across 32+ bounded contexts, and designed from day one to interoperate with two other frozen platform capabilities that most CNAPP products bolt on as an afterthought: a **native SIEM** (M37) and a **native AI Security Foundation**. Its job: continuously discover every cloud resource across every provider, model it as one graph, find what's misconfigured/over-privileged/exposed/reachable-by-an-attacker, and prioritize all of it by real business risk — durably, tenant-isolated, multi-cloud, at enterprise scale.

## 1. Bounded Context Structure

Following the same reasoning as M37 (split by scaling/consistency profile, not by org chart), and explicitly avoiding rebuilding what Integration Hub/Asset Inventory/Knowledge Graph/Risk Engine already do:

| Bounded Context | Responsibility | Why separate |
|---|---|---|
| `cloud_inventory` | Multi-provider cloud resource discovery orchestration, resource lifecycle | Provider-adapter churn independent of graph/posture logic; **built on Integration Hub's discovery engine, not a reimplementation** (§11) |
| `cloud_graph` | Resource graph construction: relationships, ownership, trust, identity links, network topology, cross-account edges | Graph *construction* from cloud-specific semantics is a distinct concern from the platform's generic Knowledge Graph, which it feeds into (§11) |
| `cspm` | Misconfiguration detection, benchmark/policy evaluation (CIS/NIST/ISO/SOC2/HIPAA/PCI-DSS/custom) | Policy authoring/versioning lifecycle, independent of graph construction |
| `ciem` | IAM/permission graph analysis, privilege analysis, toxic combinations, least-privilege recommendations | Permission-graph algorithms have a fundamentally different data shape (identity/policy graph, not resource graph) and different update cadence than `cloud_graph` |
| `cwpp` | Compute/VM/container/Kubernetes/serverless posture | Workload-runtime posture has its own discovery cadence (often agent- or scan-based, not API-poll-based like `cloud_inventory`) |
| `cloud_attack_path` | Reachability, identity paths, lateral movement, public exposure, privilege escalation path computation | Graph-traversal-heavy, computationally distinct from `cloud_graph`'s construction concern — **consumes** the graph, doesn't build it |
| `cloud_exposure` | Internet/identity/data/secrets/AI exposure aggregation | A cross-cutting read/aggregation concern over `cloud_graph` + `ciem` + `cwpp` output, not new discovery |
| `cloud_findings` | Finding lifecycle, suppression, exceptions, evidence linkage | Same reasoning as SIEM's `siem_alerting` vs. `incident` split — findings lifecycle is a workflow concern distinct from the detection/analysis contexts that produce candidate findings |
| `cloud_compliance` | Benchmark-to-control mapping, compliance posture reporting | Read/reporting concern over `cspm` output, same shape as `exposure`/`exposure_reporting`'s existing split |

**Explicitly not separate bounded contexts** (reused, per the "no duplicated abstractions" instruction):
- **Resource risk scoring** → delegated to the platform's existing **Risk Engine Foundation**, not a `cloud_risk` context. `cspm`/`ciem`/`cwpp`/`cloud_attack_path` all *feed* Risk Engine; none of them computes a final risk score itself.
- **Finding storage/evidence** → `cloud_findings` is a thin lifecycle/workflow layer; actual evidence payloads route through the existing Evidence bounded context, exactly as M37 did.
- **Cloud events as SIEM input** → not a new event pipeline; `cloud_inventory`/`cspm`/`cwpp` publish domain events that M37's `siem_ingestion` consumes as a `cloud` category source, reusing M37's Canonical Event Model rather than inventing a parallel one.

**Shared kernel**: `cloud_shared` — provider-agnostic value objects only (`CloudProvider` enum, `CloudResourceIdentity`, `CloudAccountRef`) — mirrors `redforge/shared/identifiers.py`'s role, and M37's `siem_shared`: the one cross-context dependency every Cloud Security sub-context may take, containing no behavior.

## 2. Domain Model

### 2.1 Canonical Cloud Resource Model — the shared kernel

Exactly as M37 mandated one Canonical Event Model so "no module downstream of normalization understands a vendor schema," Cloud Security mandates one **Canonical Cloud Resource (CCR)** shape so no bounded context downstream of `cloud_inventory` understands an AWS/Azure/GCP/OCI/Kubernetes-specific resource shape. This is the direct cloud-domain equivalent of Integration Hub's `DiscoveredAsset`/`AssetIdentity` — and in fact **is** an extension of it, not a parallel model (§11): `CloudResource` is a specialization of Integration Hub's `DiscoveredAsset` aggregate, adding cloud-specific value objects, not a new asset concept competing with it.

`CloudResource` (aggregate, extends `DiscoveredAsset`'s existing shape):
- `resource_id: EntityId` (ULID, same identifier convention as everything else post-ADR-0005)
- `tenant_id: EntityId`
- `identity: CloudResourceIdentity` (value object: `provider: CloudProvider` [aws|azure|gcp|oci|kubernetes|saas], `native_id: str` [ARN/resource-id/URI], `account_ref: CloudAccountRef`, `region: str | None`)
- `resource_type: CloudResourceType` (a versioned, extensible taxonomy — not a flat enum; see §2.3)
- `configuration: dict[str, Any]` (raw-but-normalized-key configuration snapshot; **not** the full unfiltered vendor payload — an explicit, documented allow-list convention, since this exact gap — "no allow-list, copy-everything-except-id" — was a confirmed finding in this session's own Integration Hub audit and is deliberately not repeated here at cloud scale, where configuration payloads are far larger and more likely to contain sensitive fields)
- `ownership: ResourceOwnership` (value object: `owner_identity_ref: EntityRef | None`, `managed_by: str | None` [IaC tool/team tag])
- `discovery_provenance: DiscoveryProvenance` (source connector, discovery timestamp, last-sync — same fields Integration Hub's `DiscoveredAsset` already has, inherited not re-declared)
- `posture_refs: PostureRefs` (value object bundling *references* to the latest `cspm`/`ciem`/`cwpp` evaluation results for this resource — **not** the scores themselves inline; `CloudResource` never holds a risk score directly, exactly matching M37's and Integration Hub's principle that domain aggregates reference evaluation state, they don't own the evaluation)

### 2.2 Aggregates (beyond `CloudResource`)

- **`CloudAccountEnrollment`** (`cloud_inventory`) — provider account/subscription/project onboarding lifecycle (enrolled → syncing → active → degraded → disabled), **directly analogous to Integration Hub's `ConnectorRegistration`**, and in fact implemented as one: a cloud account enrollment *is* a `ConnectorRegistration` of a specific `ConnectorType`, not a new registration concept (§11).
- **`ResourceGraphSnapshot`** (`cloud_graph`) — a versioned, point-in-time graph materialization (nodes = `CloudResource` refs, edges = typed relationships: `OWNS`, `USES`, `TRUSTS`, `CONNECTED_TO`, `MEMBER_OF`, `AUTHENTICATES_WITH` — the exact same `RelationshipType` vocabulary Integration Hub's `AssetRelationship` already defines, reused verbatim, not redefined). Graph snapshots are append-only/versioned (never mutated in place) so historical drift/diff is queryable — the same "findings are regenerable, evidence is immutable" principle from ADR-0003, applied to graph state.
- **`PermissionGraphSnapshot`** (`ciem`) — identity→policy→resource edges, versioned separately from `ResourceGraphSnapshot` since IAM policy evaluation (especially cross-account assume-role chains) has a different computation model (policy-language evaluation) than resource-relationship discovery.
- **`PolicyEvaluationRun`** (`cspm`) — a bounded execution of one or more benchmark/policy evaluations against a resource set, analogous to Integration Hub's `SyncRun` (checkpoint/resume/partial-success shape reused wholesale, not redesigned — CSPM evaluation at enterprise scale has the identical "thousands of resources, must be resumable/paginated" shape M37 and Integration Hub Phase 2C already solved).
- **`AttackPathGraph`** (`cloud_attack_path`) — a computed, versioned traversal result (not a live/interactive graph-query surface — see §6) over a specific `ResourceGraphSnapshot` + `PermissionGraphSnapshot` pair.
- **`CloudFinding`** (`cloud_findings`) — lifecycle aggregate: `OPEN → (SUPPRESSED | EXCEPTED) → REMEDIATED → CLOSED | REOPENED`, deliberately modeled the same way M37's `Alert` was: a pipeline-output workflow object, distinct from the platform's generic `Findings` concept the same way M37 kept `Alert` distinct from `Incident` (§11).

### 2.3 Value Objects

- `CloudResourceType` — a **versioned, extensible taxonomy**, not a flat enum (unlike Integration Hub's simpler `AssetCategory`) — cloud resource types number in the hundreds-to-thousands across providers and grow constantly; modeled as `(provider, service, type_name, taxonomy_version)` so new resource types are additive data, never a code change or enum edit. This is a deliberate scale-driven deviation from Integration Hub's simpler enum, justified explicitly rather than copied blindly.
- `Exposure` (value object: `exposure_type` [internet|identity|data|secrets|ai], `path_ref: AttackPathGraph ref | None`, `severity`) — used by `cloud_exposure`.
- `PrivilegeFinding` (value object: `principal_ref: EntityRef`, `permission_set`, `is_excessive: bool`, `toxic_combination_ref: ToxicCombination | None`) — used by `ciem`.
- `BenchmarkControl` (value object: `framework` [CIS|NIST|ISO27001|SOC2|HIPAA|PCI_DSS|custom], `control_id`, `version`) — used by `cspm`/`cloud_compliance`.

### 2.4 Domain Events

- `CloudAccountEnrolled`, `CloudAccountSyncCompleted`, `CloudAccountDegraded` (inventory — mirrors Integration Hub's connector/sync event shape exactly)
- `ResourceDiscovered`, `ResourceConfigurationChanged`, `ResourceDeleted` (inventory — mirrors `AssetDiscovered`/`AssetModified`/`AssetRemoved`)
- `GraphSnapshotComputed`, `GraphDriftDetected` (graph)
- `PermissionGraphComputed`, `ExcessivePermissionDetected`, `ToxicCombinationDetected` (ciem)
- `PolicyEvaluationCompleted`, `MisconfigurationDetected` (cspm)
- `WorkloadPostureEvaluated` (cwpp)
- `AttackPathComputed`, `CriticalPathDetected` (cloud_attack_path — `CriticalPathDetected` is the highest-signal event in the whole context: internet-exposed + privilege-escalation-reachable + high-business-impact, a genuine trillion-dollar-scale detection signal, not a generic finding)
- `ExposureAggregated` (cloud_exposure)
- `CloudFindingOpened`, `CloudFindingSuppressed`, `CloudFindingExcepted`, `CloudFindingRemediated`, `CloudFindingReopened` (findings)

All published through the platform's real event dispatcher (M37's ADR-level correction of Integration Hub's originally-inert event sink is inherited here as the baseline, not re-litigated) — every one of the above is a genuine pub/sub event with at least one real subscriber named in §9/§11, never constructed-and-discarded.

### 2.5 Commands / Queries (CQRS)

Write side: `EnrollCloudAccount`, `RunResourceDiscovery` (delegates to Integration Hub, §11), `ComputeResourceGraph`, `ComputePermissionGraph`, `RunPolicyEvaluation`, `ComputeAttackPaths`, `OpenCloudFinding`, `SuppressCloudFinding`, `ExceptCloudFinding`, `RemediateCloudFinding`.

Read side (served by denormalized read-models, never the write-optimized graph/inventory store directly — same discipline M37 committed to): `SearchCloudResources`, `GetResourceGraph`, `GetPermissionGraph`, `GetAttackPathsForResource`, `GetExposureSummary`, `GetComplianceScorecard`, `GetFindingQueue`, `GetRiskRankedResources`.

## 3. Cloud Asset Inventory

**Built on Integration Hub, not parallel to it.** Each provider (AWS, Azure, GCP, OCI, Kubernetes, SaaS) is a `ConnectorPlugin` in the existing Integration Hub connector framework, using the exact paginated `DiscoveryPage`/cursor/checkpoint contract M37... no — established in Integration Hub Phase 2C, extended (not redesigned) to carry `CloudResource`-shaped normalized output. `cloud_inventory`'s only real responsibility is registering the cloud-specific `INormalizer` implementations (one per provider) against Integration Hub's existing `NormalizerRegistry`, plus cloud-specific enrollment UX/policy (e.g. AWS Organizations/multi-account enrollment, Azure management-group enrollment, GCP folder/project enrollment, Kubernetes cluster registration) that doesn't fit Integration Hub's simpler single-credential-per-connector model and therefore needs its own thin enrollment aggregate (`CloudAccountEnrollment`, §2.2) sitting *on top of* `ConnectorRegistration`, not replacing it.

This is the single most important architectural commitment in this document: **Cloud Security does not reimplement discovery, pagination, normalization registration, or sync/checkpoint machinery** — it is the second production consumer (after the 3 existing AI-provider connectors) of everything Integration Hub Phase 2A/2B/2C already built, which is exactly the payoff that work was designed to enable.

Kubernetes and SaaS resources use the same connector/normalizer shape; Kubernetes's higher-frequency, often-push-based (watch API) discovery pattern is accommodated the same way M37 kept push-based agent sources architecturally distinct from pull-based connector sources (§3 of M37) — a Kubernetes cluster connector can implement a streaming/watch-based `discover` variant without forcing every other provider into that shape.

## 4. Cloud Graph Engine

`cloud_graph` computes `ResourceGraphSnapshot`s from `CloudResource` data plus provider-specific relationship inference (e.g. an EC2 instance's security-group/subnet/IAM-role edges; an Azure VM's NSG/VNet/managed-identity edges). It **feeds** the platform's existing Knowledge Graph as a new node/edge-source (exactly as M37 extended Knowledge Graph rather than building a parallel one, §7 of M37) — `cloud_graph` is the cloud-domain-specific *construction* logic; Knowledge Graph is the platform-wide *storage/query* substrate. This split mirrors M37's own `siem_investigation` vs. Knowledge Graph relationship.

Cross-account visibility is modeled as edges between `CloudResource`s whose `CloudAccountRef`s differ but whose `CloudAccountEnrollment`s share a tenant — never inferred by convention; the ownership/trust-relationship edges must be explicitly computed from actual provider data (organization membership, cross-account role trust policies, VPC peering), because silently assuming account co-membership implies trust would be a real security modeling error in a product whose entire value proposition is finding exactly this kind of implicit trust.

## 5. CSPM Engine

`PolicyEvaluationRun` evaluates `BenchmarkControl`s against `CloudResource` configuration snapshots. Benchmark content (CIS, NIST, ISO27001, SOC2, HIPAA, PCI-DSS, custom) is versioned, registry-based content — the exact same "additive, open/closed, registry-driven" shape as Integration Hub's `NormalizerRegistry` and M37's detection-rule registry, deliberately repeated a third time because it is now a proven platform pattern for "pluggable, versioned, tenant-or-platform-owned content," not a coincidence. Custom policies are tenant-authored content in the same registry, with the same draft/active/deprecated lifecycle as M37's `DetectionRule`.

Evaluation is resumable/paginated exactly like Integration Hub's `SyncRun` (§2.2) — this is not optional at cloud scale; a tenant with tens of thousands of resources across hundreds of controls must never require a from-scratch re-evaluation after a transient failure.

## 6. CIEM Engine

`PermissionGraphSnapshot` models identity→policy→resource reachability as its own graph (distinct data shape from `ResourceGraphSnapshot`, per §2.2's justification). Least-privilege recommendation generation and toxic-combination detection (e.g. "can create an EC2 instance profile AND can attach an admin-equivalent role AND has no MFA") are domain services operating over this graph, publishing `ExcessivePermissionDetected`/`ToxicCombinationDetected` rather than a computed number embedded on the identity itself — matching the "aggregates reference evaluation state, don't own it" principle from §2.1.

`ciem` explicitly **references** the platform's existing Identity bounded context for principal identity/resolution (§11) — it does not maintain its own identity model; it maintains the *permission graph*, which is a cloud-specific structure Identity itself has no reason to own.

## 7. CWPP Foundation

Compute/VM/container/Kubernetes/serverless posture is discovered via the same connector/normalizer pipeline (§3), with `cwpp`'s domain responsibility being posture *evaluation* (vulnerable package presence, drift from golden image, runtime configuration) rather than a separate inventory. Deliberately scoped as a **foundation** in this milestone, not a full runtime-protection product (no in-guest agent architecture, no eBPF-based runtime detection design) — those are explicit Future Extension Points (§17), consistent with the milestone naming ("CWPP Foundation," not "CWPP").

## 8. Attack Path Engine

`cloud_attack_path` computes `AttackPathGraph`s — **a computed, versioned artifact, not a live interactive traversal query** — over a `ResourceGraphSnapshot` + `PermissionGraphSnapshot` pair, evaluating: reachability (network path from internet to resource), identity paths (assume-role/privilege chains), lateral movement (resource-to-resource trust/access), public exposure, and privilege escalation. This directly reuses the platform's existing **Attack Library** for TTP/technique context (identical integration to how M37's correlation engine referenced Attack Library, §6/§11 of M37) rather than maintaining a second attack-technique taxonomy.

**This is the highest-computational-complexity component in this architecture** (graph traversal over potentially millions of resource/permission edges at enterprise scale) and is explicitly flagged as requiring an Architecture Spike before implementation (§21) — this document commits to the *shape* (computed/versioned artifact, not live query; consumes but doesn't own the graphs; reuses Attack Library) but does not claim to have solved the traversal-algorithm/performance problem at architecture-freeze time, exactly as M37 flagged its correlation engine.

## 9. Exposure Management

`cloud_exposure` is a pure aggregation/read-model context — internet exposure (from `cloud_graph` network edges + `cloud_attack_path` reachability), identity exposure (from `ciem`), data exposure (from `cwpp`/resource configuration — e.g. a public S3 bucket, an unencrypted database), secrets exposure (cross-references Credential Vault's existing scope — but note: `cloud_exposure` detects *leaked/exposed* secrets in cloud configuration, e.g. a hardcoded key in a Lambda environment variable; it does not manage or store real secrets, which remains exclusively Credential Vault's job, §11), AI exposure (cross-references AI Security Foundation for AI-specific exposure signals — e.g. a publicly reachable model endpoint, an over-permissioned service account attached to an AI workload). No new discovery happens here — this context computes nothing that `cloud_graph`/`ciem`/`cwpp` don't already produce; it aggregates and presents.

## 10. Risk Engine Integration

**No `cloud_risk` bounded context.** Every finding-producing context (`cspm`, `ciem`, `cwpp`, `cloud_attack_path`) publishes its domain events to the platform's existing **Risk Engine Foundation** via a port (`IRiskContributionPort` — one new port method per contributing signal type, not a new risk-scoring engine). Risk Engine's existing business-impact/likelihood/exploitability model is extended with cloud-specific *inputs* (internet exposure, privilege escalation reachability, resource business-criticality tags), not a parallel scoring system. This directly mirrors M37's own choice to delegate behavioral/AI-assisted detection scoring to Risk Engine rather than reimplementing it (§5, §10, §22 of M37) — Cloud Security repeats the identical integration shape for the identical reason.

Context-aware prioritization (the actual "what do I fix first" output) is therefore a Risk Engine query, surfaced through `cloud_exposure`'s/`cloud_findings`' read-models, not computed independently by Cloud Security.

## 11. Integration with Existing Platform Contexts

| Existing context | Integration shape |
|---|---|
| **Integration Hub** | The foundation of `cloud_inventory` — every cloud provider is a `ConnectorPlugin`; `CloudAccountEnrollment` sits atop `ConnectorRegistration`; discovery/pagination/normalization-registry/sync-checkpoint machinery is reused wholesale, not reimplemented (§3). |
| **Asset Inventory** (`DiscoveredAsset`) | `CloudResource` is a specialization of `DiscoveredAsset`, not a competing model (§2.1) — cloud resources are first-class entries in the platform's one asset inventory, with cloud-specific extensions. |
| **Knowledge Graph** | `cloud_graph`'s `ResourceGraphSnapshot` and `ciem`'s `PermissionGraphSnapshot` feed Knowledge Graph as new node/edge sources; Knowledge Graph remains the one platform-wide graph store (§4, §7 of M37 — same principle, same store, new sources). |
| **Credential Vault** | Cloud provider credentials (AWS role ARNs/access keys, Azure service principals, GCP service accounts) are managed exactly as Integration Hub connectors already require — via `ICredentialVaultPort`-mediated resolution (Integration Hub's own recently-fixed pattern, §1 of the Freeze Blocker Resolution work, directly reused, not repeated as a new bypass). `cloud_exposure`'s secrets-exposure detection reads Credential Vault's *metadata* (is this cloud-embedded key one the vault also manages, i.e. is it a known/rotatable secret vs. a truly orphaned one) but never raw secret values. |
| **Risk Engine Foundation** | Sole owner of final risk scoring; Cloud Security is a contributor via port, not a parallel scorer (§10). |
| **Findings** (platform-wide) | `cloud_findings` is Cloud-Security-specific lifecycle (mirroring M37's `Alert`); it publishes to the platform's generic Findings concept the same way M37's `AlertRaised` does — as a candidate input, with the exact binding marked a Future Extension Point in both M37 and here, deliberately kept consistent rather than solved twice independently and possibly divergently. |
| **Identity** | `ciem` references Identity for principal resolution; does not duplicate identity data (§6). |
| **AI Security Foundation** | Referenced by `cloud_exposure` for AI-specific exposure signals (§9); `cwpp` may also reference it for AI-workload-specific posture (e.g. a GPU compute instance running an unpatched inference server) — reference, not duplication. |
| **Native SIEM (M37)** | Bidirectional, decoupled via events, same shape as every other cross-context relationship in this document: Cloud Security's domain events (`ResourceConfigurationChanged`, `MisconfigurationDetected`, `CriticalPathDetected`, etc.) are ingested by `siem_ingestion` as a `cloud` category source using M37's Canonical Event Model (a `cloud`-specific normalizer registered against `siem_normalization`, not a new event pipeline). Conversely, SIEM-detected runtime anomalies on cloud resources (e.g. anomalous API calls from `siem_detection`) are a signal `cloud_exposure`/Risk Engine can reference back — same bidirectional-but-decoupled-via-ports pattern M37 established for Risk Engine and AI Security Foundation (§11 of M37). |
| **Attack Library** | Referenced by `cloud_attack_path` for TTP/technique context, not duplicated (§8). |
| **Future Vulnerability Engine** | Natural consumer of `CloudResource`/`cwpp` posture data (e.g. a VM's package inventory) the moment it exists — no bespoke integration needed, same "committing to real pub/sub now pays off for every future consumer" argument M37 made (§11 of M37, restated here for the identical reason). |
| **Future SOAR** | Natural consumer of `CloudFindingOpened`/`CriticalPathDetected` for automated remediation playbooks — architecture placeholder, not designed further here, consistent with M37's identical SOAR placeholder. |

## 12. Resource Lifecycle

`CloudResource`: `DISCOVERED → ACTIVE → (CONFIGURATION_CHANGED)* → (DRIFTED | DEGRADED)? → DELETED`. Deletion is soft (tombstoned, not hard-deleted) for a tenant-configurable retention window, since a deleted resource's historical posture/finding/attack-path data remains audit- and investigation-relevant — same "append-only, regenerable" principle as evidence and graph snapshots, applied to resource lifecycle itself.

## 13. Risk Calculation Strategy

Fully delegated to Risk Engine Foundation (§10) — Cloud Security's responsibility ends at publishing well-formed risk-contribution signals (exposure level, privilege-escalation reachability, business-impact tags sourced from resource tagging/ownership data) via `IRiskContributionPort`. No risk-scoring algorithm is designed in this document; that already exists as frozen platform capability.

## 14. Compliance Strategy

`cloud_compliance` maps `PolicyEvaluationRun` results to `BenchmarkControl`s and produces scorecards (per-framework, per-account, per-tenant) — a read/reporting context, same shape as `cspm`'s relationship to `cloud_compliance` as `exposure`'s relationship to `exposure_reporting`. Custom compliance frameworks are supported the same way custom CSPM policies are (§5) — registry content, not code.

## 15. Executive Dashboards, Search, Reporting

All three are read-model concerns over the contexts above (`cloud_exposure`, `cloud_findings`, `cloud_compliance`, `cloud_graph` query surfaces) — no new domain logic, matching M37's `siem_analytics`/`siem_search` treatment as "thin, mostly-infrastructure, CQRS read side" (§10 of M37, same principle).

## 16. Multi-Cloud Strategy

One Canonical Cloud Resource model (§2.1), one relationship-type vocabulary (reused from Integration Hub, §2.2), one connector-per-provider pattern (§3) — multi-cloud is achieved by having exactly one place (`cloud_inventory`'s normalizer registrations) that understands provider differences, and zero places downstream that do. Cross-cloud resource relationships (e.g. a GCP workload assuming an AWS role via workload identity federation) are modeled as ordinary `cloud_graph` edges with mixed-provider endpoints — the graph model does not assume single-provider edges.

## 17. Multi-Tenant Isolation

Identical structural commitment to M37's (§4 of M37): no query against any Cloud Security store executes without a tenant filter compiled in at query-construction time, not left to convention — carried forward as a non-negotiable, especially critical here since a CIEM/attack-path leak across tenants would be a catastrophic-severity defect class (revealing one customer's cloud attack surface to another).

## 18. Scalability Strategy

- `cloud_inventory` scales exactly as Integration Hub already does (proven pattern, not a new one).
- `cloud_graph`/`ciem` graph computation scales by **account/tenant partitioning** of graph computation runs — never a single global graph recompute.
- `cloud_attack_path` computation is the one component requiring dedicated scalability design (§8, §21) — flagged, not solved, here.
- `cspm`/`cwpp` policy evaluation scales via the same resumable/paginated/checkpointed shape as Integration Hub's `SyncRun` (§5).

## 19. High Availability & Disaster Recovery

Same posture as M37 (§13, §14 of M37): stateless components (inventory, normalization, CSPM/CWPP evaluation workers) scale active-active trivially; graph snapshots and attack-path graphs are versioned, immutable artifacts recoverable by recomputation from the underlying `CloudResource`/`PermissionGraphSnapshot` data (the resource inventory itself, not the computed graphs, is the source of truth) — directly mirroring M37's "cold archive is source of truth, hot/warm are accelerated views" DR principle, applied here as "raw resource/permission data is source of truth, graphs/attack-paths are recomputable views."

## 20. Security Model

- Tenant isolation: structural (§17).
- Credentials: exclusively Credential Vault-mediated, no direct handling (§11).
- Secrets/data exposure detection: read-only inspection of cloud *configuration* for exposure signals, never storage of discovered secret values themselves (`cloud_exposure` records "a secret-shaped value was found exposed at location X," referencing Evidence for the finding's proof, never the secret's plaintext) — same evidence-reference discipline as M37's `raw_payload_ref` pattern (§2.1 of M37).
- RBAC: extends existing platform RBAC with new scopes (`cloud:read`, `cloud:cspm:manage`, `cloud:ciem:read`, `cloud:findings:manage`, etc.) following the existing naming convention, no parallel authorization model (§11 of M37, identical principle restated for this context).
- Audit: every domain event in §2.4 is audit-loggable via existing platform Audit Logging, same "domain events are the audit trail" principle as M37 and Evidence (ADR-0003).

## 21. Extension Framework & Points Requiring Architecture Spikes

**Extension points** (designed, open by construction):
- New cloud/SaaS providers: implement a `ConnectorPlugin` + normalizer, zero core changes (§3).
- New benchmark/compliance frameworks: registry content (§5, §14).
- New CSPM/custom policies: registry content, tenant-authored (§5).

**Requiring dedicated Architecture Spikes before implementation** (flagged explicitly, not glossed over — consistent with this milestone's own instruction to critically review rather than rubber-stamp):
1. **`cloud_attack_path` traversal algorithm and performance model** (§8, §18) — the shape (computed/versioned artifact, reuses Attack Library) is frozen; the actual graph-traversal algorithm, its complexity bounds at millions-of-edges scale, and incremental-recomputation strategy (must every resource change trigger a full graph-traversal recompute, or can it be incremental?) are undesigned. This is the single highest-risk unresolved item in this entire architecture.
2. **`ciem` toxic-combination detection rule authoring model** — the domain shape (`PrivilegeFinding`, `ToxicCombinationDetected`) is frozen; the actual rule/pattern language for defining a "toxic combination" (analogous to M37's Sigma-compatible detection rules, §5 of M37) is not designed, and is a nontrivial sub-problem in its own right (IAM policy semantics vary meaningfully across providers).
3. **`CloudResourceType` taxonomy governance** (§2.3) — committing to a versioned, extensible taxonomy is the right shape, but who owns/curates/versions it (platform team vs. community vs. auto-derived-from-provider-schemas) is undesigned.
4. **Kubernetes watch-based/streaming discovery integration into Integration Hub's connector contract** (§3) — the principle (push-based sources get their own adapter shape, per M37's precedent) is established; the concrete mechanism for a "streaming" `ConnectorPlugin` variant does not yet exist anywhere in the platform and needs its own small spike before the first Kubernetes connector is built.

## 22. Risks

- **Attack path computation is the dominant technical risk** (§8, §21.1) — explicitly the cloud-domain analogue of M37's correlation-engine risk, and for the identical underlying reason (stateful, computationally heavy, easy to under-design at architecture-freeze time).
- **CIEM cross-provider IAM semantic differences** are a real source of correctness risk if underestimated — AWS/Azure/GCP permission models are not isomorphic; a naive unified permission-graph model risks losing provider-specific nuance that determines whether a "toxic combination" finding is even valid.
- **Configuration payload sensitivity at cloud scale** — explicitly designed against via the allow-list commitment in §2.1, but this is a discipline that must be enforced per-normalizer at implementation time; the architecture names the requirement, it cannot enforce it by itself.
- **Volume of `ResourceConfigurationChanged` events feeding SIEM** (§11) could be very high at enterprise multi-account scale — worth validating against M37's own flagged risk (§22 of M37: "cross-context event volume... is a genuinely new load profile") before both M37 and M38 implementations proceed simultaneously; this is a shared risk between the two milestones, not unique to either.

## 23. Trade-offs

- Nine cooperating bounded contexts (§1) again trades coordination overhead for avoiding a God-context — accepted for the identical reason as M37, now doubly justified since Cloud Security's CSPM/CIEM/CWPP/attack-path concerns are even more clearly separable by data shape and computational profile than SIEM's sub-concerns were.
- Building `cloud_inventory` entirely atop Integration Hub (§3) trades some cloud-specific enrollment flexibility (multi-account/org-level enrollment doesn't fit Integration Hub's original single-credential-per-connector shape cleanly) for enormous reuse leverage — accepted, with `CloudAccountEnrollment` as the deliberately thin adapter aggregate absorbing that mismatch rather than modifying Integration Hub itself.
- Deferring the attack-path traversal algorithm and CIEM rule language (§21) to spikes rather than solving them now trades a fully-detailed architecture for a freeze that can actually happen on schedule — accepted as the right trade specifically because both gaps are computational/algorithmic design problems that would benefit from prototyping, not further up-front specification.

## 24. Architecture Review

**Is the architecture stable?** Yes for 8 of 9 bounded contexts and their integration points — each traces to a proven precedent in this platform (Integration Hub's discovery/normalization/sync machinery, Knowledge Graph extension, Risk Engine delegation, Evidence-referenced findings, M37's identical SIEM-integration shape). `cloud_attack_path` is the one context whose internal algorithm is genuinely undesigned, not merely deferred-for-brevity.

**Is it scalable?** Directionally yes, with the same caveat as M37: partitioning strategy is committed to everywhere except attack-path computation, which is named as needing its own scalability design.

**Is it maintainable?** Yes — this architecture adds almost no new platform-level patterns; it is overwhelmingly composition of already-frozen capabilities (Integration Hub, Knowledge Graph, Risk Engine, Evidence, Identity, Attack Library, and now M37's SIEM) into a cloud-domain-specific arrangement. This is the strongest maintainability signal available: the amount of genuinely new architectural surface is small and concentrated exactly where the spikes are flagged.

**Is it production ready?** Not applicable to this milestone (architecture-only, correctly). Implementation-ready: yes, for everything except the four spike items in §21, which should not block freezing the other 16 of 20 scope areas.

## 25. Freeze Recommendation

# ARCHITECTURE FREEZE APPROVED WITH REQUIRED ARCHITECTURE SPIKES

**Required spikes before implementation begins in their respective areas** (§21):
1. `cloud_attack_path` traversal algorithm and performance/incremental-recomputation model — **highest priority**, blocks `cloud_attack_path` and materially informs `cloud_exposure`'s exposure-path data.
2. `ciem` toxic-combination rule/pattern language design.
3. `CloudResourceType` taxonomy governance model.
4. Streaming/push-based connector contract extension to Integration Hub (needed before the first Kubernetes connector, not before cloud inventory generally).

The remaining 16 of 20 scope areas — Cloud Asset Inventory (non-Kubernetes-streaming aspects), Cloud Graph Engine, CSPM Engine, CIEM Engine (excluding rule language), CWPP Foundation, Exposure Management, Risk Engine integration, Findings Engine, Compliance Architecture, Executive Dashboards, Search, Reporting, Multi-cloud Strategy, Multi-tenant Isolation, Scalability Strategy (excluding attack-path), and Security Model — are frozen as specified and ready for implementation planning without further architecture-level rework.
