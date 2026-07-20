# M26 Architecture Decision Records

**Milestone:** M26 — Enterprise Cloud Security Platform  
**Status:** ARCHITECTURE PHASE — AWAITING APPROVAL  
**Date:** 2026-07-19  

---

## ADR-M26-001: Single `cloud_security` Bounded Context for All Providers

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
M26 must support AWS, Azure, and GCP. There are two structural options: (a) one bounded context per cloud provider, or (b) a single `cloud_security` bounded context with provider adapters.

### Decision
A single `cloud_security` bounded context with a `CloudProviderAdapter` protocol and per-provider infrastructure implementations.

### Rationale
- A per-provider bounded context (e.g., `aws_security`, `azure_security`, `gcp_security`) would require three separate domain models, three sets of application services, and three repository interfaces for structurally identical concepts (cloud account, cloud asset, IAM principal). This triples the maintenance surface.
- The unified model allows cross-provider risk scoring, attack path analysis, and compliance mapping to operate on a single aggregate type (`CloudAsset`) without inter-context translation.
- Provider differences are real but belong in the infrastructure layer (adapters, normalizers), not the domain.
- The `CloudProviderType` closed enum and `NormalizedConfig` value object are the domain's expression of provider identity without leaking provider-specific concepts.

### Consequences
- All provider-specific logic is confined to `infrastructure/cloud_security/adapters/{provider}/`
- New provider onboarding requires zero domain changes
- The domain model must be designed conservatively: only fields common to ≥2 providers enter `NormalizedConfig`; provider-specific fields go to `provider_metadata` (opaque JSONB)

---

## ADR-M26-002: Reuse Existing Security Graph — No New Graph Engine

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
M26 introduces cloud IAM graphs, privilege escalation paths, and K8s workload relationships. A new graph-native storage backend (Neo4j, Amazon Neptune) could provide richer traversal capabilities.

### Decision
Reuse the existing Security Graph (M4/M22) with PostgreSQL-backed node/edge tables. Extend the ontology to v8 with M26-specific node/edge kinds. Do not introduce a new graph engine.

### Rationale
- The Security Graph already serves all existing graph use cases (M4–M22). The attack path engine (M15) traverses it. The investigation platform (M21) correlates to it. Adding a second graph store creates a split-brain problem: which graph is authoritative for cross-domain queries?
- PostgreSQL recursive CTEs are sufficient for the BFS traversal patterns required by privilege escalation analysis (depth ≤ 5 hops on IAM graphs of ≤ 50,000 nodes).
- Operational complexity of maintaining a separate graph database (Neptune, Neo4j) at enterprise scale exceeds the traversal performance benefit for M26's use cases.
- The ontology is already designed for extension (version-bumped `ONTOLOGY_VERSION` constant, closed enum enforcement, valid-pair table in `EDGE_ONTOLOGY`).

### Consequences
- Security Graph ontology bumped from v7 to v8 (single migration)
- New node kinds: `IAM_ROLE`, `IAM_POLICY`, `K8S_WORKLOAD`, `K8S_NAMESPACE`, `CLOUD_AI_SERVICE`, `CLOUD_ACCOUNT_GROUP`
- New edge kinds: `ASSUMES_ROLE`, `HAS_POLICY`, `TRUSTS`, `RUNS_IN`, `HOSTED_IN_ACCOUNT`, `ESCALATES_TO`, `EXPOSES_AI_SERVICE`
- All new node/edge kinds follow existing `_ASSET_KINDS` / `EDGE_ONTOLOGY` guard patterns
- If graph traversal performance becomes a bottleneck at >500k nodes, a read replica with materialized adjacency lists (recursive CTE + caching) is the first remediation — not a new graph engine

---

## ADR-M26-003: EffectivePermissions Is Never Persisted

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
IAM effective permissions (the union of all permissions reachable by a principal through attached policies, group memberships, and role assumptions) are expensive to compute and tempting to cache as a database column.

### Decision
`EffectivePermissions` is a computed value object that is never persisted to the database. Only `attached_policies` (raw references) and `trust_relationships` are persisted in `cloud_iam_principals`.

### Rationale
- Persisted effective permissions are always potentially stale (IAM changes happen asynchronously). A stale permission row could cause a risk scoring decision based on outdated truth.
- The risk score already carries `computed_at` and `valid_until` to communicate staleness. Adding a second staleness dimension (effective permissions freshness) complicates the trust model.
- Effective permissions computation is O(depth × policies) — fast enough for on-demand computation with a short-lived (1-hour) in-process TTL cache.
- The domain model invariant is enforced structurally: `EffectivePermissions` has no repository save path.

### Consequences
- `cloud_iam_principals` table has no `effective_permissions` column
- Privilege escalation analysis operates on `attached_policies` + `trust_relationships` graphs
- In-process TTL cache invalidated on `IAMPrincipalUpdated` events
- Effective permissions computations are logged with timing metrics to detect future performance regression

---

## ADR-M26-004: CSPM Policies as Version-Controlled YAML

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
CSPM policies define the rules that detect cloud misconfigurations. Options: (a) YAML files in the repository, (b) database-stored policy records editable via API, (c) OPA/Rego policies.

### Decision
CSPM policies are YAML files stored in `infrastructure/cloud_security/cspm_policies/` under version control. Each evaluation run snapshots the active policies to a database table (`cspm_policies`) for audit trail purposes.

### Rationale
- YAML under version control provides full history, PR-based review, rollback, and CI validation — critical for a security product where policy changes must be audited and reviewed
- Database-editable policies introduce an administrative attack surface (a compromised admin could disable critical CSPM rules)
- OPA/Rego would require a new runtime dependency, adds operational complexity, and provides no meaningful benefit over a well-designed restricted evaluator for the condition complexity M26 requires
- The snapshot pattern (YAML → DB at evaluation time) provides the audit trail for "what policy version produced this finding" without making the DB the source of truth

### Consequences
- CI must validate CSPM policy YAML against JSON schema before merging
- Policy condition evaluator must use a restricted expression language (no Python eval)
- Policy changes require a PR with security team review label
- `cspm_findings` table stores `policy_version` FK to the snapshot for finding reproducibility

---

## ADR-M26-005: CloudTrail / Audit Log Events Are Eventually Consistent

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
CloudTrail delivery to S3 has a typical latency of 5–15 minutes. Azure Activity Log via Event Hub has typical latency of 2–5 minutes. GCP Audit Log via Pub/Sub has typical latency of < 1 minute. Should M26 attempt to approximate real-time detection?

### Decision
Accept eventual consistency for runtime event ingestion. Design all correlation and detection logic to use `event_time` (the time the API call occurred at the provider), not `ingested_at` (the time M26 processed the event).

### Rationale
- True real-time CloudTrail detection requires AWS CloudTrail Lake or EventBridge integration (additional cost and configuration complexity beyond M26 scope)
- For cloud audit log use cases (threat hunting, forensics, compliance), a 15-minute latency is operationally acceptable
- Using `event_time` rather than `ingested_at` means timeline reconstructions are accurate regardless of ingestion lag
- Late-arriving events (delivered hours after occurrence due to S3 redelivery) are handled correctly by `event_time`-based partitioning

### Consequences
- `cloud_runtime_events` is partitioned by `event_time`, not `ingested_at`
- The SOC dashboard shows "events as of `max(event_time)`" not "events as of now" — a staleness indicator is displayed
- Near-real-time detections (< 1 minute) remain the responsibility of M20 (NDR/UEBA) which operates on network-layer events
- Event deduplication key is `(cloud_account_id, event_source, provider_event_id)` — not timestamp-based

---

## ADR-M26-006: Kubernetes Access via Credential Vault Kubeconfig Only

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
Kubernetes cluster access can be achieved via: (a) in-cluster agent deployed to each cluster, (b) kubeconfig stored in credential vault, (c) provider-managed API (EKS API, AKS AAD, GKE Workload Identity).

### Decision
M26 accesses Kubernetes clusters exclusively via kubeconfig retrieved from the credential vault. No in-cluster agent is deployed.

### Rationale
- An in-cluster agent requires deploying software to customer clusters — a significant trust and security boundary crossing that requires customer approval, change management, and ongoing maintenance
- Kubeconfig via credential vault is already the pattern used by M22 and other bounded contexts that interact with cloud resources
- EKS/AKS/GKE all support kubeconfig-based authentication with short-lived tokens generated from the provider credential
- Provider-managed API access (EKS cluster API, AKS AAD) is the mechanism for generating these tokens — it is used by the adapter to populate the kubeconfig token, not a separate access path

### Consequences
- K8s cluster must be network-accessible from the RedForge worker (VPC peering or public endpoint)
- kubeconfig tokens have short TTLs (15–60 min) and must be refreshed before each K8s API call
- The K8s adapter must not cache credentials beyond the token TTL
- Clusters with private API endpoints only require VPN or direct connect access from the RedForge deployment environment — documented as a prerequisite

---

## ADR-M26-007: `cloud_runtime_events` Range Partitioning with 90-Day Hot Tier

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
Runtime events are append-only and high-volume. They need to be queryable for threat hunting and forensics but also subject to data retention policies. Options: (a) single table with time-based index, (b) range partitioning by month, (c) separate time-series database.

### Decision
PostgreSQL range partitioning by `event_time` with monthly partitions, 90-day hot tier, and archive-on-detach at 90 days.

### Rationale
- Range partitioning provides automatic partition pruning for time-bounded queries (e.g., "events in the last 7 days") — the planner only scans the relevant month partitions
- Monthly granularity matches typical incident investigation windows and retention policy boundaries
- 90-day hot tier balances regulatory compliance requirements (most regulations require 90-day real-time access) with storage costs
- Archive-on-detach: old partitions are detached from the main table and their data exported to cold storage (S3/GCS/ADLS) before dropping — not deleted
- A separate time-series database (TimescaleDB, InfluxDB) introduces a new operational dependency for what is fundamentally a write-heavy append-only workload that PostgreSQL handles well with proper partitioning

### Consequences
- Monthly partition creation must be automated (cron job or declarative partition management)
- Queries spanning >1 month must explicitly include multiple partition ranges or accept full-table scan
- Archive export must run before partition drop (migration script validates archive completion)
- Storage estimate: 1M events/day × 2KB avg × 90 days = ~180 GB per tenant — acceptable for PostgreSQL

---

## ADR-M26-008: CloudRiskScore Is Asset-Level, Not Account-Level

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
Risk scores could be defined at: (a) asset level (one score per CloudAsset), (b) account level (one score per CloudAccount), (c) organization level (one score per organization). Account-level scores would reduce the number of score records significantly.

### Decision
`CloudRiskScore` is computed and stored at the individual `CloudAsset` level.

### Rationale
- Asset-level scoring enables ranking (top-100 highest risk assets) which is the primary SOC and remediation workflow entry point
- Attack path analysis (M15) and exposure management (M25) operate at asset level — their inputs are meaningless at account level
- Account-level and organization-level aggregated risk is derived from asset scores at read time (materialized views) — not a separate stored computation
- The `cloud_risk_scores` table with index on `(org_id, overall_score DESC)` makes the ranking query efficient at scale

### Consequences
- `cloud_risk_scores` table has one row per `CloudAsset` (latest score only — older versions not retained)
- Account-level and org-level risk summaries are materialized views over `cloud_risk_scores`
- `CloudRiskCalculationWorker` must handle high fan-out events (e.g., an IAM principal whose policy changes affects 10,000 assets) using debouncing

---

## ADR-M26-009: Compliance Mapping via M24 ACL Only — No New Framework Registry

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
CSPM findings map to compliance controls (CIS AWS Foundations, SOC2, NIST CSF, PCI-DSS, etc.). M24 already maintains the compliance framework registry. M26 could maintain its own registry for cloud-specific controls or reuse M24.

### Decision
M26 uses M24's compliance framework registry exclusively. `ComplianceRef` value objects in CSPM policies carry `framework_id` and `control_id` that are resolved against M24's `ComplianceFrameworkRepository` via the `CSPMFindingToComplianceACL`.

### Rationale
- Maintaining a parallel compliance framework registry in M26 would create two sources of truth for the same frameworks (CIS, SOC2, etc.)
- M24 was explicitly designed (M24 Architecture) as the single compliance intelligence bounded context for the platform
- Cross-domain compliance posture (combining CSPM findings from M26 with findings from other sources) requires a unified compliance evidence store in M24

### Consequences
- M26 cannot define new compliance frameworks — this must go through M24
- `ComplianceRef` in CSPM policy YAML must use `framework_id` values that exist in M24's registry
- CI validation of CSPM policies includes a check that all `framework_id` values resolve against M24's framework catalog
- If M24 is unavailable, CSPM findings are still created but `compliance_refs` are marked as `UNRESOLVED` until M24 is available

---

## ADR-M26-010: IAM Privilege Escalation Uses Depth-Limited SQL Recursive CTE

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
Privilege escalation detection requires graph traversal over the IAM graph stored in the Security Graph tables. Options: (a) in-memory BFS after loading the full graph, (b) SQL recursive CTE with depth limit, (c) specialized graph algorithm library (NetworkX, igraph).

### Decision
Privilege escalation analysis uses PostgreSQL recursive CTEs with a depth limit of 5 hops. In-memory fallback using Python adjacency list for graphs with < 10,000 nodes.

### Rationale
- SQL recursive CTEs leverage PostgreSQL's existing query optimizer and avoid loading the full IAM graph into application memory
- Depth limit of 5 hops captures all practically exploitable escalation paths (real-world IAM privilege escalation chains rarely exceed 3–4 hops)
- For small organizations (< 10,000 IAM nodes), in-memory BFS with NetworkX is faster and clearer — applied as an optimization for that tier
- Adding NetworkX or igraph as a production dependency purely for this use case (which PostgreSQL handles well) is not justified

### Consequences
- `PrivilegeEscalationAnalysisService` has two implementations selected by node count heuristic
- SQL CTE depth limit is configurable via `PrivilegeEscalationConfig.max_depth` (default 5)
- Escalation paths are persisted as ESCALATES_TO edges in the Security Graph with `confidence` edge property
- Analysis is re-run incrementally (only for principals whose `attached_policies` changed since last analysis run)

---

## ADR-M26-011: CloudAsset Soft Delete Over Hard Delete

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
When a cloud asset is removed (terminated EC2 instance, deleted S3 bucket), M26 must decide whether to hard-delete the `CloudAsset` record or soft-delete it.

### Decision
Soft delete: set `CloudAsset.is_deleted = true` and `CloudAsset.deleted_at`. Do not hard-delete records.

### Rationale
- Cloud assets may briefly disappear from sync and reappear (transient API inconsistencies). Hard-delete on first absence would lose history and generate spurious `CloudAssetDiscovered` events on reappearance.
- Security investigations (M21) may reference a `CloudAssetId` that has since been terminated. Hard-delete would break investigation timeline integrity.
- Compliance audit trails require evidence of past asset existence, configurations, and security findings.
- `mark_deleted` in the repository is used after a full sync cycle confirms an asset is absent from the provider response — not on first absence.

### Consequences
- Queries for active assets must filter `is_deleted = false` (enforced by repository layer default)
- Deleted assets are excluded from risk scoring after a configurable grace period (default 7 days)
- Security Graph nodes for deleted assets are marked with `node_metadata.is_deleted = true` and excluded from attack path computation
- Storage reclamation: assets deleted > 365 days ago may be purged (hard-deleted) by a scheduled maintenance job — requires compliance team approval

---

## ADR-M26-012: Dashboard Read Models as PostgreSQL Materialized Views

**Status:** Accepted  
**Date:** 2026-07-19  

### Context
The eight M26 dashboards aggregate data across millions of rows. Options: (a) PostgreSQL materialized views refreshed on schedule, (b) dedicated read replica with complex aggregation queries, (c) in-application caching layer (Redis), (d) dedicated OLAP store (ClickHouse, Redshift).

### Decision
Dashboard read models are PostgreSQL materialized views refreshed `CONCURRENTLY` on a schedule (15-minute or 30-minute cadence depending on dashboard). The SOC alert dashboard uses a direct query with a short time-window filter (not a materialized view).

### Rationale
- Materialized views are natively supported in PostgreSQL, require no additional infrastructure, and provide acceptable performance for dashboards that tolerate 15-minute staleness (executive, compliance, inventory)
- `REFRESH MATERIALIZED VIEW CONCURRENTLY` prevents read-blocking during refresh
- A dedicated OLAP store (ClickHouse) would provide significantly better aggregation performance but introduces an operational dependency not yet present in the platform. The expected data volume at M26 completion (< 2M assets per tenant) does not justify this cost.
- Redis caching would add TTL staleness management complexity with no benefit over materialized views for this use case
- The SOC alert dashboard is the exception: it must show near-real-time suspicious events and cannot tolerate 15-minute staleness. Its query uses a WHERE clause on `event_time > now() - interval '1 hour'` which leverages the `cloud_runtime_events` partition index efficiently.

### Consequences
- Materialized views are owned by the `cloud_security` schema
- View refresh schedule is managed by the existing scheduler (M11)
- Dashboard API routes query materialized views only — never command-side aggregate tables
- A background health check monitors view refresh lag and alerts if a view has not been refreshed in > 2× its configured interval
- If OLAP volume requirements are exceeded in future milestones, the migration path is: materialized views → materialized views on read replica → ClickHouse (progressive, not big-bang)
