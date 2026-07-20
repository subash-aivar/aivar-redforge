# M26 Hardening Review — Enterprise Cloud Security Platform

**Status:** ARCHITECTURE PHASE — PRE-IMPLEMENTATION  
**Milestone:** M26  
**Review Date:** 2026-07-19  
**Reviewer:** Principal Enterprise Security Architect  

---

## 1. Architectural Risks

### AR-1: Provider Credential Exposure

**Severity:** CRITICAL  
**Description:** Cloud provider credentials (AWS access keys, Azure service principal secrets, GCP service account keys) are among the most sensitive secrets in any enterprise environment. Any leak through logs, domain events, API responses, or exception traces is a catastrophic breach.

**Mitigations:**
- `CredentialRef` is an opaque value object — it carries a reference ID, not the credential material
- The `credential_vault` module is the only component that ever holds plaintext credentials
- Provider adapters receive a `CloudCredential` object with a `get_session()` method; the credential material is never stored in adapter state
- Domain events carry only `credential_ref` (opaque), never `credential_value`
- Exception handlers in adapter layer must not include `CloudCredential` objects in exception messages or tracebacks; implement a `sanitize_exception` decorator for all adapter methods
- Audit log every credential access through the credential vault
- CI secret scanning (gitleaks, truffleHog) must be enabled before P1 implementation begins

**Acceptance Criteria:** Zero credential material in logs, events, API responses, or exception traces. Automated test verifies this by asserting no domain event JSON contains known test credential patterns.

---

### AR-2: CSPM Policy Condition Injection

**Severity:** HIGH  
**Description:** CSPM policies are defined as YAML with condition expressions evaluated at runtime. If the evaluator uses Python `eval()` or `exec()`, a maliciously crafted policy file could achieve arbitrary code execution on the assessment worker.

**Mitigations:**
- The `CSPMPolicyEvaluator` must use a restricted expression evaluator (e.g., `simpleeval` or a hand-rolled AST walker), not Python `eval()`
- Allowed operations: attribute access, comparison operators, boolean operators, string/numeric literals, `in` operator, `len()`, `any()`, `all()`
- Disallowed: `__builtins__`, `import`, function calls not in the allowed list, attribute access to private/dunder attributes
- CSPM policy YAML files are version-controlled; changes require PR review
- Policy files are JSON-schema validated on load before any evaluation
- Policy condition tests cover injection attempts (e.g., `"__import__('os').system('id')"` as a condition value) and assert they raise `InvalidPolicyConditionError`

**Acceptance Criteria:** `CSPMPolicyEvaluator` rejects any condition containing `__`, `import`, `exec`, `eval`, `open`, or `subprocess`. Test suite includes explicit injection test cases.

---

### AR-3: IAM Effective Permissions Persistence

**Severity:** HIGH  
**Description:** Storing computed effective permissions as a database column creates a stale truth problem. If the IAM permissions change but the sync hasn't run yet, a stale row could mislead risk scoring or access decisions.

**Mitigations:**
- `EffectivePermissions` is a computed value object — it is never persisted to the database
- Only `attached_policies` (raw attachment references) and `trust_relationships` are persisted
- Effective permissions are computed lazily in `IAMRiskAnalysisService` with a 1-hour in-process TTL cache keyed on `(CloudIAMPrincipalId, etag_hash_of_policies)`
- The cache is invalidated on `IAMPrincipalUpdated` events
- The risk score explicitly records its `computed_at` and `valid_until` timestamps so consumers know when to treat a score as stale

**Acceptance Criteria:** Database schema review confirms no `effective_permissions` column exists in `cloud_iam_principals`. Domain model unit test asserts `EffectivePermissions` has no repository persistence path.

---

### AR-4: Cross-Tenant Graph Query Leakage

**Severity:** CRITICAL  
**Description:** The Security Graph (M4) stores nodes and edges for all tenants. If M26 graph projection queries do not correctly filter by `org_id`, one tenant's cloud assets could be visible to another.

**Mitigations:**
- All Security Graph queries issued by M26 projectors pass `org_id` as a mandatory parameter
- Existing `SecurityGraphProjectionWorker` already enforces `org_id` at the projection layer (M4 contract)
- M26 graph ACL wraps all Security Graph calls with an `OrgIdEnforcingGraphClient` that asserts `org_id` is always present before any query
- Integration test: create assets for two organizations, verify Security Graph queries for org A never return nodes from org B

**Acceptance Criteria:** Integration test with two-tenant fixture passes. Security review confirms no graph query path bypasses `org_id` filter.

---

### AR-5: Runtime Event Volume Causing Write Contention

**Severity:** HIGH  
**Description:** CloudTrail can emit millions of events per day for large accounts. If ingestion writes synchronously to PostgreSQL with row-level locking, it will create write contention that degrades the entire platform.

**Mitigations:**
- `RuntimeEventIngestionWorker` uses batched async inserts (COPY command, batch size 1,000)
- `cloud_runtime_events` is range-partitioned by month — new inserts go to the current month's partition only, minimizing index contention
- Insert path uses `INSERT ... ON CONFLICT DO NOTHING` (event_id is idempotent key)
- Worker backpressure: if the insert queue depth exceeds 10,000, the worker pauses ingestion and waits for drain (using existing `BackpressureController` from M26)
- DLQ (M29) receives events that fail after 3 insert retries

**Acceptance Criteria:** Load test: 10,000 events/second sustained for 60 seconds with no insert latency > 500ms p99. Confirmed with EXPLAIN ANALYZE on partitioned table.

---

## 2. Scalability Risks

### SR-1: Asset Sync at Organizational Scale

**Context:** An enterprise AWS Organization may contain 200+ accounts, each with 10,000+ resources = 2M+ cloud assets per tenant.

**Risks:**
- Full-account sync becomes multi-hour operation
- NormalizedConfig JSONB blobs grow per-row storage significantly
- Tag-filter GIN index becomes expensive on 2M rows

**Mitigations:**
- Incremental sync: use provider change APIs (AWS Config, Azure Resource Graph change feed, GCP Asset Inventory updates) where available
- `cloud_assets` is logically partitioned by `account_id` (clustered physical layout)
- NormalizedConfig JSONB is compressed at the application layer before storage; estimated avg 2KB per asset
- Tag GIN index uses `jsonb_ops` (not `jsonb_path_ops`) for most-common query patterns
- `CloudAssetSyncWorker` per-account concurrency limited to 5 concurrent account crawls via `BulkheadExecutor`
- Full sweep falls back to per-asset-type pagination if provider bulk API is unavailable

**2M asset storage estimate:** 2M × (UUID 16B + account_id 16B + provider_id 128B + NormalizedConfig 2KB + indexes ~500B) ≈ 5.2 GB per tenant per provider — acceptable for PostgreSQL.

---

### SR-2: IAM Graph BFS Scalability

**Context:** An AWS Organization with 10,000 IAM roles and policies produces a dense graph. BFS-based privilege escalation analysis is O(V+E) per principal.

**Risks:**
- Analysis for 10,000 principals × O(V+E) traversal may take hours
- Memory pressure from holding full adjacency list in-process

**Mitigations:**
- Privilege escalation analysis runs as a background worker, not in-request
- Graph traversal uses depth limit (default 5 hops) to prevent unbounded traversal
- IAM graph is stored in the existing PostgreSQL Security Graph tables (not in-memory) — BFS queries use SQL recursive CTEs with depth limit
- Analysis results are cached as `PrivilegeEscalationPath` records with an `analyzed_at` timestamp
- Only principals whose attached_policies changed since last analysis are re-analyzed (incremental mode)

---

### SR-3: CSPM Policy Evaluation at Scale

**Context:** 65 CSPM policies × 2M assets = 130M evaluations per full sweep.

**Mitigations:**
- CSPM assessment is asset-change-driven (event-based) for incremental evaluation
- Full sweep runs only once per 24 hours (not continuously)
- Policy evaluation is CPU-bound, not I/O-bound — horizontally scalable by deploying multiple `CSPMAssessmentWorker` replicas
- Worker is stateless — multiple replicas consume from the same SQS/event queue
- Per-account sweep is the unit of parallelism (not per-asset)

---

### SR-4: Dashboard Materialized View Refresh Lag

**Context:** Executive dashboard aggregates across all assets and risk scores for a large organization.

**Risks:**
- Refresh takes > 60 seconds on 2M assets → stale data during refresh

**Mitigations:**
- All materialized views use `REFRESH MATERIALIZED VIEW CONCURRENTLY` — readers are not blocked during refresh
- Executive and compliance dashboards refresh every 15 minutes (acceptable lag for C-suite consumption)
- SOC alert dashboard is event-driven (not materialized view) — it reads from `cloud_runtime_events` directly with a 1-minute window filter
- Materialized view refresh is a low-priority background task; it yields if the database load average exceeds threshold

---

## 3. Performance Risks

### PR-1: NormalizedConfig JSONB Query Performance

**Risk:** Querying inside JSONB `normalized_config` without a covering index causes sequential scans.

**Mitigation:** Only indexed fields (`tags`, `asset_type`, `account_id`, `org_id`) are used in WHERE clauses. `normalized_config` is retrieved but never filtered in SQL. Policy evaluation reads `normalized_config` in application memory after a primary-key fetch.

---

### PR-2: CloudRiskScore Recomputation Cascade

**Risk:** A single `IAMRiskLevelChanged` event for a principal with access to 10,000 assets could trigger 10,000 risk score recomputations.

**Mitigation:**
- Risk score recomputation is debounced per asset: if an asset's score was computed within the last 5 minutes, the recomputation is deferred to the next scheduled window
- `CloudRiskCalculationWorker` uses a priority queue: CRITICAL severity events preempt routine recomputations
- Asset-level risk score has a `valid_until` TTL; consumers show staleness indicator when score is expired

---

### PR-3: Security Graph Projection Write Amplification

**Risk:** A full account sync (~10,000 assets) triggers 10,000 graph node upsert operations.

**Mitigation:**
- Graph projection worker batches upserts: up to 500 node/edge operations per transaction
- UPSERT (`INSERT ... ON CONFLICT DO UPDATE`) semantics ensure idempotency
- Only changed assets (detected by config hash comparison) trigger graph updates during incremental syncs

---

## 4. Tenant Isolation Strategy

M26 enforces tenant isolation at three independent layers:

### Layer 1: Domain Model Invariant
Every M26 aggregate carries `organization_id` at the aggregate root level. Factory methods require `organization_id` as a mandatory parameter. No aggregate can be created without a valid `OrganizationId`.

### Layer 2: Repository Layer Enforcement
All repository `list_*` and `get_*` methods accept `organization_id` as a non-optional parameter and include it in every SQL WHERE clause. Repository implementations in PostgreSQL prepend `AND org_id = %s` to all queries. This is enforced by a base `TenantScopedRepository` abstract class.

### Layer 3: API Layer Enforcement
All M26 API route handlers extract `organization_id` from the authenticated JWT (M3 RBAC). The `organization_id` is injected into the application service command/query, not accepted from the request body. Users cannot specify `organization_id` in the request payload.

### Layer 4: Event Bus Enforcement
All domain events include `organization_id` in the event envelope. Event consumers validate that `organization_id` in the event matches the tenant context before processing.

**Verification:** A two-tenant integration test creates assets for Organization A and Organization B, then asserts:
- `list_by_organization(org_a)` returns zero Organization B assets
- Direct repository access with `org_b` returns zero Organization A assets
- API calls with Org A JWT return zero Org B assets

---

## 5. Provider Lock-in Risks

### PL-1: Provider-Specific SDK Coupling

**Risk:** If `boto3`, `azure-mgmt-*`, or `google-cloud-*` SDKs are used outside the adapter layer, migrating to a new provider or upgrading SDK versions becomes expensive.

**Mitigation:**
- All provider SDK imports are restricted to `infrastructure/cloud_security/adapters/{provider}/`
- Domain and application layers import only from `domain/cloud_security/` and `application/cloud_security/`
- CI linting rule (import boundary enforcement) prohibits `boto3`, `azure`, or `google.cloud` imports outside the adapter directory

### PL-2: Provider-Specific Data Models in NormalizedConfig

**Risk:** `NormalizedConfig` fields that are only meaningful for one provider create implicit coupling.

**Mitigation:**
- `NormalizedConfig` contains only fields that are semantically meaningful across ≥2 providers, OR are explicitly documented as provider-specific with a `provider_hint` marker
- Provider-specific raw data lives in `provider_metadata` (opaque JSONB, never queried in SQL)

### PL-3: Future Provider Onboarding

**Extension points for new providers (e.g., Oracle Cloud, IBM Cloud, Alibaba Cloud):**
1. Implement `CloudProviderAdapter` protocol (no domain changes required)
2. Add provider type to `CloudProviderType` enum (requires migration)
3. Add asset type mappings to `CloudAssetType` enum for provider-specific resources
4. Implement normalizers for each asset type
5. Register adapter in `CloudProviderAdapterRegistry`

Domain model, application services, repositories, and ACLs require zero changes to onboard a new provider.

---

## 6. Security Review

### S-1: Authentication & Authorization

- All M26 API routes require a valid JWT issued by the platform identity service (M10)
- Route-level RBAC enforced via M3 `@require_permission` decorator
- New permissions: `cloud_security:read`, `cloud_security:write`, `cloud_security:admin`
- `cloud_security:admin` required for: registering providers, triggering manual syncs, suppressing findings
- `cloud_security:read` sufficient for: all dashboard reads, asset listing, finding listing

### S-2: Secrets in CSPM Evidence

CSPM finding evidence may include portions of the `NormalizedConfig` that led to the violation. Evidence must never include:
- KMS key material
- Secret Manager secret values
- IAM access key values
- Connection strings with passwords

Evidence is sanitized by the `CSPMEvidenceSanitizer` before persisting to `cspm_findings.evidence`. Sanitization applies regex patterns for common secret formats (AWS secret key pattern, connection string password parameter, etc.).

### S-3: SSRF via Cloud Provider Endpoints

**Risk:** If the adapter constructs HTTP requests to cloud provider endpoints using user-supplied input (e.g., region name, account ID), an attacker could craft SSRF payloads.

**Mitigation:**
- Region names are validated against a closed allowlist of known regions per provider before use in API calls
- Account IDs / project IDs are validated against expected format (AWS: 12-digit numeric, GCP: lowercase alphanumeric + hyphens)
- SDK endpoint URLs are never constructed from user input — only from the provider SDK's built-in region resolution

### S-4: Kubernetes API Authentication

- `KubernetesCluster` authentication uses kubeconfig stored in the `credential_vault`
- Kubeconfig tokens are short-lived (EKS: 15 min; AKS: 60 min; GKE: 60 min) and refreshed before each API call
- K8s API requests use HTTPS with TLS certificate validation (no `insecure_skip_tls_verify`)
- K8s adapter requests use a read-only service account with minimal RBAC (list/get on: pods, namespaces, roles, rolebindings, clusterroles, clusterrolebindings, networkpolicies)

### S-5: Runtime Event Data Integrity

- `CloudRuntimeEvent.raw_payload` is stored as-is from the provider (normalized in application layer)
- Provider signatures (CloudTrail SNS/SQS message signatures) are validated before processing
- Azure Activity Log Event Hub consumer validates the Event Hub connection string against the stored credential ref
- GCP Pub/Sub subscriber validates message attributes including `logName` format

---

## 7. Integration Review

### Integration with M18 (Attack Path Engine / Security Graph)

**Dependency type:** M26 → M18 (producer)  
**Interface:** M26 projects new node/edge kinds (ontology v8) into the Security Graph. M26 also reads attack path membership via `AttackPathACL`.  
**No duplication:** M26 does not implement graph traversal or attack path computation. The existing `AttackPathService` (M15/M18) handles all path computation.  
**Contract:** M26 adds `IAM_ROLE`, `IAM_POLICY`, `K8S_WORKLOAD`, `K8S_NAMESPACE`, `CLOUD_AI_SERVICE` node kinds and 7 new edge kinds. These are additive; no existing node/edge kinds are modified.

### Integration with M20 (NDR / UEBA / Behavioral Detection)

**Dependency type:** M26 → M20 (parallel producer)  
**Interface:** `SuspiciousActivityDetected` events from M26's `RuntimeCorrelationEngine` may carry the same asset/IP observables that M20's UEBA engine tracks. Both bounded contexts may generate investigation correlation events for the same observable.  
**No duplication:** M20 operates on network-layer events (flow records, UEBA behavioral baselines). M26 operates on cloud API audit logs (control-plane events). They are complementary, not overlapping.  
**Coordination:** The M21 `InvestigationCase` serves as the correlation point. Both M20 and M26 produce `InvestigationCorrelationRequest` events; M21 deduplicates and merges them into the investigation timeline.

### Integration with M21 (Investigation Platform)

**Dependency type:** M26 → M21 (producer)  
**Interface:** `CloudRuntimeEventToInvestigationACL` translates `SuspiciousActivityDetected` into `InvestigationCorrelationRequest`.  
**No duplication:** M26 does not implement investigation case management. M21 owns the case lifecycle.  
**New graph edges:** `CORRELATED_WITH` edges from `CLOUD_RESOURCE` / `FINDING` nodes to `INVESTIGATION` nodes are already supported by the existing ontology (M21 additions in ontology v6).

### Integration with M22 (Asset Inventory)

**Dependency type:** M26 → M22 (producer)  
**Interface:** `CloudAssetToInventoryACL` projects `CloudAsset` records into M22's `AIAsset` inventory.  
**No duplication:** M22 manages the canonical asset inventory (all asset types). M26's `CloudAsset` is a cloud-security-specific aggregate with posture state, CSPM findings, and IAM relationships. The M22 record carries the cross-reference but does not duplicate the security-specific data.  
**Key distinction:** `CloudAsset` (M26) ≠ `AIAsset` (M22). The M22 record has `cloud_asset_id` FK but manages its own lifecycle independently.

### Integration with M24 (Compliance Intelligence)

**Dependency type:** M26 → M24 (producer)  
**Interface:** `CSPMFindingToComplianceACL` maps open CSPM findings to M24 compliance evidence records.  
**No duplication:** M24 owns compliance framework definitions, control mappings, and compliance posture computation. M26 produces the cloud-specific evidence that M24 evaluates.  
**Reuse:** M26 CSPM policies reference M24 framework/control IDs directly (`framework: CIS_AWS_FOUNDATIONS, control: 2.1.1`). M26 does not maintain its own compliance framework registry.

### Integration with M25 (Exposure Management)

**Dependency type:** M26 → M25 (parallel producer + consumer)  
**Interface (producer):** `CloudAsset` records with `network_exposure = PUBLIC` contribute to M25's exposure graph.  
**Interface (consumer):** `ExposureGraphACL` reads M25's `ExposureScore` for each cloud asset as one input dimension to `CloudRiskScore`.  
**No duplication:** M25 manages the unified exposure graph and scoring. M26 provides the cloud asset network exposure facts that M25 incorporates.

---

## 8. Technical Debt Prevention

The following patterns from earlier milestones must not be repeated in M26:

| Prior Debt | Lesson | M26 Prevention |
|---|---|---|
| DEBT-S24-1: KG projection without idempotency | Projection re-runs produced duplicate nodes | All M26 graph projections use UPSERT semantics with conflict-on-`provider_id` |
| DEBT-S26-1: HALF_OPEN circuit breaker race | Concurrent state check without atomic CAS | M26 workers reuse the fixed `CircuitBreaker` from M26 runtime platform |
| DEBT-S28-1: In-memory DLQ lost on restart | Failed events lost on worker restart | M26 ingestion uses PostgreSQL DLQ from M29 exclusively |
| DEBT-S29-1: No projection handlers in replay | DLQ replay couldn't reconstitute projection state | M26 projection workers register with the existing `ProjectionHandlerRegistry` (M30) |
| DEBT-S3839-IA-1: Unbounded severity promotion | Evaluation signals could escalate severity without gate | M26 Risk Engine uses explicit weighted formula, not unbounded promotion |

---

## 9. Future Extension Points

| Extension | Trigger | Architecture Impact |
|---|---|---|
| Oracle Cloud / IBM Cloud / Alibaba Cloud | Customer demand | Add `CloudProviderType` enum value + implement `CloudProviderAdapter`; zero domain changes |
| Container image scanning | M27+ | `K8sWorkload` entity extended with `image_scan_results`; new `IMAGE_SCAN_FINDING` node kind |
| Cloud data classification (DLP) | M28+ | `CloudAsset` extended with `data_classification`; new CSPM policies for unclassified sensitive data |
| Agentless cloud workload protection | M29+ | Runtime sensor events ingested as `CloudRuntimeEvent` with new `event_source = AGENT` |
| Cloud cost + security risk correlation | M30+ | `CloudRiskScore` extended with `cost_impact` dimension; new `CostRiskCorrelationService` |
| Multi-cloud attack path stitching | M27+ | Attack Path Engine (M15) extended to traverse `ASSUMES_ROLE` / `TRUSTS` edges introduced in M26 ontology v8 |
| Terraform / IaC drift detection | M28+ | New `IaCSyncWorker` compares desired-state IaC with actual `NormalizedConfig` |

---

## 10. Hardening Checklist (Pre-Implementation)

Prior to beginning Phase 1 implementation, the following must be confirmed:

- [ ] Architecture Freeze document approved by Principal Architect
- [ ] ADR-M26-001 through ADR-M26-012 reviewed and accepted
- [ ] `credential_vault` interface confirmed compatible with multi-cloud credential types
- [ ] Ontology v8 additions reviewed and approved by Security Graph maintainer
- [ ] CSPM policy evaluator security design reviewed (no eval() usage confirmed in design)
- [ ] Multi-tenancy integration test fixture designed and approved
- [ ] Provider SDK versions pinned in `pyproject.toml`
- [ ] CI secret scanning (gitleaks) enabled on main branch
- [ ] DBA review of `cloud_runtime_events` partitioning strategy
- [ ] Database migration numbering confirmed (next migration after current HEAD)
