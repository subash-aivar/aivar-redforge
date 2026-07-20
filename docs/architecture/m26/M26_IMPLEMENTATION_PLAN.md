# M26 Implementation Plan — Enterprise Cloud Security Platform

**Status:** ARCHITECTURE PHASE — AWAITING APPROVAL  
**Milestone:** M26  
**Estimated Phases:** 8  
**Estimated Tests at Completion:** ~3,700 (≈ +500 over current 3,254 baseline)  

---

## Phase Overview

| Phase | Name | Focus | Exit Criteria |
|---|---|---|---|
| P1 | Cloud Foundation | Core domain + AWS/Azure/GCP adapters + account sync | Cloud accounts discoverable, assets crawled per provider |
| P2 | Unified Asset Model | CloudAsset normalization, graph projection, inventory ACL | All asset types normalized, projected into Security Graph and Inventory |
| P3 | Cloud IAM & CIEM | IAMPrincipal sync, IAM graph, privilege escalation, cross-account trust | PrivilegeEscalationPathDetected events firing, IAM risk scored |
| P4 | CSPM | Policy engine, misconfiguration detection, drift detection, compliance ACL | CSPM findings generated, mapped to M24 compliance |
| P5 | Kubernetes Security | EKS/AKS/GKE sync, workload analysis, RBAC analysis, network policy | K8s cluster security score computed |
| P6 | Runtime Visibility | CloudTrail/Azure Activity/GCP Audit ingestion, correlation, investigation ACL | Runtime events ingested, suspicious activity detected, M21 correlated |
| P7 | Cloud AI Services | AI service inventory, exposure analysis, AI risk indicators | CloudAIService aggregates projected into M22 inventory |
| P8 | Risk Engine & Dashboards | CloudRiskScore, all dashboard read models, worker finalization | Full risk scores computed, all dashboards operational |

---

## Phase 1: Cloud Foundation

### Objective
Establish the `cloud_security` bounded context skeleton, define all core domain types, implement provider adapters for all three cloud providers, and deliver account-level discovery and synchronization.

### Deliverables

1. **Domain Layer**
   - `CloudProvider`, `CloudAccount` aggregates
   - All value objects for foundation tier (`CloudProviderId`, `CloudAccountId`, `CloudProviderType`, `CloudAccountType`, `CredentialRef`, `DiscoveryConfig`, `AccountSyncState`, `CloudRegion`, `AvailabilityZone`)
   - `CloudProviderRepository`, `CloudAccountRepository` interfaces
   - `CloudProviderRegistered`, `CloudAccountDiscovered`, `CloudAccountSyncCompleted` domain events

2. **Application Layer**
   - `RegisterCloudProviderCommand` handler
   - `SyncCloudAccountCommand` handler (dispatches to worker)

3. **Infrastructure Layer**
   - PostgreSQL: `cloud_providers`, `cloud_accounts` tables + migration
   - AWS adapter: `AWSCloudProviderAdapter` — account enumeration via Organizations API, STS assume-role integration with credential_vault
   - Azure adapter: `AzureCloudProviderAdapter` — subscription enumeration via Management Groups API
   - GCP adapter: `GCPCloudProviderAdapter` — project enumeration via Resource Manager API
   - `CloudDiscoveryWorker` — scheduled per-provider account discovery

4. **Tests**
   - Unit: domain aggregate invariants, value object validation
   - Unit: normalizer correctness per provider (mocked responses)
   - Integration: `CloudAccountRepository` against test DB
   - Integration: AWS adapter against LocalStack; Azure/GCP against service emulators

### Dependencies
- `credential_vault` (existing) — credential retrieval for provider authentication
- Organizations (M2) — `OrganizationId` as root boundary
- Platform event bus (M12) — `CloudAccountDiscovered` publication

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Provider SDK version churn during development | Medium | Medium | Pin SDK versions in `pyproject.toml`; test against pinned emulator versions |
| credential_vault credential rotation race | Low | High | Credential ref is re-resolved per adapter call, not cached |
| AWS Organizations API requires management account access | Medium | High | Support single-account mode without Organizations API; document IAM permissions required |

### Exit Criteria
- `RegisterCloudProviderCommand` successfully registers all three provider types
- `SyncCloudAccountCommand` discovers and persists cloud accounts for a mock AWS Organization, Azure Tenant, and GCP Folder
- 40+ new tests passing

### Quality Gates
- All repository interfaces have integration tests against a real PostgreSQL instance (not mocked)
- Credential material never appears in logs, events, or normalized domain objects
- `AccountSyncState.FAILED` is always accompanied by a structured error event (no silent failures)

---

## Phase 2: Unified Asset Model

### Objective
Implement the `CloudAsset` aggregate, all asset normalizers for compute/storage/database/networking/serverless/secrets/DNS/load-balancers across all three providers, and project discovered assets into the Security Graph and M22 Inventory.

### Deliverables

1. **Domain Layer**
   - `CloudAsset` aggregate with full `CloudAssetType` closed enum
   - `NormalizedConfig`, `AssetRelationship`, `CloudPostureState` value objects
   - `CloudAssetRepository` interface
   - `CloudAssetDiscovered`, `CloudAssetUpdated`, `CloudAssetDeleted`, `CloudAssetRelationshipDiscovered` domain events

2. **Application Layer**
   - `ListCloudAssetsQuery`, `GetCloudAssetDetailQuery` handlers

3. **Infrastructure Layer**
   - PostgreSQL: `cloud_assets` table with GIN tag index + migration
   - AWS normalizers: EC2, S3, RDS, Lambda, VPC, Subnet, SecurityGroup, ALB/NLB, Route53, CloudFront
   - Azure normalizers: VM, StorageAccount, AzureSQL, VNet, NSG, FunctionApp
   - GCP normalizers: ComputeInstance, GCSBucket, CloudSQL, VPCNetwork, CloudFunction
   - `CloudAssetSyncWorker` — paginated crawl with checkpoint resume
   - `GraphProjectionWorker` (Phase 2 scope: CLOUD_ACCOUNT, CLOUD_RESOURCE node kinds only; new M26 node kinds deferred to P3+)
   - `InventoryProjectionWorker` — `CloudAssetToInventoryACL`

4. **Tests**
   - Unit: normalizer field mapping for each asset type (table-driven)
   - Unit: `CloudAsset` aggregate invariants (deleted asset cannot be updated, etc.)
   - Integration: full sync cycle against LocalStack (EC2, S3, VPC)
   - Integration: graph projection — verify nodes appear in security_graph_nodes

### Dependencies
- P1 complete (CloudAccount exists)
- Security Graph (M4) — existing `SecurityGraphProjectionWorker` protocol
- Inventory (M22) — `AIAssetRepository` interface for inventory projection

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Asset count at scale (100k+ per account) | High | Medium | Pagination + incremental sync; `save_batch` with conflict-on-update semantics |
| NormalizedConfig schema drift between providers | Medium | Medium | Schema versioned via `config_schema_version` field; JSON schema validation in tests |
| Graph projection volume causing OOM in projection worker | Medium | High | Batch projection events; reuse existing backpressure controls from M26 BulkheadExecutor |

### Exit Criteria
- Full asset inventory for a mock AWS account (500+ resources) synced and queryable
- Security Graph contains correct CLOUD_ACCOUNT and CLOUD_RESOURCE nodes with CONTAINS edges
- M22 Inventory contains cross-referenced records for all synced assets
- 80+ new tests passing (cumulative P1+P2: 120+)

### Quality Gates
- `mark_deleted` correctly tombstones assets absent from latest sync (no orphan records)
- GIN index on tags verified via EXPLAIN ANALYZE on tag-filtered queries
- Graph projection worker handles duplicate discovery events idempotently

---

## Phase 3: Cloud IAM & CIEM

### Objective
Implement full `CloudIAMPrincipal` aggregate, IAM sync workers, privilege escalation analysis, cross-account trust detection, and IAM risk scoring. Project IAM entities as new graph node/edge kinds (ontology v8).

### Deliverables

1. **Domain Layer**
   - `CloudIAMPrincipal` aggregate
   - `PolicyAttachment`, `TrustRelationship`, `IAMRiskIndicator`, `EffectivePermissions` value objects
   - `IAMPrincipalType`, `PrivilegeLevel` enums
   - `IAMPrincipalDiscovered`, `PrivilegeEscalationPathDetected`, `CrossAccountTrustDiscovered`, `IAMRiskLevelChanged` events
   - `PrivilegeEscalationAnalysisService`, `IAMRiskAnalysisService` domain services

2. **Infrastructure Layer**
   - PostgreSQL: `cloud_iam_principals` table + migration
   - AWS IAM normalizer: Users, Roles, Policies, Groups, Service Principals
   - Azure normalizer: Managed Identities, Service Principals, AAD Users/Groups, Role Assignments
   - GCP normalizer: Service Accounts, IAM Bindings, Custom Roles
   - `CloudIAMSyncWorker` — hourly IAM sync
   - Security Graph ontology v8 (`IAM_ROLE`, `IAM_POLICY`, `ASSUMES_ROLE`, `HAS_POLICY`, `TRUSTS`, `ESCALATES_TO` node/edge kinds)

3. **Application Layer**
   - `DetectPrivilegeEscalationCommand`, `BuildIAMGraphCommand` handlers
   - `ListIAMRiskPrincipalsQuery` handler

4. **Tests**
   - Unit: privilege escalation path detection (BFS logic, graph fixtures)
   - Unit: risk indicator scoring
   - Integration: IAM sync against LocalStack
   - Integration: graph ontology v8 validation (new edge kinds, valid pair enforcement)

### Dependencies
- P2 complete (CloudAsset and CLOUD_ACCOUNT nodes exist in graph)
- Security Graph ontology validation (M4) — ontology version bump to v8

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Ontology v8 breaks existing graph projections | Low | High | Ontology changes are additive only; existing edge kinds unchanged |
| Effective permissions computation is expensive at scale | High | Medium | Lazy computation with TTL cache; never persist as raw data |
| Azure AAD requires elevated permissions (Directory.Read.All) | Medium | Medium | Document required permissions; graceful degradation if not granted |

### Exit Criteria
- Privilege escalation paths detected and emitted as domain events on test fixtures
- IAM risk scoring produces `PrivilegeLevel.ADMIN` for accounts with `iam:*` policy
- Cross-account trust detection correctly identifies external trust targets
- 70+ new tests (cumulative: 190+)

### Quality Gates
- `EffectivePermissions` is never persisted to the database (only `attached_policies` + `trust_relationships`)
- Ontology v8 EDGE_ONTOLOGY table updated with valid-pair guards for all new edge kinds
- IAM sync handles soft-deleted principals (setting `is_deleted=true` rather than hard-deleting)

---

## Phase 4: CSPM

### Objective
Implement the CSPM policy engine, deliver the initial policy library (AWS/Azure/GCP), implement drift detection, and wire CSPMFinding production into the M24 compliance ACL.

### Deliverables

1. **Domain Layer**
   - `CSPMFinding` aggregate, `CSPMRule`, `RemediationGuidance`, `ComplianceRef` value objects
   - `CSPMPolicyEvaluator` domain service
   - `DriftDetectionService` domain service
   - All CSPMFinding domain events

2. **Infrastructure Layer**
   - PostgreSQL: `cspm_findings`, `cspm_policies` tables + migration
   - CSPM policy library (YAML):
     - AWS: 30+ policies (S3, EC2, IAM, RDS, VPC, CloudTrail, KMS, Lambda)
     - Azure: 20+ policies (Storage, NSG, SQL, AKS, KeyVault, Functions)
     - GCP: 15+ policies (GCS, Compute, GKE, CloudSQL, IAM)
   - `CSPMAssessmentWorker` — event-driven (CloudAssetUpdated) + scheduled full-sweep
   - `CSPMFindingToComplianceACL` — projects findings into M24

3. **Application Layer**
   - `EvaluateCSPMPoliciesCommand`, `ListCSPMFindingsQuery` handlers

4. **Tests**
   - Unit: policy condition evaluator for each YAML condition type
   - Unit: drift detection (before/after NormalizedConfig comparison)
   - Integration: full CSPM sweep on mock AWS account
   - Integration: ComplianceACL correctly maps framework_id to M24 framework

### Dependencies
- P2 complete (CloudAsset with NormalizedConfig)
- Compliance (M24) — `ComplianceFrameworkRepository` for ref resolution

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| CSPM policy expression language security (eval injection) | High | High | Policy conditions evaluated against a safe restricted evaluator (no arbitrary Python eval) |
| Policy library maintenance burden | Medium | Medium | Policies sourced from CIS benchmarks; PR review required for policy changes |
| Drift detection false positives on provider-managed tag changes | Medium | Low | Tag-change exclusion list per provider; configurable drift sensitivity |

### Exit Criteria
- 65+ CSPM policies across three providers evaluated correctly against test assets
- Drift detection emits `CloudPostureStateChanged` within one sync cycle of a config change
- M24 compliance posture correctly reflects open CSPM findings
- 80+ new tests (cumulative: 270+)

### Quality Gates
- Policy YAML files pass JSON schema validation in CI
- Policy condition evaluator has no access to `__builtins__`, `eval`, `exec`, or `import`
- Every CSPM finding references at least one compliance framework mapping

---

## Phase 5: Kubernetes Security

### Objective
Implement Kubernetes cluster discovery and synchronization for EKS, AKS, and GKE. Implement workload security analysis, RBAC risk analysis, network policy gap detection, and K8s security scoring.

### Deliverables

1. **Domain Layer**
   - `KubernetesCluster` aggregate with nested entities
   - `K8sRBACAnalysisService`, `K8sWorkloadAnalysisService` domain services
   - All K8s domain events

2. **Infrastructure Layer**
   - PostgreSQL: `kubernetes_clusters` table + migration
   - EKS adapter — kubeconfig from credential_vault, `boto3` for cluster metadata
   - AKS adapter — `azure-mgmt-containerservice` for cluster metadata
   - GKE adapter — `google-cloud-container` for cluster metadata
   - Kubernetes client adapter — shared `kubernetes` Python client for in-cluster resources (pods, RBAC, network policies) using kubeconfig
   - `K8sSyncWorker` — 15-minute cadence
   - Security Graph: `K8S_WORKLOAD`, `K8S_NAMESPACE`, `RUNS_IN` node/edge kinds (ontology v8 additions)

3. **Application Layer**
   - `SyncKubernetesClusterCommand` handler

4. **Tests**
   - Unit: RBAC wildcard detection logic
   - Unit: privilege escalation detection (ClusterAdmin binding to service accounts)
   - Integration: mock K8s API server responses (using `pytest-kubernetes` or custom fixture)

### Dependencies
- P2 complete (CloudAsset for EKS/AKS/GKE cluster parent)
- P3 complete (IAM principals for service account binding analysis)

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Kubernetes API version fragmentation (v1.24–v1.30+) | Medium | Medium | Use `kubernetes` client's preferred version negotiation; test against 1.27 and 1.30 |
| Kubeconfig credentials short-lived (EKS token TTL = 15 min) | High | Low | Re-fetch token from `credential_vault` before each K8s API call |
| Large clusters (500+ nodes) | Medium | Medium | Paginated list calls; namespace-scoped queries where possible |

### Exit Criteria
- EKS/AKS/GKE clusters discovered and synced from mock provider responses
- `K8sRBACViolationDetected` events fired for `cluster-admin` bound service accounts
- `K8sSecurityScore` computed and accessible via query
- 60+ new tests (cumulative: 330+)

### Quality Gates
- K8s client never caches kubeconfig credentials beyond the token TTL
- RBAC analysis handles missing API server responses gracefully (partial results, not crash)

---

## Phase 6: Runtime Visibility

### Objective
Implement cloud audit log ingestion pipelines for all three providers. Implement the `RuntimeCorrelationEngine` for suspicious activity detection and wire into the M21 Investigation bounded context via ACL.

### Deliverables

1. **Domain Layer**
   - `CloudRuntimeEvent` aggregate
   - `RuntimeEventSource`, `EventOutcome` value objects
   - `CloudRuntimeEventRepository` interface
   - `SuspiciousActivityDetected`, `APIAbuseDetected`, `CredentialCompromiseIndicatorDetected` domain events

2. **Infrastructure Layer**
   - PostgreSQL: `cloud_runtime_events` table (range-partitioned by month) + migration
   - AWS CloudTrail ingestion: SQS-triggered S3 event reader + normalizer
   - Azure Activity Log ingestion: Event Hub consumer + normalizer
   - GCP Audit Log ingestion: Pub/Sub subscriber + normalizer
   - `RuntimeCorrelationEngine` — rule-based detection (brute force, unusual region, impossible travel, API abuse patterns)
   - `CloudRuntimeEventToInvestigationACL` — M21 integration
   - `RuntimeEventIngestionWorker` — continuous polling with DLQ integration (M29)

3. **Tests**
   - Unit: correlation rules (test fixtures for each detection type)
   - Integration: CloudTrail S3 ingestion (LocalStack S3 + SQS)
   - Integration: M21 ACL produces valid `InvestigationCorrelationRequest`

### Dependencies
- P1 complete (CloudAccount context)
- Investigation (M21) — `InvestigationCase` correlation API
- DLQ/replay (M29) — for failed event ingestion retry

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| CloudTrail S3 lag (up to 15 minutes) | High | Low | Design for eventual consistency; timeline correlation uses `event_time`, not `ingested_at` |
| Event volume at scale (10M+ events/day) | High | High | Partitioned table with 90-day hot tier; async batch inserts |
| False positive rate for correlation rules | Medium | Medium | Tunable confidence thresholds; suppression by asset/principal |

### Exit Criteria
- CloudTrail events ingested and normalized from LocalStack S3
- `SuspiciousActivityDetected` event fires for brute-force pattern in test fixture
- M21 ACL correctly creates investigation correlation from suspicious runtime event
- 65+ new tests (cumulative: 395+)

### Quality Gates
- Runtime events table is range-partitioned before any production data is written (migration must include partition DDL)
- `raw_payload` column has max 64KB limit enforced at application layer (truncate, do not reject)
- DLQ integration verified: failed ingestion events appear in DLQ and can be replayed

---

## Phase 7: Cloud AI Services

### Objective
Implement `CloudAIService` discovery and security analysis for Bedrock, Azure OpenAI, Vertex AI, and SageMaker. Project AI services into M22 Inventory. Implement AI-specific security checks.

### Deliverables

1. **Domain Layer**
   - `CloudAIService` aggregate, `DeployedModel`, `AIEndpoint`, `AIDataSource` entities
   - `CloudAIServiceType`, `AIServicePosture`, `AIRiskIndicator` value objects
   - `CloudAIServiceRepository` interface
   - `CloudAIServiceDiscovered`, `CloudAIServiceExposed` domain events

2. **Infrastructure Layer**
   - PostgreSQL: `cloud_ai_services` table + migration
   - AWS: Bedrock adapter (ListFoundationModels, ListCustomModels, InvokeModel endpoint listing), SageMaker adapter
   - Azure: Azure OpenAI Service adapter (Management API + deployments listing)
   - GCP: Vertex AI adapter (endpoints, model registry, AutoML models)
   - Security Graph: `CLOUD_AI_SERVICE`, `EXPOSES_AI_SERVICE` node/edge kinds
   - `CloudAIServiceToInventoryACL` — projects to M22 as `AIAsset`

3. **CSPM Policies for AI Services**
   - Public endpoint without VPC endpoint / Private Link
   - No logging enabled
   - No content filtering (Bedrock Guardrails)
   - Over-permissive IAM access to model invocation

4. **Tests**
   - Unit: AI service normalizer per provider
   - Unit: AI-specific CSPM policy evaluations
   - Integration: Bedrock adapter against LocalStack (limited support) / mock responses

### Dependencies
- P2 complete (CloudAsset as parent)
- P3 complete (IAM principals for access analysis)
- P4 complete (CSPM engine for AI-specific policies)
- Inventory (M22) — `AIAsset` projection

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Provider AI service APIs are rapidly evolving | High | Medium | Adapter encapsulates all API calls; domain model changes only when service semantics change |
| Bedrock/Vertex API not fully supported by LocalStack | High | Medium | Mock adapter responses for integration tests; contract tests against real APIs in CI/CD |

### Exit Criteria
- Bedrock, Azure OpenAI, Vertex AI, SageMaker services discoverable and normalized
- `CloudAIServiceExposed` fires for publicly accessible endpoints
- AI assets appear in M22 Inventory with correct `asset_class = AI_SERVICE`
- 50+ new tests (cumulative: 445+)

### Quality Gates
- `CLOUD_AI_SERVICE` graph node carries `provider_id` and `service_type` properties (queryable by Attack Path engine)
- AI service endpoints with `network_exposure = PUBLIC` always produce a CSPM finding

---

## Phase 8: Risk Engine & Dashboards

### Objective
Implement the `CloudRiskScoringService` aggregating inputs from all prior phases plus M13/M24/M25/M15. Deliver all eight dashboard read models. Finalize all worker registrations in the `RuntimeContainer`.

### Deliverables

1. **Domain Layer**
   - `CloudRiskScore` aggregate, `RiskScoreComponent` entity
   - `CloudRiskScoringService` domain service
   - `CloudRiskScoreComputed`, `CloudRiskScoreCrossedThreshold` events
   - `CloudRiskScoreRepository` interface

2. **Infrastructure Layer**
   - PostgreSQL: `cloud_risk_scores` table + migration
   - ACL implementations: `ThreatIntelACL`, `ExposureGraphACL`, `AttackPathACL`
   - `CloudRiskCalculationWorker` — event-driven, recomputes on any input signal change

3. **Dashboard Read Models (PostgreSQL materialized views)**
   - `cloud_security.mv_executive_summary` — aggregated risk posture
   - `cloud_security.mv_soc_alerts` — near-real-time suspicious events + open critical findings
   - `cloud_security.mv_cloud_inventory` — asset count by type/account/region
   - `cloud_security.mv_cloud_risk_ranked` — top-100 highest-risk assets
   - `cloud_security.mv_identity_risk` — IAM risk principals ranked by privilege level
   - `cloud_security.mv_k8s_security` — cluster security scores + workload violations
   - `cloud_security.mv_compliance_posture` — CSPM finding coverage per compliance framework
   - `cloud_security.mv_ai_services` — AI service inventory + exposure status

4. **Worker Registration**
   - All 10 M26 workers registered in `RuntimeContainer`
   - Health checks registered for all workers
   - Backpressure + bulkhead limits configured per worker

5. **Tests**
   - Unit: risk score formula with known inputs
   - Unit: weight normalization (sum of weights = 1.0)
   - Integration: full risk computation pipeline (end-to-end from CloudAsset → CloudRiskScore)
   - Integration: materialized view refresh correctness

6. **API Routes (OpenAPI)**
   - `GET /api/v1/cloud/providers`
   - `GET /api/v1/cloud/accounts`
   - `GET /api/v1/cloud/assets`
   - `GET /api/v1/cloud/assets/{id}`
   - `GET /api/v1/cloud/cspm/findings`
   - `GET /api/v1/cloud/iam/principals`
   - `GET /api/v1/cloud/k8s/clusters`
   - `GET /api/v1/cloud/ai-services`
   - `GET /api/v1/cloud/risk/scores`
   - `GET /api/v1/cloud/dashboards/executive`
   - `GET /api/v1/cloud/dashboards/soc`
   - `POST /api/v1/cloud/providers` (register)
   - `POST /api/v1/cloud/accounts/{id}/sync` (trigger sync)

### Dependencies
- P1–P7 complete
- Threat Intelligence (M13/M22) — enrichment queries
- Compliance (M24) — compliance posture reads
- Exposure (M25) — exposure score reads
- Attack Path (M15) — attack path membership queries
- RuntimeContainer (M26/existing) — worker registration

### Risks

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Risk score computation latency at scale (10k+ assets) | High | Medium | Async worker-based computation; stale score TTL with staleness indicator |
| Materialized view refresh contention | Medium | Medium | CONCURRENTLY refresh; scheduled off-peak |
| Dashboard query performance degradation | Medium | Medium | All dashboards read from materialized views, never command tables |

### Exit Criteria
- `CloudRiskScore` correctly produced for a test asset using all seven input dimensions
- All 8 dashboard read models return correct data in integration tests
- All 10 workers registered and passing health check in RuntimeContainer
- All API routes returning correct responses with correct RBAC enforcement
- 55+ new tests (cumulative: 500+)

### Quality Gates
- Risk score weights sum to 1.0 (enforced by domain invariant)
- No dashboard route queries a command-side table directly (enforced by code review)
- All worker health checks respond within 500ms

---

## Total Test Target

| Phase | New Tests | Cumulative |
|---|---|---|
| Baseline (M38/39 post-sprint) | — | 3,254 |
| P1 | +45 | 3,299 |
| P2 | +80 | 3,379 |
| P3 | +70 | 3,449 |
| P4 | +80 | 3,529 |
| P5 | +60 | 3,589 |
| P6 | +65 | 3,654 |
| P7 | +50 | 3,704 |
| P8 | +55 | 3,759 |

---

## Cross-Phase Constraints

1. **No production code before architecture approval.** All phases blocked until this plan is approved.
2. **Ontology v8 is a single migration.** All new node/edge kinds are added in one ontology bump (P3), not incrementally across phases.
3. **No new graph engine.** All graph operations use the existing `SecurityGraphProjectionWorker` and PostgreSQL `security_graph_*` tables.
4. **No new compliance storage.** All compliance mapping uses M24 structures via the `CSPMFindingToComplianceACL`.
5. **Provider SDK pinning.** `boto3`, `azure-mgmt-*`, and `google-cloud-*` SDKs pinned to specific versions in `pyproject.toml` at the start of P1.
6. **Credential safety invariant.** `CredentialRef` is an opaque pointer. Raw credentials never appear in domain events, logs, or normalized config.
7. **Tenant isolation invariant.** Every repository method filters by `organization_id`. Violation is a P0 defect.
