# M26 Architecture Freeze — Enterprise Cloud Security Platform

**Status:** ARCHITECTURE FREEZE — PENDING APPROVAL  
**Milestone:** M26  
**Theme:** Enterprise Cloud Security Platform  
**Date:** 2026-07-19  
**Author:** Principal Enterprise Security Architect  

---

## 1. Executive Summary

M26 introduces a provider-agnostic **Cloud Security Platform** bounded context that delivers unified visibility, identity risk analysis, posture management, and runtime threat detection across AWS, Microsoft Azure, and Google Cloud Platform. It reuses the existing **Security Graph** (M4/M22), **Attack Path Engine** (M15), **Threat Intelligence** (M13/M22), **Compliance Intelligence** (M24), **Exposure Management** (M25), and **Inventory** (M22) rather than recreating any of them. The bounded context adds the cloud-native abstractions—provider accounts, unified cloud assets, IAM graph, CSPM policies, K8s security, and runtime audit event pipelines—that the existing platform deliberately deferred.

---

## 2. Bounded Context Definition

### 2.1 Context Name

`cloud_security`

### 2.2 Bounded Context Responsibilities

| Responsibility | Owned by M26 | Delegated to Existing BC |
|---|---|---|
| Cloud provider account/subscription/project management | ✅ | — |
| Unified cloud asset model (compute, storage, network, K8s, AI) | ✅ | — |
| Cloud credential vault integration | ✅ | credential_vault (existing) |
| Cloud IAM graph (roles, policies, trust, privilege escalation) | ✅ | — |
| CSPM misconfiguration detection | ✅ | — |
| Drift detection | ✅ | — |
| K8s cluster/workload/RBAC security | ✅ | — |
| Runtime audit event ingestion (CloudTrail, Activity, GCP Audit) | ✅ | — |
| Cloud AI service inventory (Bedrock, Azure OpenAI, Vertex, SageMaker) | ✅ | — |
| Cloud risk scoring | ✅ | — |
| Graph node/edge projection | ✅ (produces) | Security Graph (M4) consumes |
| Attack path computation | — | Attack Path Engine (M15) |
| Compliance policy evaluation | Produces findings | Compliance (M24) evaluates |
| Threat intelligence enrichment | Consumes | TI (M13/M22) |
| Investigation case management | Produces events | Investigation (M21) |
| Exposure scoring | Produces inputs | Exposure (M25) |
| Asset inventory synchronization | Produces CloudAsset records | Inventory (M22) |

### 2.3 Context Map

```
cloud_security ──[upstream/producer]──► security_graph      (M4)
cloud_security ──[upstream/producer]──► inventory           (M22)
cloud_security ──[upstream/producer]──► compliance          (M24)
cloud_security ──[upstream/producer]──► exposure            (M25)
cloud_security ──[upstream/producer]──► investigation       (M21)
cloud_security ──[downstream/consumer]─ threat_intel        (M13/M22)
cloud_security ──[downstream/consumer]─ attack_path         (M15)
cloud_security ──[conformist]──────────  organizations      (M2)
cloud_security ──[conformist]──────────  rbac               (M3)
cloud_security ──[shared kernel]────────  platform          (M12)
```

---

## 3. Domain Model

### 3.1 Aggregates

#### 3.1.1 `CloudProvider`

Root of cloud provider configuration for a tenant organization.

```
CloudProvider
├── id: CloudProviderId
├── organization_id: OrganizationId          ← conformist: M2 org boundary
├── provider_type: CloudProviderType         ← AWS | AZURE | GCP
├── display_name: str
├── discovery_config: DiscoveryConfig
├── status: CloudProviderStatus
├── created_at: datetime
└── updated_at: datetime
```

**Domain Events:** `CloudProviderRegistered`, `CloudProviderUpdated`, `CloudProviderDisabled`

#### 3.1.2 `CloudAccount`

A single cloud billing/administrative unit (AWS account, Azure subscription, GCP project).

```
CloudAccount
├── id: CloudAccountId
├── cloud_provider_id: CloudProviderId
├── organization_id: OrganizationId
├── external_id: str                         ← AWS account ID / Azure sub UUID / GCP project ID
├── display_name: str
├── account_type: CloudAccountType           ← ROOT | MEMBER | STANDALONE
├── regions: list[CloudRegion]
├── credential_ref: CredentialRef            ← opaque pointer into credential_vault
├── sync_state: AccountSyncState
├── metadata: CloudAccountMetadata
└── tags: dict[str, str]
```

**Domain Events:** `CloudAccountDiscovered`, `CloudAccountSyncStarted`, `CloudAccountSyncCompleted`, `CloudAccountSyncFailed`, `CloudAccountCredentialRotated`

#### 3.1.3 `CloudAsset`

Unified model for any discoverable cloud resource. This is M26's primary aggregate and the source of truth for all cloud resource state within this bounded context.

```
CloudAsset
├── id: CloudAssetId
├── cloud_account_id: CloudAccountId
├── organization_id: OrganizationId
├── asset_type: CloudAssetType               ← closed enum (see §3.3)
├── provider_id: str                         ← native ARN / resource ID / full resource name
├── region: CloudRegion
├── availability_zone: Optional[AvailabilityZone]
├── display_name: str
├── provider_metadata: ProviderMetadata      ← opaque JSON, provider-specific
├── normalized_config: NormalizedConfig      ← structured, provider-agnostic
├── tags: dict[str, str]
├── relationships: list[AssetRelationship]
├── posture_state: CloudPostureState
├── last_seen_at: datetime
├── first_seen_at: datetime
└── is_deleted: bool
```

**Domain Events:** `CloudAssetDiscovered`, `CloudAssetUpdated`, `CloudAssetDeleted`, `CloudAssetRelationshipDiscovered`, `CloudPostureStateChanged`

#### 3.1.4 `CloudIAMPrincipal`

An identity in the cloud provider's IAM system.

```
CloudIAMPrincipal
├── id: CloudIAMPrincipalId
├── cloud_account_id: CloudAccountId
├── organization_id: OrganizationId
├── principal_type: IAMPrincipalType         ← USER | ROLE | SERVICE_PRINCIPAL | GROUP | MANAGED_IDENTITY | SERVICE_ACCOUNT
├── provider_id: str                         ← ARN / object ID / email
├── display_name: str
├── attached_policies: list[PolicyAttachment]
├── trust_relationships: list[TrustRelationship]
├── effective_permissions: EffectivePermissions   ← computed, not persisted raw
├── privilege_level: PrivilegeLevel          ← NONE | LOW | MEDIUM | HIGH | ADMIN
├── is_federated: bool
├── is_human: bool
├── last_activity_at: Optional[datetime]
└── risk_indicators: list[IAMRiskIndicator]
```

**Domain Events:** `IAMPrincipalDiscovered`, `IAMPrincipalUpdated`, `PrivilegeEscalationPathDetected`, `CrossAccountTrustDiscovered`, `IAMRiskLevelChanged`

#### 3.1.5 `CSPMFinding`

A misconfiguration or policy violation on a cloud asset.

```
CSPMFinding
├── id: CSPMFindingId
├── cloud_asset_id: CloudAssetId
├── organization_id: OrganizationId
├── policy_id: CSPMPolicyId
├── rule_id: CSPMRuleId
├── severity: FindingSeverity               ← CRITICAL | HIGH | MEDIUM | LOW | INFO
├── title: str
├── description: str
├── remediation: RemediationGuidance
├── compliance_mapping: list[ComplianceRef]  ← links to M24 frameworks
├── status: CSPMFindingStatus               ← OPEN | ACKNOWLEDGED | RESOLVED | SUPPRESSED
├── detected_at: datetime
├── resolved_at: Optional[datetime]
└── evidence: CSPMEvidence
```

**Domain Events:** `CSPMFindingOpened`, `CSPMFindingResolved`, `CSPMFindingSuppressed`, `CSPMFindingReopened`

#### 3.1.6 `KubernetesCluster`

A Kubernetes cluster and its security posture.

```
KubernetesCluster
├── id: KubernetesClusterId
├── cloud_asset_id: CloudAssetId            ← parent CloudAsset
├── organization_id: OrganizationId
├── cloud_account_id: CloudAccountId
├── cluster_type: K8sClusterType            ← EKS | AKS | GKE | SELF_MANAGED
├── version: str
├── api_server_endpoint: str
├── namespaces: list[K8sNamespace]
├── node_groups: list[K8sNodeGroup]
├── workloads: list[K8sWorkload]
├── rbac_policies: list[K8sRBACPolicy]
├── network_policies: list[K8sNetworkPolicy]
├── pod_security_standards: PodSecurityStandards
└── security_score: K8sSecurityScore
```

**Domain Events:** `K8sClusterDiscovered`, `K8sWorkloadUpdated`, `K8sRBACViolationDetected`, `K8sPodSecurityViolationDetected`, `K8sNetworkPolicyGapDetected`

#### 3.1.7 `CloudRuntimeEvent`

An ingested audit/activity event from a cloud provider.

```
CloudRuntimeEvent
├── id: CloudRuntimeEventId
├── cloud_account_id: CloudAccountId
├── organization_id: OrganizationId
├── event_source: RuntimeEventSource        ← CLOUDTRAIL | AZURE_ACTIVITY | GCP_AUDIT
├── event_time: datetime
├── event_name: str
├── principal_id: Optional[str]
├── source_ip: Optional[str]
├── target_resource: Optional[str]
├── outcome: EventOutcome                   ← SUCCESS | FAILURE | UNKNOWN
├── raw_payload: dict                       ← normalized from provider format
├── correlated_finding_ids: list[CSPMFindingId]
└── risk_score: Optional[float]
```

**Domain Events:** `CloudRuntimeEventIngested`, `SuspiciousActivityDetected`, `APIAbuseDetected`, `CredentialCompromiseIndicatorDetected`

#### 3.1.8 `CloudAIService`

An AI/ML service in the cloud environment.

```
CloudAIService
├── id: CloudAIServiceId
├── cloud_asset_id: CloudAssetId
├── organization_id: OrganizationId
├── service_type: CloudAIServiceType        ← BEDROCK | AZURE_OPENAI | VERTEX_AI | SAGEMAKER | REKOGNITION | COGNITIVE_SERVICES | AUTOML
├── models: list[DeployedModel]
├── endpoints: list[AIEndpoint]
├── data_sources: list[AIDataSource]
├── iam_principals: list[CloudIAMPrincipalId]
├── network_exposure: NetworkExposure
├── security_posture: AIServicePosture
└── risk_indicators: list[AIRiskIndicator]
```

**Domain Events:** `CloudAIServiceDiscovered`, `CloudAIServiceExposed`, `CloudAIServicePostureChanged`

#### 3.1.9 `CloudRiskScore`

Composite risk score for a cloud asset, computed by the Risk Engine.

```
CloudRiskScore
├── id: CloudRiskScoreId
├── cloud_asset_id: CloudAssetId
├── organization_id: OrganizationId
├── overall_score: float                    ← 0.0–10.0
├── threat_intel_score: float
├── compliance_score: float
├── identity_score: float
├── exposure_score: float
├── business_criticality_score: float
├── attack_path_score: float
├── score_components: list[RiskScoreComponent]
├── computed_at: datetime
└── valid_until: datetime
```

**Domain Events:** `CloudRiskScoreComputed`, `CloudRiskScoreExpired`, `CloudRiskScoreCrossedThreshold`

---

### 3.2 Entities (non-root)

| Entity | Parent Aggregate | Description |
|---|---|---|
| `CloudRegion` | CloudAccount | Enabled region with endpoint metadata |
| `AvailabilityZone` | CloudAccount | AZ within a region |
| `AssetRelationship` | CloudAsset | Directed relationship between two assets |
| `NormalizedConfig` | CloudAsset | Provider-agnostic parsed configuration |
| `PolicyAttachment` | CloudIAMPrincipal | Policy bound to a principal |
| `TrustRelationship` | CloudIAMPrincipal | Cross-account or federated trust |
| `IAMRiskIndicator` | CloudIAMPrincipal | Specific risk signal (unused role, wildcard, etc.) |
| `CSPMRule` | CSPMFinding | Individual check within a policy |
| `RemediationGuidance` | CSPMFinding | Step-by-step fix instructions |
| `K8sNamespace` | KubernetesCluster | Namespace with resource quotas and policies |
| `K8sWorkload` | KubernetesCluster | Pod/Deployment/DaemonSet/StatefulSet |
| `K8sRBACPolicy` | KubernetesCluster | ClusterRole or Role binding |
| `DeployedModel` | CloudAIService | Inference model version and config |
| `AIEndpoint` | CloudAIService | API endpoint with exposure details |
| `RiskScoreComponent` | CloudRiskScore | Individual score dimension with rationale |

---

### 3.3 Value Objects

| Value Object | Type | Description |
|---|---|---|
| `CloudProviderId` | UUID | Tenant-scoped provider identity |
| `CloudAccountId` | UUID | Tenant-scoped account identity |
| `CloudAssetId` | UUID | Stable UUID assigned by RedForge |
| `CloudAssetType` | Closed enum | `EC2_INSTANCE \| S3_BUCKET \| RDS_INSTANCE \| LAMBDA_FUNCTION \| VPC \| SUBNET \| SECURITY_GROUP \| LOAD_BALANCER \| EKS_CLUSTER \| ECS_CLUSTER \| ECR_REPOSITORY \| IAM_ROLE \| IAM_USER \| IAM_POLICY \| KMS_KEY \| SECRETS_MANAGER_SECRET \| ROUTE53_ZONE \| CLOUDFRONT_DISTRIBUTION \| AZURE_VM \| AZURE_STORAGE_ACCOUNT \| AZURE_SQL_DATABASE \| AZURE_VNET \| AZURE_NSG \| AZURE_AKS_CLUSTER \| AZURE_FUNCTION_APP \| AZURE_KEYVAULT \| AZURE_OPENAI_SERVICE \| GCP_COMPUTE_INSTANCE \| GCP_STORAGE_BUCKET \| GCP_CLOUD_SQL \| GCP_VPC_NETWORK \| GCP_GKE_CLUSTER \| GCP_CLOUD_FUNCTION \| GCP_SECRET_MANAGER \| GCP_VERTEX_AI_ENDPOINT \| SAGEMAKER_ENDPOINT \| BEDROCK_MODEL \| UNKNOWN` |
| `CloudProviderType` | Closed enum | `AWS \| AZURE \| GCP` |
| `CloudAccountType` | Closed enum | `ROOT \| MEMBER \| STANDALONE` |
| `IAMPrincipalType` | Closed enum | see §3.1.4 |
| `PrivilegeLevel` | Closed enum | `NONE \| LOW \| MEDIUM \| HIGH \| ADMIN` |
| `CSPMFindingStatus` | Closed enum | `OPEN \| ACKNOWLEDGED \| RESOLVED \| SUPPRESSED` |
| `FindingSeverity` | Closed enum | `CRITICAL \| HIGH \| MEDIUM \| LOW \| INFO` |
| `RuntimeEventSource` | Closed enum | `CLOUDTRAIL \| AZURE_ACTIVITY \| GCP_AUDIT` |
| `EventOutcome` | Closed enum | `SUCCESS \| FAILURE \| UNKNOWN` |
| `CloudAIServiceType` | Closed enum | see §3.1.8 |
| `NetworkExposure` | VO | `PUBLIC \| PRIVATE \| VPN_ONLY \| UNKNOWN` with port/protocol details |
| `ComplianceRef` | VO | `framework_id + control_id` pointer into M24 compliance |
| `CredentialRef` | VO | Opaque reference into credential_vault, never contains secret material |
| `DiscoveryConfig` | VO | Polling interval, region filter, service filter, tags filter |
| `AccountSyncState` | VO | `PENDING \| SYNCING \| SYNCED \| FAILED` with timestamps |
| `EffectivePermissions` | VO | Computed permission set (not persisted as raw data) |

---

### 3.4 Domain Events (Complete Inventory)

| Event | Source Aggregate | Consumed By |
|---|---|---|
| `CloudProviderRegistered` | CloudProvider | Worker (triggers account discovery) |
| `CloudProviderDisabled` | CloudProvider | Worker (halts sync) |
| `CloudAccountDiscovered` | CloudAccount | Worker (triggers asset sync) |
| `CloudAccountSyncCompleted` | CloudAccount | Risk Engine, Graph Projector |
| `CloudAssetDiscovered` | CloudAsset | Graph Projector, Inventory ACL, Risk Engine |
| `CloudAssetUpdated` | CloudAsset | Graph Projector, CSPM Assessor, Risk Engine |
| `CloudAssetDeleted` | CloudAsset | Graph Projector, Inventory ACL |
| `CloudPostureStateChanged` | CloudAsset | CSPM service, Risk Engine |
| `IAMPrincipalDiscovered` | CloudIAMPrincipal | IAM Graph Builder, Risk Engine |
| `PrivilegeEscalationPathDetected` | CloudIAMPrincipal | Risk Engine, Investigation ACL |
| `CrossAccountTrustDiscovered` | CloudIAMPrincipal | IAM Graph Builder, Risk Engine |
| `IAMRiskLevelChanged` | CloudIAMPrincipal | Risk Engine, Dashboard |
| `CSPMFindingOpened` | CSPMFinding | Risk Engine, Compliance ACL, Graph Projector |
| `CSPMFindingResolved` | CSPMFinding | Risk Engine |
| `K8sClusterDiscovered` | KubernetesCluster | Graph Projector |
| `K8sRBACViolationDetected` | KubernetesCluster | Risk Engine, Investigation ACL |
| `CloudRuntimeEventIngested` | CloudRuntimeEvent | Correlation Engine |
| `SuspiciousActivityDetected` | CloudRuntimeEvent | Investigation ACL, Risk Engine |
| `CloudAIServiceDiscovered` | CloudAIService | Inventory ACL, Risk Engine |
| `CloudAIServiceExposed` | CloudAIService | Risk Engine, Graph Projector |
| `CloudRiskScoreComputed` | CloudRiskScore | Exposure ACL, Dashboard |
| `CloudRiskScoreCrossedThreshold` | CloudRiskScore | Alert Engine |

---

## 4. Repository Interfaces

```python
# All interfaces live in domain/cloud_security/repositories.py
# Implementations live in infrastructure/cloud_security/

class CloudProviderRepository(Protocol):
    def save(self, provider: CloudProvider) -> None: ...
    def get_by_id(self, id: CloudProviderId) -> Optional[CloudProvider]: ...
    def list_by_organization(self, org_id: OrganizationId) -> list[CloudProvider]: ...

class CloudAccountRepository(Protocol):
    def save(self, account: CloudAccount) -> None: ...
    def get_by_id(self, id: CloudAccountId) -> Optional[CloudAccount]: ...
    def list_by_provider(self, provider_id: CloudProviderId) -> list[CloudAccount]: ...
    def list_by_organization(self, org_id: OrganizationId, *, page: int, size: int) -> Page[CloudAccount]: ...
    def get_by_external_id(self, provider_type: CloudProviderType, external_id: str, org_id: OrganizationId) -> Optional[CloudAccount]: ...

class CloudAssetRepository(Protocol):
    def save(self, asset: CloudAsset) -> None: ...
    def save_batch(self, assets: list[CloudAsset]) -> None: ...
    def get_by_id(self, id: CloudAssetId) -> Optional[CloudAsset]: ...
    def get_by_provider_id(self, account_id: CloudAccountId, provider_id: str) -> Optional[CloudAsset]: ...
    def list_by_account(self, account_id: CloudAccountId, asset_type: Optional[CloudAssetType], *, page: int, size: int) -> Page[CloudAsset]: ...
    def list_by_organization(self, org_id: OrganizationId, *, page: int, size: int) -> Page[CloudAsset]: ...
    def mark_deleted(self, provider_ids: set[str], account_id: CloudAccountId) -> int: ...

class CloudIAMPrincipalRepository(Protocol):
    def save(self, principal: CloudIAMPrincipal) -> None: ...
    def save_batch(self, principals: list[CloudIAMPrincipal]) -> None: ...
    def list_by_account(self, account_id: CloudAccountId) -> list[CloudIAMPrincipal]: ...
    def list_high_privilege(self, org_id: OrganizationId) -> list[CloudIAMPrincipal]: ...

class CSPMFindingRepository(Protocol):
    def save(self, finding: CSPMFinding) -> None: ...
    def get_by_id(self, id: CSPMFindingId) -> Optional[CSPMFinding]: ...
    def list_open_by_asset(self, asset_id: CloudAssetId) -> list[CSPMFinding]: ...
    def list_by_organization(self, org_id: OrganizationId, severity: Optional[FindingSeverity], *, page: int, size: int) -> Page[CSPMFinding]: ...
    def count_open_by_severity(self, org_id: OrganizationId) -> dict[FindingSeverity, int]: ...

class KubernetesClusterRepository(Protocol):
    def save(self, cluster: KubernetesCluster) -> None: ...
    def list_by_organization(self, org_id: OrganizationId) -> list[KubernetesCluster]: ...

class CloudRuntimeEventRepository(Protocol):
    def save_batch(self, events: list[CloudRuntimeEvent]) -> None: ...
    def list_by_account(self, account_id: CloudAccountId, *, since: datetime, page: int, size: int) -> Page[CloudRuntimeEvent]: ...
    def list_suspicious(self, org_id: OrganizationId, *, since: datetime) -> list[CloudRuntimeEvent]: ...

class CloudAIServiceRepository(Protocol):
    def save(self, service: CloudAIService) -> None: ...
    def list_by_organization(self, org_id: OrganizationId) -> list[CloudAIService]: ...
    def list_publicly_exposed(self, org_id: OrganizationId) -> list[CloudAIService]: ...

class CloudRiskScoreRepository(Protocol):
    def save(self, score: CloudRiskScore) -> None: ...
    def get_current_by_asset(self, asset_id: CloudAssetId) -> Optional[CloudRiskScore]: ...
    def list_critical_by_organization(self, org_id: OrganizationId, threshold: float) -> list[CloudRiskScore]: ...
```

---

## 5. Application Services

```
application/cloud_security/
├── register_cloud_provider.py          ← RegisterCloudProviderCommand
├── sync_cloud_account.py               ← SyncCloudAccountCommand (triggers worker)
├── assess_cloud_asset.py               ← AssessCloudAssetCommand
├── evaluate_cspm_policies.py           ← EvaluateCSPMPoliciesCommand
├── detect_iam_privilege_escalation.py  ← DetectPrivilegeEscalationCommand
├── build_iam_graph.py                  ← BuildIAMGraphCommand
├── ingest_runtime_events.py            ← IngestRuntimeEventsCommand
├── compute_cloud_risk_score.py         ← ComputeCloudRiskScoreCommand
├── sync_k8s_cluster.py                 ← SyncKubernetesClusterCommand
├── list_cloud_assets.py                ← ListCloudAssetsQuery
├── get_cloud_asset_detail.py           ← GetCloudAssetDetailQuery
├── list_cspm_findings.py               ← ListCSPMFindingsQuery
├── get_cloud_risk_summary.py           ← GetCloudRiskSummaryQuery
└── list_iam_risk_principals.py         ← ListIAMRiskPrincipalsQuery
```

---

## 6. Provider Adapters (Anti-Corruption Layer)

Each provider adapter lives in `infrastructure/cloud_security/adapters/` and implements a shared `CloudProviderAdapter` protocol. The adapter is the only place that contains provider-specific SDKs, API calls, and response parsing.

```python
class CloudProviderAdapter(Protocol):
    """Implemented once per cloud provider. Never called outside infrastructure."""

    async def discover_accounts(self, credential: CloudCredential) -> list[DiscoveredAccount]: ...
    async def list_assets(self, account: CloudAccount, asset_types: list[CloudAssetType]) -> AsyncIterator[RawAsset]: ...
    async def list_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]: ...
    async def ingest_runtime_events(self, account: CloudAccount, since: datetime) -> AsyncIterator[RawRuntimeEvent]: ...
    async def describe_k8s_clusters(self, account: CloudAccount) -> AsyncIterator[RawK8sCluster]: ...
    async def list_ai_services(self, account: CloudAccount) -> AsyncIterator[RawAIService]: ...
```

### 6.1 AWS Adapter

`infrastructure/cloud_security/adapters/aws/`

- Uses `boto3` via the existing `credential_vault`
- Implements: EC2, S3, RDS, Lambda, VPC, EKS, ECR, IAM, KMS, Secrets Manager, Route53, CloudFront, Bedrock, SageMaker
- Runtime events: CloudTrail S3/CloudWatch Events via SQS

### 6.2 Azure Adapter

`infrastructure/cloud_security/adapters/azure/`

- Uses `azure-mgmt-*` SDKs
- Implements: VMs, Storage Accounts, SQL, VNets, NSGs, AKS, Functions, Key Vault, Azure OpenAI
- Runtime events: Azure Monitor Activity Log via Event Hub

### 6.3 GCP Adapter

`infrastructure/cloud_security/adapters/gcp/`

- Uses `google-cloud-*` SDKs
- Implements: Compute Engine, GCS, Cloud SQL, VPC, GKE, Cloud Functions, Secret Manager, Vertex AI
- Runtime events: GCP Audit Logs via Pub/Sub

### 6.4 Normalization Layer

`infrastructure/cloud_security/normalizers/`

Each adapter returns `RawAsset` / `RawIAMPrincipal` / `RawRuntimeEvent`. A provider-agnostic normalizer maps provider-specific fields to the `NormalizedConfig` value object. The domain layer never receives raw provider payloads.

---

## 7. Security Graph Integration (No New Engine)

M26 projects into the existing Security Graph (M4/M22) by producing `GraphProjectionEvent` objects consumed by the existing `SecurityGraphProjectionWorker`.

### 7.1 New Node Kinds (Ontology v8)

The ontology requires a single version bump to v8 for M26:

| New Node Kind | Maps From | Rationale |
|---|---|---|
| `CLOUD_ACCOUNT_GROUP` | AWS Organization / Azure Management Group / GCP Folder | Account hierarchy grouping |
| `IAM_ROLE` | CloudIAMPrincipal (ROLE type) | Distinct from IDENTITY — has trust policy |
| `IAM_POLICY` | CloudIAMPrincipal policy attachments (standalone policies) | Policy as a graph node |
| `K8S_WORKLOAD` | KubernetesCluster.workloads | Container workload unit |
| `K8S_NAMESPACE` | KubernetesCluster.namespaces | K8s isolation boundary |
| `CLOUD_AI_SERVICE` | CloudAIService | AI service endpoint in cloud |

### 7.2 New Edge Kinds (Ontology v8)

| New Edge Kind | Source Kind | Target Kind | Rationale |
|---|---|---|---|
| `ASSUMES_ROLE` | IDENTITY / SERVICE_IDENTITY | IAM_ROLE | IAM role assumption |
| `HAS_POLICY` | IAM_ROLE / IDENTITY | IAM_POLICY | Policy attachment |
| `TRUSTS` | IAM_ROLE | IAM_ROLE / IDENTITY | Cross-account trust |
| `RUNS_IN` | K8S_WORKLOAD | K8S_NAMESPACE | Workload namespace placement |
| `HOSTED_IN_ACCOUNT` | CLOUD_RESOURCE | CLOUD_ACCOUNT | Account containment (extends existing CONTAINS) |
| `ESCALATES_TO` | IAM_ROLE / IDENTITY | IAM_ROLE | Privilege escalation path |
| `EXPOSES_AI_SERVICE` | CLOUD_RESOURCE | CLOUD_AI_SERVICE | Asset hosts AI service |

---

## 8. Cloud IAM Graph (CIEM)

The IAM Graph is a read model projection of `CloudIAMPrincipal` aggregates into the Security Graph. It is not a separate storage layer.

### 8.1 Privilege Escalation Detection

The `PrivilegeEscalationAnalysisService` traverses the IAM Graph using depth-limited BFS to detect:

1. **Role chaining** — A → assumes → B → assumes → C where C has Admin
2. **Policy boundary bypass** — permissions boundary that can be removed by a non-admin
3. **Wildcard policy attachment** — `iam:*` or `*:*` on reachable policies
4. **Cross-account assume-role** — trust policy to external account IDs not in the organization
5. **Transitive resource-based policies** — S3 bucket policy granting cross-account access

### 8.2 Identity Risk Analysis

`IAMRiskAnalysisService` scores each principal on:

- Unused credentials (last activity > 90 days)
- Access keys not rotated (> 90 days)
- MFA not enabled (human users)
- Admin permissions on non-admin principals
- Root account activity
- Cross-account trust to unknown accounts
- Wildcard resource or action permissions

---

## 9. CSPM Policy Model

CSPM policies are stored in `infrastructure/cloud_security/cspm_policies/` as structured YAML. Each policy file specifies:

```yaml
id: CSPM-AWS-S3-001
title: S3 Bucket Public Access Not Blocked
severity: CRITICAL
provider: AWS
asset_type: S3_BUCKET
rule:
  condition: "normalized_config.block_public_acls == false OR normalized_config.block_public_policy == false"
remediation:
  steps:
    - "Enable S3 Block Public Access at the account level"
compliance_mapping:
  - framework: CIS_AWS_FOUNDATIONS
    control: "2.1.1"
  - framework: SOC2
    control: "CC6.1"
```

The `CSPMPolicyEvaluator` in the application layer evaluates each policy against the `NormalizedConfig` of a `CloudAsset`. Compliance mappings are resolved through the M24 Anti-Corruption Layer.

### 9.1 Drift Detection

`DriftDetectionService` compares the current `NormalizedConfig` snapshot to the previous known-good baseline stored in `CloudAsset.posture_state`. Any deviation triggers a `CloudPostureStateChanged` event and re-evaluation.

---

## 10. Kubernetes Security Model

### 10.1 Cluster Layers

```
KubernetesCluster
  └── Control Plane Security
        ├── API server audit logs
        ├── RBAC binding analysis
        └── Admission controller config
  └── Workload Security
        ├── Pod security standard (Privileged / Baseline / Restricted)
        ├── Privileged container detection
        ├── hostPath / hostNetwork / hostPID mount detection
        └── Capabilities analysis (SYS_ADMIN, NET_ADMIN, etc.)
  └── Network Security
        ├── Network policy coverage analysis
        ├── Ingress/egress exposure
        └── East-west traffic gap detection
  └── Image Security
        ├── Registry origin (public vs. private ECR/ACR/GCR)
        ├── Image age policy
        └── Digest pinning
  └── Secrets Security
        ├── Secrets mounted as env vars
        ├── RBAC access to secrets
        └── External secrets operator adoption
```

### 10.2 K8s RBAC Analysis

`K8sRBACAnalysisService` detects:

- Wildcard verb/resource bindings
- `cluster-admin` ClusterRoleBinding to service accounts
- Cross-namespace RBAC escalation
- RBAC grants to `system:anonymous` or `system:unauthenticated`

---

## 11. Runtime Visibility Architecture

### 11.1 Event Ingestion Pipeline

```
CloudTrail (S3/SQS)     ─┐
Azure Activity Log (EventHub) ─┤── CloudRuntimeEventIngestionWorker
GCP Audit Log (Pub/Sub) ─┘         │
                                    ▼
                          RawRuntimeEvent (provider-specific)
                                    │
                          RuntimeEventNormalizer (ACL)
                                    │
                          CloudRuntimeEvent (domain)
                                    │
                          RuntimeCorrelationEngine
                                    │
                    ┌───────────────┴──────────────┐
                    ▼                               ▼
           CSPMFinding enrichment         SuspiciousActivityDetected
                                                    │
                                          Investigation ACL (M21)
```

### 11.2 Timeline Integration

`CloudRuntimeEvent` records carry `event_time` and are projected into the M21 `InvestigationCase` timeline when correlated with an active investigation. The Investigation ACL translates `SuspiciousActivityDetected` into an `InvestigationCorrelationEvent` using the M21 Anti-Corruption Layer.

---

## 12. Cloud AI Service Security

### 12.1 AI Asset Inventory

`CloudAIService` aggregates are projected to the M22 `inventory` bounded context via the Inventory Anti-Corruption Layer (`CloudAIServiceToInventoryAdapter`). Each AI service becomes an `AIAsset` record in the inventory with `asset_class = AI_SERVICE`.

### 12.2 AI Service Security Checks

- Network exposure (public endpoint with no VPC endpoint)
- IAM permissions (over-permissive access to model endpoints)
- Data residency (model/training data region vs. compliance requirement)
- Logging and monitoring enabled
- Content filtering / guardrails enabled (Bedrock)
- Prompt injection exposure surface (public-facing endpoints)

---

## 13. Cloud Risk Engine

The `CloudRiskScoringService` aggregates signals from multiple bounded contexts to produce `CloudRiskScore`:

```
Inputs (consumed via ACL):
  ├── Threat Intelligence (M13)   → TI matches for asset IP/domain/ARN
  ├── Compliance (M24)            → Compliance posture score for asset
  ├── Identity (M26 CIEM)        → Privilege level of principals with access
  ├── Exposure (M25)              → Exposure score from exposure graph
  ├── Attack Path (M15)           → Is asset on a critical attack path?
  ├── CSPM Findings (M26)        → Open critical/high findings
  └── Business Criticality       → Tag-based or manual criticality label

Formula:
  overall_score = weighted_sum([
      TI_weight * ti_score,
      compliance_weight * compliance_score,
      identity_weight * identity_score,
      exposure_weight * exposure_score,
      attack_path_weight * attack_path_score,
      cspm_weight * cspm_score,
      criticality_weight * criticality_score,
  ])
  
  Weights are organization-configurable, with defaults:
  TI=0.20, Compliance=0.15, Identity=0.20, Exposure=0.15,
  AttackPath=0.15, CSPM=0.10, Criticality=0.05
```

---

## 14. Dashboard Architecture

All dashboards are read models composed from projections. No dashboard queries the command-side aggregate tables directly.

| Dashboard | Primary Data Sources | Refresh Strategy |
|---|---|---|
| Executive | CloudRiskScore, CSPMFinding counts, K8s score, compliance posture | 15-min materialized view |
| SOC | CloudRuntimeEvent (suspicious), CSPMFinding (CRITICAL/HIGH), IAM risk | Near-real-time (event-driven) |
| Cloud Inventory | CloudAsset by type/account/region | Sync-on-change + 5-min polling |
| Cloud Risk | CloudRiskScore ranked by score, breakdown by dimension | 15-min materialized view |
| Identity (CIEM) | CloudIAMPrincipal by privilege level, escalation paths | Sync-on-change |
| Kubernetes | KubernetesCluster security scores, workload violations | Sync-on-change |
| Compliance | ComplianceRef coverage via M24 ACL, open findings per framework | 30-min materialized view |
| AI Services | CloudAIService exposure, model inventory, risk indicators | Sync-on-change |

---

## 15. Worker Architecture

### 15.1 Workers

| Worker | Trigger | Description |
|---|---|---|
| `CloudDiscoveryWorker` | Scheduled (per-provider cadence) | Discovers accounts/subscriptions/projects |
| `CloudAssetSyncWorker` | Event-driven (`CloudAccountDiscovered`) + Scheduled | Paginated asset crawl, drift detection |
| `CloudIAMSyncWorker` | Scheduled (hourly) | IAM principal sync, privilege escalation analysis |
| `CSPMAssessmentWorker` | Event-driven (`CloudAssetUpdated`) | Evaluates CSPM policies against changed assets |
| `K8sSyncWorker` | Scheduled (15-min) | K8s cluster state sync, RBAC analysis |
| `RuntimeEventIngestionWorker` | Continuous (SQS/EventHub/Pub/Sub poll) | Runtime event ingestion and normalization |
| `CloudRiskCalculationWorker` | Event-driven (multiple triggers) | Recomputes CloudRiskScore when any input changes |
| `GraphProjectionWorker` | Event-driven (`CloudAsset*` events) | Projects cloud assets/IAM into Security Graph |
| `InventoryProjectionWorker` | Event-driven (`CloudAsset*` events) | Projects CloudAssets into M22 Inventory |
| `ComplianceProjectionWorker` | Event-driven (`CSPMFinding*` events) | Projects CSPM findings into M24 Compliance |

### 15.2 Worker Concurrency Controls

- All workers use the existing `BulkheadExecutor` (M26) with per-account worker isolation
- `CloudAssetSyncWorker` uses paginated batches of 500 assets with checkpoint-based resume
- `RuntimeEventIngestionWorker` uses the existing DLQ and replay pipeline (M29)
- All workers publish to the existing `EventBus` (M12)

---

## 16. Database Strategy

### 16.1 Tables (PostgreSQL)

All new tables are in the `cloud_security` schema.

| Table | Description | Primary Index |
|---|---|---|
| `cloud_providers` | CloudProvider aggregates | `(org_id, provider_type)` |
| `cloud_accounts` | CloudAccount aggregates | `(provider_id, external_id)` |
| `cloud_assets` | CloudAsset aggregates (JSONB for provider_metadata, normalized_config) | `(account_id, asset_type)`, `(org_id, asset_type)`, GIN on `tags` |
| `cloud_iam_principals` | CloudIAMPrincipal aggregates | `(account_id, principal_type)` |
| `cspm_findings` | CSPMFinding aggregates | `(asset_id, status)`, `(org_id, severity, status)` |
| `kubernetes_clusters` | KubernetesCluster aggregates | `(org_id, cluster_type)` |
| `cloud_runtime_events` | CloudRuntimeEvent (partitioned by month) | `(account_id, event_time)`, `(org_id, suspicious=true, event_time)` |
| `cloud_ai_services` | CloudAIService aggregates | `(org_id, service_type)` |
| `cloud_risk_scores` | CloudRiskScore (latest per asset) | `(asset_id)`, `(org_id, overall_score DESC)` |
| `cspm_policies` | CSPM policy definitions (versioned YAML snapshot) | `(provider, asset_type, rule_id)` |

### 16.2 Storage Reuse

- `cloud_accounts.id` is projected as a `CLOUD_ACCOUNT` node in the existing `security_graph_nodes` table (no new graph storage)
- `cloud_assets` are cross-referenced to `inventory_assets` (M22) by `cloud_asset_id` FK
- `cspm_findings` map to M24 compliance via `compliance_refs JSONB` column; no new compliance storage

### 16.3 Partitioning

`cloud_runtime_events` is range-partitioned by `event_time` with monthly partitions and a 12-month retention policy. Older partitions are archived to S3/GCS/ADLS before dropping.

---

## 17. Anti-Corruption Layers

### 17.1 Inventory ACL (`CloudAssetToInventoryACL`)

Translates `CloudAssetDiscovered` → `AIAsset` creation command in M22.  
Location: `infrastructure/cloud_security/acl/inventory_acl.py`

### 17.2 Compliance ACL (`CSPMFindingToComplianceACL`)

Translates `CSPMFindingOpened` → compliance evidence record in M24.  
Resolves `ComplianceRef.framework_id` against M24 `ComplianceFrameworkRepository`.  
Location: `infrastructure/cloud_security/acl/compliance_acl.py`

### 17.3 Investigation ACL (`CloudRuntimeEventToInvestigationACL`)

Translates `SuspiciousActivityDetected` → `InvestigationCorrelationRequest` in M21.  
Location: `infrastructure/cloud_security/acl/investigation_acl.py`

### 17.4 Threat Intelligence ACL (`ThreatIntelACL`)

Translates M13/M22 TI events into `ThreatIntelEnrichment` value objects consumed by the Risk Engine.  
Location: `infrastructure/cloud_security/acl/threat_intel_acl.py`

### 17.5 Exposure ACL (`ExposureGraphACL`)

Reads `ExposureScore` from M25 for a given asset.  
Location: `infrastructure/cloud_security/acl/exposure_acl.py`

### 17.6 Attack Path ACL (`AttackPathACL`)

Queries M15 for whether a given asset appears on any critical attack path.  
Location: `infrastructure/cloud_security/acl/attack_path_acl.py`

---

## 18. Multi-Tenancy & RBAC

- All aggregates carry `organization_id` at the root level
- Repository implementations apply `WHERE org_id = ?` to every query
- RBAC roles (from M3): `CLOUD_ADMIN`, `CLOUD_VIEWER`, `CSPM_OPERATOR`, `IAM_ANALYST`, `K8S_OPERATOR` — defined in M3's existing permission registry
- Cross-tenant data access is structurally prevented by the repository layer; no application-layer tenant checks are required

---

## 19. Open Decisions Requiring Architecture Review

| ID | Decision | Options | Recommendation |
|---|---|---|---|
| D-M26-1 | Runtime event storage retention | 12 months partitioned PG vs. offload to object store | 12 months PG + archive to cold storage at 90 days |
| D-M26-2 | IAM effective permissions computation | Inline at sync time vs. lazy at query time | Lazy with 1-hour TTL cache; never persist raw effective perms |
| D-M26-3 | CSPM policy distribution | YAML in-repo vs. versioned DB table | YAML in-repo with DB snapshot per evaluation run |
| D-M26-4 | K8s access method | In-cluster (agent) vs. kubeconfig from credential vault | Credential vault kubeconfig; no in-cluster agent in M26 |
| D-M26-5 | Ontology v8 guard | Hard fail vs. warning on unknown node/edge kind | Hard fail in production; warning only in test fixtures |
