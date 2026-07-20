"""DTOs for Kubernetes security application services."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class DiscoverClusterCommand:
    organization_id: str
    cloud_account_id: UUID
    cloud_asset_id: UUID | None = None
    credential_ref_id: str = ""
    cluster_type: str | None = None
    name: str | None = None
    version: str | None = None
    api_server_endpoint: str | None = None
    region: str | None = None
    sync_inventory: bool = True


@dataclass(frozen=True, slots=True)
class EvaluateClusterCommand:
    organization_id: str
    cluster_id: UUID
    provider_type: str = "*"


@dataclass(frozen=True, slots=True)
class GetClusterQuery:
    organization_id: str
    cluster_id: UUID


@dataclass(frozen=True, slots=True)
class ListClustersQuery:
    organization_id: str
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True, slots=True)
class ListClusterChildrenQuery:
    organization_id: str
    cluster_id: UUID
    namespace: str | None = None
    limit: int = 200
    offset: int = 0


@dataclass(frozen=True, slots=True)
class GetWorkloadQuery:
    organization_id: str
    cluster_id: UUID
    workload_id: UUID


@dataclass(frozen=True, slots=True)
class ClusterDTO:
    cluster_id: str
    organization_id: str
    cloud_account_id: str
    cloud_asset_id: str | None
    cluster_type: str
    name: str
    version: str
    api_server_endpoint: str
    region: str
    security_score: dict[str, Any]
    labels: dict[str, str]
    pod_security_standards: dict[str, str]
    discovered_at: datetime
    last_synced_at: datetime | None
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class NamespaceDTO:
    namespace_id: str
    cluster_id: str
    name: str
    pod_security_level: str
    has_network_policy: bool
    labels: dict[str, str]


@dataclass(frozen=True, slots=True)
class WorkloadDTO:
    workload_id: str
    cluster_id: str
    namespace: str
    name: str
    kind: str
    privileged: bool
    host_network: bool
    host_pid: bool
    host_ipc: bool
    security_level: str
    exposure: str
    replicas: int
    containers: list[dict[str, Any]]
    service_account: dict[str, Any]
    posture_snapshot: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RBACPrincipalDTO:
    principal_id: str
    cluster_id: str
    kind: str
    name: str
    namespace: str
    inventory: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NetworkPolicyDTO:
    policy_id: str
    cluster_id: str
    namespace: str
    name: str
    policy_types: list[str]
    allows_cross_namespace: bool
    pod_selector: dict[str, str]


@dataclass(frozen=True, slots=True)
class ViolationResultDTO:
    workload_id: str
    policy_id: str
    rule_id: str
    severity: str
    title: str
    message: str
    passed: bool


@dataclass(frozen=True, slots=True)
class EvaluationResultDTO:
    cluster_id: str
    workloads_evaluated: int
    policies_evaluated: int
    violations: list[ViolationResultDTO]
    security_score: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ComplianceSummaryDTO:
    cluster_id: str
    security_score: dict[str, Any]
    workload_count: int
    privileged_count: int
    public_exposure_count: int
    namespaces_without_network_policy: int
    rbac_wildcard_count: int
