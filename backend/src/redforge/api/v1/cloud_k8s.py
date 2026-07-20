"""M26 Phase 5 Kubernetes Security APIs — cluster inventory and posture."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field

from redforge.api.dependencies import get_kubernetes_security_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.cloud_security.kubernetes.dtos import (
    DiscoverClusterCommand,
    EvaluateClusterCommand,
)
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.cloud_security.kubernetes.security_service import (
        KubernetesSecurityService,
    )

router = APIRouter(prefix="/cloud-foundation", tags=["cloud-foundation"])


class DiscoverClusterRequest(BaseModel):
    cloud_account_id: UUID
    cloud_asset_id: UUID | None = None
    credential_ref_id: str = ""
    cluster_type: str | None = None
    name: str | None = None
    version: str | None = None
    api_server_endpoint: str | None = None
    region: str | None = None
    sync_inventory: bool = True


class ClusterResponse(BaseModel):
    cluster_id: UUID
    organization_id: str
    cloud_account_id: UUID
    cloud_asset_id: UUID | None
    cluster_type: str
    name: str
    version: str
    api_server_endpoint: str
    region: str
    security_score: dict[str, Any]
    labels: dict[str, str] = Field(default_factory=dict)
    pod_security_standards: dict[str, str] = Field(default_factory=dict)
    discovered_at: str
    last_synced_at: str | None
    created_at: str
    updated_at: str


class NamespaceResponse(BaseModel):
    namespace_id: UUID
    cluster_id: UUID
    name: str
    pod_security_level: str
    has_network_policy: bool
    labels: dict[str, str] = Field(default_factory=dict)


class WorkloadResponse(BaseModel):
    workload_id: UUID
    cluster_id: UUID
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
    containers: list[dict[str, Any]] = Field(default_factory=list)
    service_account: dict[str, Any] = Field(default_factory=dict)
    posture_snapshot: dict[str, Any] = Field(default_factory=dict)


class RBACPrincipalResponse(BaseModel):
    principal_id: UUID
    cluster_id: UUID
    kind: str
    name: str
    namespace: str
    inventory: dict[str, Any] = Field(default_factory=dict)


class NetworkPolicyResponse(BaseModel):
    policy_id: UUID
    cluster_id: UUID
    namespace: str
    name: str
    policy_types: list[str] = Field(default_factory=list)
    allows_cross_namespace: bool
    pod_selector: dict[str, str] = Field(default_factory=dict)


class ViolationResponse(BaseModel):
    workload_id: UUID
    policy_id: str
    rule_id: str
    severity: str
    title: str
    message: str
    passed: bool


class EvaluationResponse(BaseModel):
    cluster_id: UUID
    workloads_evaluated: int
    policies_evaluated: int
    violations: list[ViolationResponse] = Field(default_factory=list)
    security_score: dict[str, Any] = Field(default_factory=dict)


class ComplianceSummaryResponse(BaseModel):
    cluster_id: UUID
    security_score: dict[str, Any]
    workload_count: int
    privileged_count: int
    public_exposure_count: int
    namespaces_without_network_policy: int
    rbac_wildcard_count: int


def _cluster_response(dto: Any) -> ClusterResponse:
    return ClusterResponse(
        cluster_id=UUID(dto.cluster_id),
        organization_id=dto.organization_id,
        cloud_account_id=UUID(dto.cloud_account_id),
        cloud_asset_id=UUID(dto.cloud_asset_id) if dto.cloud_asset_id else None,
        cluster_type=dto.cluster_type,
        name=dto.name,
        version=dto.version,
        api_server_endpoint=dto.api_server_endpoint,
        region=dto.region,
        security_score=dict(dto.security_score),
        labels=dict(dto.labels),
        pod_security_standards=dict(dto.pod_security_standards),
        discovered_at=dto.discovered_at.isoformat(),
        last_synced_at=dto.last_synced_at.isoformat() if dto.last_synced_at else None,
        created_at=dto.created_at.isoformat(),
        updated_at=dto.updated_at.isoformat(),
    )


@router.post(
    "/k8s/clusters/discover",
    response_model=ClusterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def discover_cluster(
    body: DiscoverClusterRequest,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> ClusterResponse:
    dto = await service.discover_cluster(
        DiscoverClusterCommand(
            organization_id=tenant.organization_id,
            cloud_account_id=body.cloud_account_id,
            cloud_asset_id=body.cloud_asset_id,
            credential_ref_id=body.credential_ref_id,
            cluster_type=body.cluster_type,
            name=body.name,
            version=body.version,
            api_server_endpoint=body.api_server_endpoint,
            region=body.region,
            sync_inventory=body.sync_inventory,
        )
    )
    return _cluster_response(dto)


@router.get("/k8s/clusters", response_model=list[ClusterResponse])
async def list_clusters(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> list[ClusterResponse]:
    items = await service.list_clusters(tenant.organization_id, limit=limit, offset=offset)
    return [_cluster_response(c) for c in items]


@router.get("/k8s/clusters/{cluster_id}", response_model=ClusterResponse)
async def get_cluster(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> ClusterResponse:
    dto = await service.get_cluster(tenant.organization_id, cluster_id)
    return _cluster_response(dto)


@router.get(
    "/k8s/clusters/{cluster_id}/namespaces",
    response_model=list[NamespaceResponse],
)
async def list_namespaces(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> list[NamespaceResponse]:
    items = await service.list_namespaces(tenant.organization_id, cluster_id)
    return [
        NamespaceResponse(
            namespace_id=UUID(ns.namespace_id),
            cluster_id=UUID(ns.cluster_id),
            name=ns.name,
            pod_security_level=ns.pod_security_level,
            has_network_policy=ns.has_network_policy,
            labels=dict(ns.labels),
        )
        for ns in items
    ]


@router.get(
    "/k8s/clusters/{cluster_id}/workloads",
    response_model=list[WorkloadResponse],
)
async def list_workloads(
    cluster_id: UUID,
    namespace: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> list[WorkloadResponse]:
    items = await service.list_workloads(
        tenant.organization_id,
        cluster_id,
        namespace=namespace,
        limit=limit,
        offset=offset,
    )
    return [
        WorkloadResponse(
            workload_id=UUID(w.workload_id),
            cluster_id=UUID(w.cluster_id),
            namespace=w.namespace,
            name=w.name,
            kind=w.kind,
            privileged=w.privileged,
            host_network=w.host_network,
            host_pid=w.host_pid,
            host_ipc=w.host_ipc,
            security_level=w.security_level,
            exposure=w.exposure,
            replicas=w.replicas,
            containers=list(w.containers),
            service_account=dict(w.service_account),
            posture_snapshot=dict(w.posture_snapshot),
        )
        for w in items
    ]


@router.get(
    "/k8s/clusters/{cluster_id}/workloads/{workload_id}",
    response_model=WorkloadResponse,
)
async def get_workload(
    cluster_id: UUID,
    workload_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> WorkloadResponse:
    w = await service.get_workload(tenant.organization_id, cluster_id, workload_id)
    return WorkloadResponse(
        workload_id=UUID(w.workload_id),
        cluster_id=UUID(w.cluster_id),
        namespace=w.namespace,
        name=w.name,
        kind=w.kind,
        privileged=w.privileged,
        host_network=w.host_network,
        host_pid=w.host_pid,
        host_ipc=w.host_ipc,
        security_level=w.security_level,
        exposure=w.exposure,
        replicas=w.replicas,
        containers=list(w.containers),
        service_account=dict(w.service_account),
        posture_snapshot=dict(w.posture_snapshot),
    )


@router.get(
    "/k8s/clusters/{cluster_id}/rbac",
    response_model=list[RBACPrincipalResponse],
)
async def list_rbac(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> list[RBACPrincipalResponse]:
    items = await service.list_rbac(tenant.organization_id, cluster_id)
    return [
        RBACPrincipalResponse(
            principal_id=UUID(p.principal_id),
            cluster_id=UUID(p.cluster_id),
            kind=p.kind,
            name=p.name,
            namespace=p.namespace,
            inventory=dict(p.inventory),
        )
        for p in items
    ]


@router.get(
    "/k8s/clusters/{cluster_id}/network-policies",
    response_model=list[NetworkPolicyResponse],
)
async def list_network_policies(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> list[NetworkPolicyResponse]:
    items = await service.list_network_policies(tenant.organization_id, cluster_id)
    return [
        NetworkPolicyResponse(
            policy_id=UUID(p.policy_id),
            cluster_id=UUID(p.cluster_id),
            namespace=p.namespace,
            name=p.name,
            policy_types=list(p.policy_types),
            allows_cross_namespace=p.allows_cross_namespace,
            pod_selector=dict(p.pod_selector),
        )
        for p in items
    ]


@router.post(
    "/k8s/clusters/{cluster_id}/evaluate",
    response_model=EvaluationResponse,
)
async def evaluate_cluster(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_MANAGE)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> EvaluationResponse:
    result = await service.evaluate_cluster(
        EvaluateClusterCommand(
            organization_id=tenant.organization_id,
            cluster_id=cluster_id,
        )
    )
    return EvaluationResponse(
        cluster_id=UUID(result.cluster_id),
        workloads_evaluated=result.workloads_evaluated,
        policies_evaluated=result.policies_evaluated,
        violations=[
            ViolationResponse(
                workload_id=UUID(v.workload_id),
                policy_id=v.policy_id,
                rule_id=v.rule_id,
                severity=v.severity,
                title=v.title,
                message=v.message,
                passed=v.passed,
            )
            for v in result.violations
        ],
        security_score=dict(result.security_score),
    )


@router.get(
    "/k8s/clusters/{cluster_id}/compliance-summary",
    response_model=ComplianceSummaryResponse,
)
async def compliance_summary(
    cluster_id: UUID,
    tenant: TenantContext = Depends(require_permission(Permission.ORG_READ)),
    service: KubernetesSecurityService = Depends(get_kubernetes_security_service),
) -> ComplianceSummaryResponse:
    summary = await service.compliance_summary(tenant.organization_id, cluster_id)
    return ComplianceSummaryResponse(
        cluster_id=UUID(summary.cluster_id),
        security_score=dict(summary.security_score),
        workload_count=summary.workload_count,
        privileged_count=summary.privileged_count,
        public_exposure_count=summary.public_exposure_count,
        namespaces_without_network_policy=summary.namespaces_without_network_policy,
        rbac_wildcard_count=summary.rbac_wildcard_count,
    )
