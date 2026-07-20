"""Domain ↔ SQLAlchemy mappings for Kubernetes security aggregates."""

from __future__ import annotations

from redforge.domain.cloud_security.kubernetes.admission_policy import (
    AdmissionPolicyId,
    KubernetesAdmissionPolicy,
)
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.entities import (
    AdmissionViolation,
    NetworkRule,
    PodContainer,
    RBACBinding,
    ServiceAccountReference,
)
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import (
    KubernetesNetworkPolicy,
    NetworkPolicyId,
)
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode, NodeId
from redforge.domain.cloud_security.kubernetes.rbac import (
    KubernetesRBACPrincipal,
    RBACPrincipalId,
)
from redforge.domain.cloud_security.kubernetes.service import K8sServiceId, KubernetesService
from redforge.domain.cloud_security.kubernetes.value_objects import (
    AdmissionMode,
    ClusterId,
    K8sClusterType,
    K8sNetworkExposure,
    K8sSecurityScore,
    NamespaceId,
    PodSecurityLevel,
    RBACPrincipalKind,
    WorkloadExposure,
    WorkloadId,
    WorkloadKind,
)
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)
from redforge.infrastructure.database.models.cloud_security import (
    KubernetesAdmissionPolicyModel,
    KubernetesClusterModel,
    KubernetesNamespaceModel,
    KubernetesNetworkPolicyModel,
    KubernetesNodeModel,
    KubernetesRBACPrincipalModel,
    KubernetesServiceModel,
    KubernetesWorkloadModel,
)


def cluster_to_model(
    cluster: KubernetesCluster, existing: KubernetesClusterModel | None = None
) -> KubernetesClusterModel:
    row = existing or KubernetesClusterModel(id=cluster.id.value)
    row.organization_id = str(cluster.organization_id)
    row.cloud_account_id = cluster.cloud_account_id.value
    row.cloud_asset_id = cluster.cloud_asset_id.value if cluster.cloud_asset_id else None
    row.cluster_type = cluster.cluster_type.value
    row.name = cluster.name
    row.version = cluster.version
    row.api_server_endpoint = cluster.api_server_endpoint
    row.region = cluster.region
    row.credential_ref_id = cluster.credential_ref_id
    row.labels = dict(cluster.labels)
    row.pod_security_standards = dict(cluster.pod_security_standards)
    row.security_score = cluster.security_score.to_dict()
    row.discovered_at = cluster.discovered_at
    row.last_synced_at = cluster.last_synced_at
    row.created_at = cluster.created_at
    row.updated_at = cluster.updated_at
    row.row_version = cluster.row_version
    return row


def cluster_from_model(row: KubernetesClusterModel) -> KubernetesCluster:
    return KubernetesCluster(
        id=ClusterId(row.id),
        organization_id=OrganizationId(row.organization_id),
        cloud_account_id=CloudAccountId(row.cloud_account_id),
        cloud_asset_id=CloudAssetId(row.cloud_asset_id) if row.cloud_asset_id else None,
        cluster_type=K8sClusterType(row.cluster_type),
        name=row.name,
        version=row.version,
        api_server_endpoint=row.api_server_endpoint,
        region=row.region,
        credential_ref_id=row.credential_ref_id,
        labels=dict(row.labels or {}),
        pod_security_standards=dict(row.pod_security_standards or {}),
        security_score=K8sSecurityScore.from_dict(row.security_score),
        discovered_at=row.discovered_at,
        last_synced_at=row.last_synced_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def namespace_to_model(
    ns: KubernetesNamespace, existing: KubernetesNamespaceModel | None = None
) -> KubernetesNamespaceModel:
    row = existing or KubernetesNamespaceModel(id=ns.id.value)
    row.cluster_id = ns.cluster_id.value
    row.organization_id = str(ns.organization_id)
    row.name = ns.name
    row.labels = dict(ns.labels)
    row.annotations = dict(ns.annotations)
    row.pod_security_level = ns.pod_security_level
    row.resource_quotas = dict(ns.resource_quotas)
    row.has_network_policy = ns.has_network_policy
    row.created_at = ns.created_at
    row.updated_at = ns.updated_at
    row.row_version = ns.row_version
    return row


def namespace_from_model(row: KubernetesNamespaceModel) -> KubernetesNamespace:
    return KubernetesNamespace(
        id=NamespaceId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        name=row.name,
        labels=dict(row.labels or {}),
        annotations=dict(row.annotations or {}),
        pod_security_level=row.pod_security_level,
        resource_quotas=dict(row.resource_quotas or {}),
        has_network_policy=row.has_network_policy,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def workload_to_model(
    wl: KubernetesWorkload, existing: KubernetesWorkloadModel | None = None
) -> KubernetesWorkloadModel:
    row = existing or KubernetesWorkloadModel(id=wl.id.value)
    row.cluster_id = wl.cluster_id.value
    row.organization_id = str(wl.organization_id)
    row.namespace = wl.namespace
    row.name = wl.name
    row.kind = wl.kind.value
    row.uid = wl.uid
    row.service_account = wl.service_account.to_dict()
    row.containers = [c.to_dict() for c in wl.containers]
    row.host_network = wl.host_network
    row.host_pid = wl.host_pid
    row.host_ipc = wl.host_ipc
    row.privileged = wl.privileged
    row.security_level = wl.security_level.value
    row.exposure = wl.exposure.value
    row.labels = dict(wl.labels)
    row.annotations = dict(wl.annotations)
    row.replicas = wl.replicas
    row.created_at = wl.created_at
    row.updated_at = wl.updated_at
    row.row_version = wl.row_version
    return row


def workload_from_model(row: KubernetesWorkloadModel) -> KubernetesWorkload:
    containers = tuple(
        PodContainer.from_dict(c) for c in (row.containers or []) if isinstance(c, dict)
    )
    return KubernetesWorkload(
        id=WorkloadId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        namespace=row.namespace,
        name=row.name,
        kind=WorkloadKind(row.kind),
        uid=row.uid,
        service_account=ServiceAccountReference.from_dict(row.service_account),
        containers=containers,
        host_network=row.host_network,
        host_pid=row.host_pid,
        host_ipc=row.host_ipc,
        privileged=row.privileged,
        security_level=PodSecurityLevel(row.security_level),
        exposure=WorkloadExposure(row.exposure),
        labels=dict(row.labels or {}),
        annotations=dict(row.annotations or {}),
        replicas=row.replicas,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def node_to_model(
    node: KubernetesNode, existing: KubernetesNodeModel | None = None
) -> KubernetesNodeModel:
    row = existing or KubernetesNodeModel(id=node.id.value)
    row.cluster_id = node.cluster_id.value
    row.organization_id = str(node.organization_id)
    row.name = node.name
    row.uid = node.uid
    row.kubelet_version = node.kubelet_version
    row.os_image = node.os_image
    row.container_runtime = node.container_runtime
    row.roles = list(node.roles)
    row.labels = dict(node.labels)
    row.taints = list(node.taints)
    row.unschedulable = node.unschedulable
    row.created_at = node.created_at
    row.updated_at = node.updated_at
    row.row_version = node.row_version
    return row


def node_from_model(row: KubernetesNodeModel) -> KubernetesNode:
    return KubernetesNode(
        id=NodeId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        name=row.name,
        uid=row.uid,
        kubelet_version=row.kubelet_version,
        os_image=row.os_image,
        container_runtime=row.container_runtime,
        roles=tuple(str(x) for x in (row.roles or [])),
        labels=dict(row.labels or {}),
        taints=tuple(str(x) for x in (row.taints or [])),
        unschedulable=row.unschedulable,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def service_to_model(
    svc: KubernetesService, existing: KubernetesServiceModel | None = None
) -> KubernetesServiceModel:
    row = existing or KubernetesServiceModel(id=svc.id.value)
    row.cluster_id = svc.cluster_id.value
    row.organization_id = str(svc.organization_id)
    row.namespace = svc.namespace
    row.name = svc.name
    row.service_type = svc.service_type
    row.cluster_ip = svc.cluster_ip
    row.external_ips = list(svc.external_ips)
    row.load_balancer_ingress = list(svc.load_balancer_ingress)
    row.ports = [dict(p) for p in svc.ports]
    row.selector = dict(svc.selector)
    row.exposure = svc.exposure.value
    row.is_public = svc.is_public
    row.created_at = svc.created_at
    row.updated_at = svc.updated_at
    row.row_version = svc.row_version
    return row


def service_from_model(row: KubernetesServiceModel) -> KubernetesService:
    return KubernetesService(
        id=K8sServiceId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        namespace=row.namespace,
        name=row.name,
        service_type=row.service_type,
        cluster_ip=row.cluster_ip,
        external_ips=tuple(str(x) for x in (row.external_ips or [])),
        load_balancer_ingress=tuple(str(x) for x in (row.load_balancer_ingress or [])),
        ports=tuple(dict(p) for p in (row.ports or []) if isinstance(p, dict)),
        selector=dict(row.selector or {}),
        exposure=K8sNetworkExposure(row.exposure),
        is_public=row.is_public,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def rbac_to_model(
    principal: KubernetesRBACPrincipal,
    existing: KubernetesRBACPrincipalModel | None = None,
) -> KubernetesRBACPrincipalModel:
    row = existing or KubernetesRBACPrincipalModel(id=principal.id.value)
    row.cluster_id = principal.cluster_id.value
    row.organization_id = str(principal.organization_id)
    row.kind = principal.kind.value
    row.name = principal.name
    row.namespace = principal.namespace
    row.bindings = [b.to_dict() for b in principal.bindings]
    row.roles = list(principal.roles)
    row.cluster_roles = list(principal.cluster_roles)
    row.trust_references = list(principal.trust_references)
    row.created_at = principal.created_at
    row.updated_at = principal.updated_at
    row.row_version = principal.row_version
    return row


def rbac_from_model(row: KubernetesRBACPrincipalModel) -> KubernetesRBACPrincipal:
    bindings = tuple(RBACBinding.from_dict(b) for b in (row.bindings or []) if isinstance(b, dict))
    return KubernetesRBACPrincipal(
        id=RBACPrincipalId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        kind=RBACPrincipalKind(row.kind),
        name=row.name,
        namespace=row.namespace,
        bindings=bindings,
        roles=tuple(str(x) for x in (row.roles or [])),
        cluster_roles=tuple(str(x) for x in (row.cluster_roles or [])),
        trust_references=tuple(str(x) for x in (row.trust_references or [])),
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def network_policy_to_model(
    policy: KubernetesNetworkPolicy,
    existing: KubernetesNetworkPolicyModel | None = None,
) -> KubernetesNetworkPolicyModel:
    row = existing or KubernetesNetworkPolicyModel(id=policy.id.value)
    row.cluster_id = policy.cluster_id.value
    row.organization_id = str(policy.organization_id)
    row.namespace = policy.namespace
    row.name = policy.name
    row.pod_selector = dict(policy.pod_selector)
    row.policy_types = list(policy.policy_types)
    row.ingress_rules = [r.to_dict() for r in policy.ingress_rules]
    row.egress_rules = [r.to_dict() for r in policy.egress_rules]
    row.allows_cross_namespace = policy.allows_cross_namespace
    row.created_at = policy.created_at
    row.updated_at = policy.updated_at
    row.row_version = policy.row_version
    return row


def network_policy_from_model(row: KubernetesNetworkPolicyModel) -> KubernetesNetworkPolicy:
    return KubernetesNetworkPolicy(
        id=NetworkPolicyId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        namespace=row.namespace,
        name=row.name,
        pod_selector=dict(row.pod_selector or {}),
        policy_types=tuple(str(x) for x in (row.policy_types or [])),
        ingress_rules=tuple(
            NetworkRule.from_dict(r) for r in (row.ingress_rules or []) if isinstance(r, dict)
        ),
        egress_rules=tuple(
            NetworkRule.from_dict(r) for r in (row.egress_rules or []) if isinstance(r, dict)
        ),
        allows_cross_namespace=row.allows_cross_namespace,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )


def admission_to_model(
    policy: KubernetesAdmissionPolicy,
    existing: KubernetesAdmissionPolicyModel | None = None,
) -> KubernetesAdmissionPolicyModel:
    row = existing or KubernetesAdmissionPolicyModel(id=policy.id.value)
    row.cluster_id = policy.cluster_id.value
    row.organization_id = str(policy.organization_id)
    row.name = policy.name
    row.mode = policy.mode.value
    row.controller = policy.controller
    row.rules = [dict(r) for r in policy.rules]
    row.violations = [v.to_dict() for v in policy.violations]
    row.evaluated_at = policy.evaluated_at
    row.created_at = policy.created_at
    row.updated_at = policy.updated_at
    row.row_version = policy.row_version
    return row


def admission_from_model(row: KubernetesAdmissionPolicyModel) -> KubernetesAdmissionPolicy:
    return KubernetesAdmissionPolicy(
        id=AdmissionPolicyId(row.id),
        cluster_id=ClusterId(row.cluster_id),
        organization_id=OrganizationId(row.organization_id),
        name=row.name,
        mode=AdmissionMode(row.mode),
        controller=row.controller,
        rules=tuple(dict(r) for r in (row.rules or []) if isinstance(r, dict)),
        violations=tuple(
            AdmissionViolation.from_dict(v) for v in (row.violations or []) if isinstance(v, dict)
        ),
        evaluated_at=row.evaluated_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        row_version=row.row_version,
    )
