"""Repository ports for Kubernetes security aggregates."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import OrganizationId


class KubernetesClusterRepository(Protocol):
    async def save(self, cluster: KubernetesCluster) -> None: ...

    async def get_by_id(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> KubernetesCluster | None: ...

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[KubernetesCluster]: ...

    async def get_by_name(
        self, *, organization_id: OrganizationId, name: str
    ) -> KubernetesCluster | None: ...


class KubernetesWorkloadRepository(Protocol):
    async def save(self, workload: KubernetesWorkload) -> None: ...

    async def save_batch(self, workloads: list[KubernetesWorkload]) -> None: ...

    async def get_by_id(
        self, workload_id: UUID, *, organization_id: OrganizationId
    ) -> KubernetesWorkload | None: ...

    async def list_by_cluster(
        self,
        cluster_id: UUID,
        *,
        organization_id: OrganizationId,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[KubernetesWorkload]: ...


class KubernetesRBACRepository(Protocol):
    async def save(self, principal: KubernetesRBACPrincipal) -> None: ...

    async def save_batch(self, principals: list[KubernetesRBACPrincipal]) -> None: ...

    async def list_by_cluster(
        self,
        cluster_id: UUID,
        *,
        organization_id: OrganizationId,
        limit: int = 200,
        offset: int = 0,
    ) -> list[KubernetesRBACPrincipal]: ...


class KubernetesNamespaceRepository(Protocol):
    async def save(self, namespace: KubernetesNamespace) -> None: ...

    async def save_batch(self, namespaces: list[KubernetesNamespace]) -> None: ...

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNamespace]: ...


class KubernetesNodeRepository(Protocol):
    async def save(self, node: KubernetesNode) -> None: ...

    async def save_batch(self, nodes: list[KubernetesNode]) -> None: ...

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNode]: ...


class KubernetesServiceRepository(Protocol):
    async def save(self, service: KubernetesService) -> None: ...

    async def save_batch(self, services: list[KubernetesService]) -> None: ...

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesService]: ...


class KubernetesNetworkPolicyRepository(Protocol):
    async def save(self, policy: KubernetesNetworkPolicy) -> None: ...

    async def save_batch(self, policies: list[KubernetesNetworkPolicy]) -> None: ...

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNetworkPolicy]: ...


class KubernetesAdmissionPolicyRepository(Protocol):
    async def save(self, policy: KubernetesAdmissionPolicy) -> None: ...

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesAdmissionPolicy]: ...
