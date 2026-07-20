"""PostgreSQL repository implementations for Kubernetes security aggregates."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import select

from redforge.domain.cloud_security.kubernetes.admission_policy import KubernetesAdmissionPolicy
from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
from redforge.domain.cloud_security.kubernetes.node import KubernetesNode
from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
from redforge.domain.cloud_security.kubernetes.service import KubernetesService
from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.kubernetes.mappings import (
    admission_from_model,
    admission_to_model,
    cluster_from_model,
    cluster_to_model,
    namespace_from_model,
    namespace_to_model,
    network_policy_from_model,
    network_policy_to_model,
    node_from_model,
    node_to_model,
    rbac_from_model,
    rbac_to_model,
    service_from_model,
    service_to_model,
    workload_from_model,
    workload_to_model,
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

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgKubernetesClusterRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, cluster: KubernetesCluster) -> None:
        existing = await self._session.get(KubernetesClusterModel, cluster.id.value)
        if existing is None:
            self._session.add(cluster_to_model(cluster))
        else:
            cluster_to_model(cluster, existing)
        await self._session.flush()

    async def get_by_id(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> KubernetesCluster | None:
        result = await self._session.execute(
            select(KubernetesClusterModel).where(
                KubernetesClusterModel.id == cluster_id,
                KubernetesClusterModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return cluster_from_model(row) if row is not None else None

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[KubernetesCluster]:
        result = await self._session.execute(
            select(KubernetesClusterModel)
            .where(KubernetesClusterModel.organization_id == str(organization_id))
            .order_by(KubernetesClusterModel.name.asc())
            .limit(max(1, min(limit, 500)))
            .offset(max(0, offset))
        )
        return [cluster_from_model(row) for row in result.scalars().all()]

    async def get_by_name(
        self, *, organization_id: OrganizationId, name: str
    ) -> KubernetesCluster | None:
        result = await self._session.execute(
            select(KubernetesClusterModel).where(
                KubernetesClusterModel.organization_id == str(organization_id),
                KubernetesClusterModel.name == name,
            )
        )
        row = result.scalar_one_or_none()
        return cluster_from_model(row) if row is not None else None


class PgKubernetesWorkloadRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, workload: KubernetesWorkload) -> None:
        existing = await self._session.get(KubernetesWorkloadModel, workload.id.value)
        if existing is None:
            self._session.add(workload_to_model(workload))
        else:
            workload_to_model(workload, existing)
        await self._session.flush()

    async def save_batch(self, workloads: list[KubernetesWorkload]) -> None:
        for workload in workloads:
            await self.save(workload)

    async def get_by_id(
        self, workload_id: UUID, *, organization_id: OrganizationId
    ) -> KubernetesWorkload | None:
        result = await self._session.execute(
            select(KubernetesWorkloadModel).where(
                KubernetesWorkloadModel.id == workload_id,
                KubernetesWorkloadModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return workload_from_model(row) if row is not None else None

    async def list_by_cluster(
        self,
        cluster_id: UUID,
        *,
        organization_id: OrganizationId,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[KubernetesWorkload]:
        stmt = select(KubernetesWorkloadModel).where(
            KubernetesWorkloadModel.cluster_id == cluster_id,
            KubernetesWorkloadModel.organization_id == str(organization_id),
        )
        if namespace is not None:
            stmt = stmt.where(KubernetesWorkloadModel.namespace == namespace)
        result = await self._session.execute(
            stmt.order_by(
                KubernetesWorkloadModel.namespace.asc(), KubernetesWorkloadModel.name.asc()
            )
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [workload_from_model(row) for row in result.scalars().all()]


class PgKubernetesRBACRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, principal: KubernetesRBACPrincipal) -> None:
        existing = await self._session.get(KubernetesRBACPrincipalModel, principal.id.value)
        if existing is None:
            self._session.add(rbac_to_model(principal))
        else:
            rbac_to_model(principal, existing)
        await self._session.flush()

    async def save_batch(self, principals: list[KubernetesRBACPrincipal]) -> None:
        for principal in principals:
            await self.save(principal)

    async def list_by_cluster(
        self,
        cluster_id: UUID,
        *,
        organization_id: OrganizationId,
        limit: int = 200,
        offset: int = 0,
    ) -> list[KubernetesRBACPrincipal]:
        result = await self._session.execute(
            select(KubernetesRBACPrincipalModel)
            .where(
                KubernetesRBACPrincipalModel.cluster_id == cluster_id,
                KubernetesRBACPrincipalModel.organization_id == str(organization_id),
            )
            .order_by(KubernetesRBACPrincipalModel.name.asc())
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [rbac_from_model(row) for row in result.scalars().all()]


class PgKubernetesNamespaceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, namespace: KubernetesNamespace) -> None:
        existing = await self._session.get(KubernetesNamespaceModel, namespace.id.value)
        if existing is None:
            self._session.add(namespace_to_model(namespace))
        else:
            namespace_to_model(namespace, existing)
        await self._session.flush()

    async def save_batch(self, namespaces: list[KubernetesNamespace]) -> None:
        for namespace in namespaces:
            await self.save(namespace)

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNamespace]:
        result = await self._session.execute(
            select(KubernetesNamespaceModel)
            .where(
                KubernetesNamespaceModel.cluster_id == cluster_id,
                KubernetesNamespaceModel.organization_id == str(organization_id),
            )
            .order_by(KubernetesNamespaceModel.name.asc())
        )
        return [namespace_from_model(row) for row in result.scalars().all()]


class PgKubernetesNodeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, node: KubernetesNode) -> None:
        existing = await self._session.get(KubernetesNodeModel, node.id.value)
        if existing is None:
            self._session.add(node_to_model(node))
        else:
            node_to_model(node, existing)
        await self._session.flush()

    async def save_batch(self, nodes: list[KubernetesNode]) -> None:
        for node in nodes:
            await self.save(node)

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNode]:
        result = await self._session.execute(
            select(KubernetesNodeModel)
            .where(
                KubernetesNodeModel.cluster_id == cluster_id,
                KubernetesNodeModel.organization_id == str(organization_id),
            )
            .order_by(KubernetesNodeModel.name.asc())
        )
        return [node_from_model(row) for row in result.scalars().all()]


class PgKubernetesServiceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, service: KubernetesService) -> None:
        existing = await self._session.get(KubernetesServiceModel, service.id.value)
        if existing is None:
            self._session.add(service_to_model(service))
        else:
            service_to_model(service, existing)
        await self._session.flush()

    async def save_batch(self, services: list[KubernetesService]) -> None:
        for service in services:
            await self.save(service)

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesService]:
        result = await self._session.execute(
            select(KubernetesServiceModel)
            .where(
                KubernetesServiceModel.cluster_id == cluster_id,
                KubernetesServiceModel.organization_id == str(organization_id),
            )
            .order_by(KubernetesServiceModel.namespace.asc(), KubernetesServiceModel.name.asc())
        )
        return [service_from_model(row) for row in result.scalars().all()]


class PgKubernetesNetworkPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, policy: KubernetesNetworkPolicy) -> None:
        existing = await self._session.get(KubernetesNetworkPolicyModel, policy.id.value)
        if existing is None:
            self._session.add(network_policy_to_model(policy))
        else:
            network_policy_to_model(policy, existing)
        await self._session.flush()

    async def save_batch(self, policies: list[KubernetesNetworkPolicy]) -> None:
        for policy in policies:
            await self.save(policy)

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesNetworkPolicy]:
        result = await self._session.execute(
            select(KubernetesNetworkPolicyModel)
            .where(
                KubernetesNetworkPolicyModel.cluster_id == cluster_id,
                KubernetesNetworkPolicyModel.organization_id == str(organization_id),
            )
            .order_by(
                KubernetesNetworkPolicyModel.namespace.asc(),
                KubernetesNetworkPolicyModel.name.asc(),
            )
        )
        return [network_policy_from_model(row) for row in result.scalars().all()]


class PgKubernetesAdmissionPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, policy: KubernetesAdmissionPolicy) -> None:
        existing = await self._session.get(KubernetesAdmissionPolicyModel, policy.id.value)
        if existing is None:
            self._session.add(admission_to_model(policy))
        else:
            admission_to_model(policy, existing)
        await self._session.flush()

    async def list_by_cluster(
        self, cluster_id: UUID, *, organization_id: OrganizationId
    ) -> list[KubernetesAdmissionPolicy]:
        result = await self._session.execute(
            select(KubernetesAdmissionPolicyModel)
            .where(
                KubernetesAdmissionPolicyModel.cluster_id == cluster_id,
                KubernetesAdmissionPolicyModel.organization_id == str(organization_id),
            )
            .order_by(KubernetesAdmissionPolicyModel.name.asc())
        )
        return [admission_from_model(row) for row in result.scalars().all()]
