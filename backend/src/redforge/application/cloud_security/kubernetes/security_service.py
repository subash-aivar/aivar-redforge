"""Facade composing Kubernetes discovery, sync, and posture evaluation services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from redforge.application.cloud_security.kubernetes.admission_policy_evaluation_service import (
    AdmissionPolicyEvaluationService,
)
from redforge.application.cloud_security.kubernetes.cluster_discovery_service import (
    ClusterDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.dtos import (
    ClusterDTO,
    ComplianceSummaryDTO,
    DiscoverClusterCommand,
    EvaluateClusterCommand,
    EvaluationResultDTO,
    NamespaceDTO,
    NetworkPolicyDTO,
    RBACPrincipalDTO,
    WorkloadDTO,
)
from redforge.application.cloud_security.kubernetes.inventory_projection_service import (
    InventoryProjectionService,
)
from redforge.application.cloud_security.kubernetes.network_policy_discovery_service import (
    NetworkPolicyDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.posture_evaluation_service import (
    PostureEvaluationService,
)
from redforge.application.cloud_security.kubernetes.rbac_discovery_service import (
    RBACDiscoveryService,
)
from redforge.application.cloud_security.kubernetes.workload_discovery_service import (
    WorkloadDiscoveryService,
)
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    RepoFactory = Callable[[AsyncSession], object]


class KubernetesSecurityService:
    """API-facing orchestrator over focused Phase 5 application services."""

    def __init__(
        self,
        *,
        cluster_discovery: ClusterDiscoveryService,
        workload_discovery: WorkloadDiscoveryService,
        rbac_discovery: RBACDiscoveryService,
        network_policy_discovery: NetworkPolicyDiscoveryService,
        inventory_projection: InventoryProjectionService,
        posture_evaluation: PostureEvaluationService,
        admission_evaluation: AdmissionPolicyEvaluationService,
        session_factory: SessionFactory,
        namespace_repo_factory: RepoFactory,
    ) -> None:
        self._clusters = cluster_discovery
        self._workloads = workload_discovery
        self._rbac = rbac_discovery
        self._network = network_policy_discovery
        self._inventory = inventory_projection
        self._posture = posture_evaluation
        self._admission = admission_evaluation
        self._session_factory = session_factory
        self._namespace_repo_factory = namespace_repo_factory

    async def discover_cluster(self, command: DiscoverClusterCommand) -> ClusterDTO:
        cluster = await self._clusters.discover(command)
        if command.sync_inventory:
            await self._inventory.sync(
                organization_id=command.organization_id,
                cluster_id=UUID(cluster.cluster_id),
            )
            return await self._clusters.get(command.organization_id, cluster.cluster_id)
        return cluster

    async def list_clusters(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ClusterDTO]:
        return await self._clusters.list_clusters(organization_id, limit=limit, offset=offset)

    async def get_cluster(self, organization_id: str, cluster_id: UUID) -> ClusterDTO:
        return await self._clusters.get(organization_id, str(cluster_id))

    async def list_namespaces(self, organization_id: str, cluster_id: UUID) -> list[NamespaceDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster = await self._clusters.get(organization_id, str(cluster_id))
            _ = cluster
            repo = self._namespace_repo_factory(uow.session)
            items = await repo.list_by_cluster(cluster_id, organization_id=org)  # type: ignore[attr-defined]
        return [
            NamespaceDTO(
                namespace_id=str(ns.id),
                cluster_id=str(ns.cluster_id),
                name=ns.name,
                pod_security_level=ns.pod_security_level,
                has_network_policy=ns.has_network_policy,
                labels=dict(ns.labels),
            )
            for ns in items
        ]

    async def list_workloads(
        self,
        organization_id: str,
        cluster_id: UUID,
        *,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[WorkloadDTO]:
        return await self._workloads.list_workloads(
            organization_id=organization_id,
            cluster_id=cluster_id,
            namespace=namespace,
            limit=limit,
            offset=offset,
        )

    async def get_workload(
        self, organization_id: str, cluster_id: UUID, workload_id: UUID
    ) -> WorkloadDTO:
        return await self._workloads.get_workload(
            organization_id=organization_id,
            cluster_id=cluster_id,
            workload_id=workload_id,
        )

    async def list_rbac(self, organization_id: str, cluster_id: UUID) -> list[RBACPrincipalDTO]:
        return await self._rbac.list_rbac(organization_id=organization_id, cluster_id=cluster_id)

    async def list_network_policies(
        self, organization_id: str, cluster_id: UUID
    ) -> list[NetworkPolicyDTO]:
        return await self._network.list_policies(
            organization_id=organization_id, cluster_id=cluster_id
        )

    async def evaluate_cluster(self, command: EvaluateClusterCommand) -> EvaluationResultDTO:
        return await self._posture.evaluate(command)

    async def compliance_summary(
        self, organization_id: str, cluster_id: UUID
    ) -> ComplianceSummaryDTO:
        return await self._posture.compliance_summary(
            organization_id=organization_id, cluster_id=cluster_id
        )

    async def evaluate_admission(
        self, organization_id: str, cluster_id: UUID
    ) -> list[dict[str, Any]]:
        return await self._admission.evaluate(
            organization_id=organization_id, cluster_id=cluster_id
        )
