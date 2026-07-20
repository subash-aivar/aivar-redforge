"""Discover Kubernetes workloads from inventory and persist."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from redforge.application.cloud_security.kubernetes.dtos import WorkloadDTO
from redforge.application.cloud_security.kubernetes.normalization_service import (
    KubernetesNormalizationService,
)
from redforge.domain.cloud_security.kubernetes.exceptions import (
    KubernetesClusterNotFoundError,
    KubernetesWorkloadNotFoundError,
)
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.infrastructure.cloud_security.kubernetes.inventory_port import (
        KubernetesInventoryPort,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    RepoFactory = Callable[[AsyncSession], object]


_WORKLOAD_KINDS = [
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Pod",
]


def _to_workload_dto(wl: object) -> WorkloadDTO:
    from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload

    assert isinstance(wl, KubernetesWorkload)
    return WorkloadDTO(
        workload_id=str(wl.id),
        cluster_id=str(wl.cluster_id),
        namespace=wl.namespace,
        name=wl.name,
        kind=wl.kind.value,
        privileged=wl.privileged,
        host_network=wl.host_network,
        host_pid=wl.host_pid,
        host_ipc=wl.host_ipc,
        security_level=wl.security_level.value,
        exposure=wl.exposure.value,
        replicas=wl.replicas,
        containers=[c.to_dict() for c in wl.containers],
        service_account=wl.service_account.to_dict(),
        posture_snapshot=wl.posture_snapshot(),
    )


class WorkloadDiscoveryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        workload_repo_factory: RepoFactory,
        inventory: KubernetesInventoryPort,
        normalizer: KubernetesNormalizationService | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._workload_repo_factory = workload_repo_factory
        self._inventory = inventory
        self._normalizer = normalizer or KubernetesNormalizationService()
        self._graph_acl = graph_acl

    async def discover(self, *, organization_id: str, cluster_id: UUID) -> list[WorkloadDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))
            resources = await self._inventory.list_resources(kinds=_WORKLOAD_KINDS)
            normalized = self._normalizer.normalize_resources(
                resources,
                cluster_id=ClusterId(cluster_id),
                organization_id=org,
            )
            workload_repo = self._workload_repo_factory(uow.session)
            await workload_repo.save_batch(normalized.workloads)  # type: ignore[attr-defined]
            cluster.mark_synced()
            await cluster_repo.save(cluster)  # type: ignore[attr-defined]
            await uow.commit()
            workloads = normalized.workloads

        if self._graph_acl is not None:
            project = getattr(self._graph_acl, "project_workload", None)
            if callable(project):
                for wl in workloads:
                    await project(workload=wl)

        return [_to_workload_dto(w) for w in workloads]

    async def list_workloads(
        self,
        *,
        organization_id: str,
        cluster_id: UUID,
        namespace: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[WorkloadDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._workload_repo_factory(uow.session)
            items = await repo.list_by_cluster(  # type: ignore[attr-defined]
                cluster_id,
                organization_id=org,
                namespace=namespace,
                limit=limit,
                offset=offset,
            )
        return [_to_workload_dto(w) for w in items]

    async def get_workload(
        self, *, organization_id: str, cluster_id: UUID, workload_id: UUID
    ) -> WorkloadDTO:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._workload_repo_factory(uow.session)
            wl = await repo.get_by_id(workload_id, organization_id=org)  # type: ignore[attr-defined]
        if wl is None or wl.cluster_id.value != cluster_id:
            raise KubernetesWorkloadNotFoundError(str(workload_id))
        return _to_workload_dto(wl)
