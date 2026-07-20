"""Orchestrate full Kubernetes inventory sync into repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from redforge.application.cloud_security.kubernetes.normalization_service import (
    KubernetesNormalizationService,
)
from redforge.domain.cloud_security.kubernetes.exceptions import KubernetesClusterNotFoundError
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


_ALL_KINDS = [
    "Namespace",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "Pod",
    "Node",
    "Service",
    "Ingress",
    "ConfigMap",
    "Secret",
    "PersistentVolume",
    "PersistentVolumeClaim",
    "NetworkPolicy",
    "ServiceAccount",
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
    "PodDisruptionBudget",
    "HorizontalPodAutoscaler",
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
]


class InventoryProjectionService:
    """Full sync of inventory into repos + best-effort graph projection."""

    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        namespace_repo_factory: RepoFactory,
        workload_repo_factory: RepoFactory,
        node_repo_factory: RepoFactory,
        service_repo_factory: RepoFactory,
        rbac_repo_factory: RepoFactory,
        network_policy_repo_factory: RepoFactory,
        admission_repo_factory: RepoFactory,
        inventory: KubernetesInventoryPort,
        normalizer: KubernetesNormalizationService | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._namespace_repo_factory = namespace_repo_factory
        self._workload_repo_factory = workload_repo_factory
        self._node_repo_factory = node_repo_factory
        self._service_repo_factory = service_repo_factory
        self._rbac_repo_factory = rbac_repo_factory
        self._network_policy_repo_factory = network_policy_repo_factory
        self._admission_repo_factory = admission_repo_factory
        self._inventory = inventory
        self._normalizer = normalizer or KubernetesNormalizationService()
        self._graph_acl = graph_acl

    async def sync(self, *, organization_id: str, cluster_id: UUID) -> dict[str, Any]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))

            resources = await self._inventory.list_resources(kinds=_ALL_KINDS)
            normalized = self._normalizer.normalize_resources(
                resources,
                cluster_id=ClusterId(cluster_id),
                organization_id=org,
            )

            await self._namespace_repo_factory(uow.session).save_batch(  # type: ignore[attr-defined]
                normalized.namespaces
            )
            await self._workload_repo_factory(uow.session).save_batch(  # type: ignore[attr-defined]
                normalized.workloads
            )
            await self._node_repo_factory(uow.session).save_batch(normalized.nodes)  # type: ignore[attr-defined]
            await self._service_repo_factory(uow.session).save_batch(  # type: ignore[attr-defined]
                normalized.services
            )
            await self._rbac_repo_factory(uow.session).save_batch(  # type: ignore[attr-defined]
                normalized.rbac_principals
            )
            await self._network_policy_repo_factory(uow.session).save_batch(  # type: ignore[attr-defined]
                normalized.network_policies
            )
            for adm in normalized.admission_policies:
                await self._admission_repo_factory(uow.session).save(adm)  # type: ignore[attr-defined]

            cluster.mark_synced()
            await cluster_repo.save(cluster)  # type: ignore[attr-defined]
            await uow.commit()

        if self._graph_acl is not None:
            project_all = getattr(self._graph_acl, "project_inventory", None)
            if callable(project_all):
                await project_all(
                    cluster=cluster,
                    namespaces=normalized.namespaces,
                    workloads=normalized.workloads,
                    services=normalized.services,
                    rbac=normalized.rbac_principals,
                    network_policies=normalized.network_policies,
                )

        return {
            "cluster_id": str(cluster_id),
            "namespaces": len(normalized.namespaces),
            "workloads": len(normalized.workloads),
            "nodes": len(normalized.nodes),
            "services": len(normalized.services),
            "rbac_principals": len(normalized.rbac_principals),
            "network_policies": len(normalized.network_policies),
            "admission_policies": len(normalized.admission_policies),
            "metadata_only": len(normalized.metadata_only),
        }
