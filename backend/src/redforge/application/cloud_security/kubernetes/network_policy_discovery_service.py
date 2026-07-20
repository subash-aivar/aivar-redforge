"""Discover Kubernetes network policies from inventory."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from redforge.application.cloud_security.kubernetes.dtos import NetworkPolicyDTO
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


def _to_dto(policy: object) -> NetworkPolicyDTO:
    from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy

    assert isinstance(policy, KubernetesNetworkPolicy)
    return NetworkPolicyDTO(
        policy_id=str(policy.id),
        cluster_id=str(policy.cluster_id),
        namespace=policy.namespace,
        name=policy.name,
        policy_types=list(policy.policy_types),
        allows_cross_namespace=policy.allows_cross_namespace,
        pod_selector=dict(policy.pod_selector),
    )


class NetworkPolicyDiscoveryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        network_policy_repo_factory: RepoFactory,
        inventory: KubernetesInventoryPort,
        normalizer: KubernetesNormalizationService | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._network_policy_repo_factory = network_policy_repo_factory
        self._inventory = inventory
        self._normalizer = normalizer or KubernetesNormalizationService()
        self._graph_acl = graph_acl

    async def discover(self, *, organization_id: str, cluster_id: UUID) -> list[NetworkPolicyDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))
            resources = await self._inventory.list_resources(kinds=["NetworkPolicy"])
            normalized = self._normalizer.normalize_resources(
                resources,
                cluster_id=ClusterId(cluster_id),
                organization_id=org,
            )
            repo = self._network_policy_repo_factory(uow.session)
            await repo.save_batch(normalized.network_policies)  # type: ignore[attr-defined]
            await uow.commit()
            policies = normalized.network_policies

        if self._graph_acl is not None:
            project = getattr(self._graph_acl, "project_network_policy", None)
            if callable(project):
                for p in policies:
                    await project(policy=p)

        return [_to_dto(p) for p in policies]

    async def list_policies(
        self, *, organization_id: str, cluster_id: UUID
    ) -> list[NetworkPolicyDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._network_policy_repo_factory(uow.session)
            items = await repo.list_by_cluster(cluster_id, organization_id=org)  # type: ignore[attr-defined]
        return [_to_dto(p) for p in items]
