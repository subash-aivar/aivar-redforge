"""Discover Kubernetes RBAC principals (inventory only — no escalation paths)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from redforge.application.cloud_security.kubernetes.dtos import RBACPrincipalDTO
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


_RBAC_KINDS = [
    "ServiceAccount",
    "Role",
    "ClusterRole",
    "RoleBinding",
    "ClusterRoleBinding",
]


def _to_dto(principal: object) -> RBACPrincipalDTO:
    from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal

    assert isinstance(principal, KubernetesRBACPrincipal)
    return RBACPrincipalDTO(
        principal_id=str(principal.id),
        cluster_id=str(principal.cluster_id),
        kind=principal.kind.value,
        name=principal.name,
        namespace=principal.namespace,
        inventory=principal.inventory_dict(),
    )


class RBACDiscoveryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        rbac_repo_factory: RepoFactory,
        inventory: KubernetesInventoryPort,
        normalizer: KubernetesNormalizationService | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._rbac_repo_factory = rbac_repo_factory
        self._inventory = inventory
        self._normalizer = normalizer or KubernetesNormalizationService()
        self._graph_acl = graph_acl

    async def discover(self, *, organization_id: str, cluster_id: UUID) -> list[RBACPrincipalDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            cluster_repo = self._cluster_repo_factory(uow.session)
            cluster = await cluster_repo.get_by_id(cluster_id, organization_id=org)  # type: ignore[attr-defined]
            if cluster is None:
                raise KubernetesClusterNotFoundError(str(cluster_id))
            resources = await self._inventory.list_resources(kinds=_RBAC_KINDS)
            normalized = self._normalizer.normalize_resources(
                resources,
                cluster_id=ClusterId(cluster_id),
                organization_id=org,
            )
            rbac_repo = self._rbac_repo_factory(uow.session)
            await rbac_repo.save_batch(normalized.rbac_principals)  # type: ignore[attr-defined]
            await uow.commit()
            principals = normalized.rbac_principals

        if self._graph_acl is not None:
            project = getattr(self._graph_acl, "project_rbac", None)
            if callable(project):
                for p in principals:
                    await project(principal=p)

        return [_to_dto(p) for p in principals]

    async def list_rbac(
        self, *, organization_id: str, cluster_id: UUID, limit: int = 200, offset: int = 0
    ) -> list[RBACPrincipalDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._rbac_repo_factory(uow.session)
            items = await repo.list_by_cluster(  # type: ignore[attr-defined]
                cluster_id, organization_id=org, limit=limit, offset=offset
            )
        return [_to_dto(p) for p in items]
