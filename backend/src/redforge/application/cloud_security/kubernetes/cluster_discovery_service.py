"""Discover and register Kubernetes clusters from inventory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.cloud_security.kubernetes.dtos import ClusterDTO, DiscoverClusterCommand
from redforge.application.cloud_security.kubernetes.normalization_service import (
    KubernetesNormalizationService,
)
from redforge.domain.cloud_security.kubernetes.exceptions import KubernetesClusterNotFoundError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)
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


def _to_cluster_dto(cluster: object) -> ClusterDTO:
    from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster

    assert isinstance(cluster, KubernetesCluster)
    return ClusterDTO(
        cluster_id=str(cluster.id),
        organization_id=str(cluster.organization_id),
        cloud_account_id=str(cluster.cloud_account_id),
        cloud_asset_id=str(cluster.cloud_asset_id) if cluster.cloud_asset_id else None,
        cluster_type=cluster.cluster_type.value,
        name=cluster.name,
        version=cluster.version,
        api_server_endpoint=cluster.api_server_endpoint,
        region=cluster.region,
        security_score=cluster.security_score.to_dict(),
        labels=dict(cluster.labels),
        pod_security_standards=dict(cluster.pod_security_standards),
        discovered_at=cluster.discovered_at,
        last_synced_at=cluster.last_synced_at,
        created_at=cluster.created_at,
        updated_at=cluster.updated_at,
    )


class ClusterDiscoveryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        cluster_repo_factory: RepoFactory,
        inventory: KubernetesInventoryPort,
        normalizer: KubernetesNormalizationService | None = None,
        graph_acl: object | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cluster_repo_factory = cluster_repo_factory
        self._inventory = inventory
        self._normalizer = normalizer or KubernetesNormalizationService()
        self._graph_acl = graph_acl

    async def discover(self, command: DiscoverClusterCommand) -> ClusterDTO:
        org = OrganizationId(command.organization_id)
        info = await self._inventory.get_cluster_info()
        if command.name:
            info = {**info, "name": command.name}
        if command.cluster_type:
            info = {**info, "cluster_type": command.cluster_type}
        if command.version:
            info = {**info, "version": command.version}
        if command.api_server_endpoint:
            info = {**info, "api_server_endpoint": command.api_server_endpoint}
        if command.region:
            info = {**info, "region": command.region}

        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._cluster_repo_factory(uow.session)
            existing = await repo.get_by_name(  # type: ignore[attr-defined]
                organization_id=org, name=str(info.get("name") or "")
            )
            cloud_asset = CloudAssetId(command.cloud_asset_id) if command.cloud_asset_id else None
            if existing is not None:
                existing.mark_synced()
                if cloud_asset is not None and existing.cloud_asset_id is None:
                    existing.bind_cloud_asset(cloud_asset)
                await repo.save(existing)  # type: ignore[attr-defined]
                await uow.commit()
                cluster = existing
            else:
                cluster = self._normalizer.normalize_cluster(
                    info,
                    organization_id=org,
                    cloud_account_id=CloudAccountId(command.cloud_account_id),
                    cloud_asset_id=cloud_asset,
                    credential_ref_id=command.credential_ref_id,
                )
                await repo.save(cluster)  # type: ignore[attr-defined]
                await uow.commit()

        if self._graph_acl is not None:
            project = getattr(self._graph_acl, "project_cluster", None)
            if callable(project):
                await project(cluster=cluster)

        return _to_cluster_dto(cluster)

    async def get(self, organization_id: str, cluster_id: ClusterId | str) -> ClusterDTO:
        org = OrganizationId(organization_id)
        cid = (
            cluster_id if isinstance(cluster_id, ClusterId) else ClusterId.from_str(str(cluster_id))
        )
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._cluster_repo_factory(uow.session)
            cluster = await repo.get_by_id(cid.value, organization_id=org)  # type: ignore[attr-defined]
        if cluster is None:
            raise KubernetesClusterNotFoundError(str(cid))
        return _to_cluster_dto(cluster)

    async def list_clusters(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[ClusterDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._cluster_repo_factory(uow.session)
            clusters = await repo.list_by_organization(  # type: ignore[attr-defined]
                org, limit=limit, offset=offset
            )
        return [_to_cluster_dto(c) for c in clusters]
