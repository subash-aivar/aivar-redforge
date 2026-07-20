"""Kubernetes inventory → Security Graph projection ACL (best-effort)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.kubernetes.cluster import KubernetesCluster
    from redforge.domain.cloud_security.kubernetes.namespace import KubernetesNamespace
    from redforge.domain.cloud_security.kubernetes.network_policy import KubernetesNetworkPolicy
    from redforge.domain.cloud_security.kubernetes.rbac import KubernetesRBACPrincipal
    from redforge.domain.cloud_security.kubernetes.service import KubernetesService
    from redforge.domain.cloud_security.kubernetes.workload import KubernetesWorkload

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

logger = logging.getLogger(__name__)


class KubernetesGraphACL:
    """Projects K8s nodes/edges; never fabricates missing endpoints."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def project_cluster(self, *, cluster: KubernetesCluster) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_k8s_cluster(
                    organization_id=str(cluster.organization_id),
                    cluster_id=str(cluster.id),
                    name=cluster.name,
                    cluster_type=cluster.cluster_type.value,
                    version=cluster.version,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: k8s cluster projection failed for %s",
                cluster.id,
                exc_info=True,
            )

    async def project_workload(self, *, workload: KubernetesWorkload) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_k8s_workload(
                    organization_id=str(workload.organization_id),
                    workload_id=str(workload.id),
                    cluster_id=str(workload.cluster_id),
                    namespace=workload.namespace,
                    name=workload.name,
                    kind=workload.kind.value,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: k8s workload projection failed for %s",
                workload.id,
                exc_info=True,
            )

    async def project_rbac(self, *, principal: KubernetesRBACPrincipal) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_k8s_rbac(
                    organization_id=str(principal.organization_id),
                    principal_id=str(principal.id),
                    kind=principal.kind.value,
                    name=principal.name,
                    namespace=principal.namespace,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: k8s rbac projection failed for %s",
                principal.id,
                exc_info=True,
            )

    async def project_network_policy(self, *, policy: KubernetesNetworkPolicy) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_k8s_network_policy(
                    organization_id=str(policy.organization_id),
                    policy_id=str(policy.id),
                    namespace=policy.namespace,
                    name=policy.name,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: k8s network policy projection failed for %s",
                policy.id,
                exc_info=True,
            )

    async def project_inventory(
        self,
        *,
        cluster: KubernetesCluster,
        namespaces: list[KubernetesNamespace],
        workloads: list[KubernetesWorkload],
        services: list[KubernetesService],
        rbac: list[KubernetesRBACPrincipal],
        network_policies: list[KubernetesNetworkPolicy],
    ) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                org = str(cluster.organization_id)
                await projector.project_k8s_cluster(
                    organization_id=org,
                    cluster_id=str(cluster.id),
                    name=cluster.name,
                    cluster_type=cluster.cluster_type.value,
                    version=cluster.version,
                )
                for ns in namespaces:
                    await projector.project_k8s_namespace(
                        organization_id=org,
                        namespace_id=str(ns.id),
                        cluster_id=str(cluster.id),
                        name=ns.name,
                    )
                    await projector.project_k8s_hosts(
                        organization_id=org,
                        cluster_id=str(cluster.id),
                        namespace_id=str(ns.id),
                    )
                for wl in workloads:
                    await projector.project_k8s_workload(
                        organization_id=org,
                        workload_id=str(wl.id),
                        cluster_id=str(cluster.id),
                        namespace=wl.namespace,
                        name=wl.name,
                        kind=wl.kind.value,
                    )
                    ns_id = next((str(n.id) for n in namespaces if n.name == wl.namespace), None)
                    if ns_id:
                        await projector.project_k8s_runs_in(
                            organization_id=org,
                            workload_id=str(wl.id),
                            namespace_id=ns_id,
                        )
                        await projector.project_k8s_deploys(
                            organization_id=org,
                            source_id=ns_id,
                            source_domain="k8s_namespace",
                            workload_id=str(wl.id),
                        )
                for svc in services:
                    await projector.project_k8s_service(
                        organization_id=org,
                        service_id=str(svc.id),
                        namespace=svc.namespace,
                        name=svc.name,
                        is_public=svc.is_public,
                    )
                for principal in rbac:
                    await projector.project_k8s_rbac(
                        organization_id=org,
                        principal_id=str(principal.id),
                        kind=principal.kind.value,
                        name=principal.name,
                        namespace=principal.namespace,
                    )
                for policy in network_policies:
                    await projector.project_k8s_network_policy(
                        organization_id=org,
                        policy_id=str(policy.id),
                        namespace=policy.namespace,
                        name=policy.name,
                    )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: k8s inventory projection failed for cluster=%s",
                cluster.id,
                exc_info=True,
            )

    def _projector(self, session: Any) -> Any:
        from redforge.application.security_graph import projector as sg_projector
        from redforge.infrastructure.database.repositories import (
            security_graph_repository as sg_repo,
        )

        repo = sg_repo.SecurityGraphRepository(session)
        return sg_projector.SecurityGraphProjector(repo)
