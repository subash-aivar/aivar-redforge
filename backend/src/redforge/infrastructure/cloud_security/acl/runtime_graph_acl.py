"""Runtime visibility → Security Graph projection ACL (best-effort)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
    from redforge.domain.cloud_security.runtime.process import (
        RuntimeNetworkConnection,
        RuntimeProcess,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]

logger = logging.getLogger(__name__)


class RuntimeGraphACL:
    """Projects runtime nodes/edges; never fabricates missing inventory endpoints."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    async def project_event(self, *, event: CloudRuntimeEvent) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                org = str(event.organization_id)
                await projector.project_runtime_event(
                    organization_id=org,
                    event_id=str(event.id),
                    event_type=event.event_type.value,
                    source=event.source.value,
                    event_name=event.metadata.event_name,
                )
                refs = event.correlation_refs
                if refs.cloud_account_id is not None:
                    await projector.project_runtime_originated_from(
                        organization_id=org,
                        runtime_event_id=str(event.id),
                        cloud_account_id=str(refs.cloud_account_id),
                    )
                if refs.cloud_asset_id is not None:
                    await projector.project_runtime_observed_on(
                        organization_id=org,
                        runtime_event_id=str(event.id),
                        target_id=str(refs.cloud_asset_id),
                        target_domain="cloud_asset",
                    )
                if refs.kubernetes_workload_id is not None:
                    await projector.project_runtime_observed_on(
                        organization_id=org,
                        runtime_event_id=str(event.id),
                        target_id=str(refs.kubernetes_workload_id),
                        target_domain="k8s_workload",
                    )
                if refs.cloud_iam_principal_id is not None:
                    await projector.project_runtime_associated_with(
                        organization_id=org,
                        runtime_event_id=str(event.id),
                        target_id=str(refs.cloud_iam_principal_id),
                        target_domain="cloud_iam_principal",
                    )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: runtime event projection failed for %s",
                event.id,
                exc_info=True,
            )

    async def project_process(self, *, process: RuntimeProcess) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_runtime_process(
                    organization_id=str(process.organization_id),
                    process_id=str(process.id),
                    process_name=process.process_name,
                    runtime_event_id=str(process.runtime_event_id),
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: runtime process projection failed for %s",
                process.id,
                exc_info=True,
            )

    async def project_connection(self, *, connection: RuntimeNetworkConnection) -> None:
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:  # type: ignore[arg-type]
                projector = self._projector(graph_uow.session)
                await projector.project_runtime_connection(
                    organization_id=str(connection.organization_id),
                    connection_id=str(connection.id),
                    direction=connection.direction.value,
                    protocol=connection.protocol.value,
                    remote_address=connection.remote_address,
                    runtime_event_id=str(connection.runtime_event_id),
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: runtime connection projection failed for %s",
                connection.id,
                exc_info=True,
            )

    async def project_batch(self, *, events: list[CloudRuntimeEvent]) -> None:
        for event in events:
            await self.project_event(event=event)

    def _projector(self, session: Any) -> Any:
        from redforge.application.security_graph import projector as sg_projector
        from redforge.infrastructure.database.repositories import (
            security_graph_repository as sg_repo,
        )

        repo = sg_repo.SecurityGraphRepository(session)
        return sg_projector.SecurityGraphProjector(repo)
