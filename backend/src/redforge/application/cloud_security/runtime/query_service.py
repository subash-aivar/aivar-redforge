"""List/get/summary queries for runtime visibility."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from redforge.application.cloud_security.runtime.dtos import (
    RuntimeEventDTO,
    RuntimeNetworkConnectionDTO,
    RuntimeProcessDTO,
    RuntimeSummaryDTO,
)
from redforge.application.cloud_security.runtime.ingestion_service import _event_dto
from redforge.domain.cloud_security.runtime.exceptions import RuntimeEventNotFoundError
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.runtime.repositories import (
    PgRuntimeEventRepository,
    PgRuntimeNetworkConnectionRepository,
    PgRuntimeProcessRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


class RuntimeQueryService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        event_repo_factory: Callable[[AsyncSession], PgRuntimeEventRepository] = (
            PgRuntimeEventRepository
        ),
        process_repo_factory: Callable[[AsyncSession], PgRuntimeProcessRepository] = (
            PgRuntimeProcessRepository
        ),
        connection_repo_factory: Callable[
            [AsyncSession], PgRuntimeNetworkConnectionRepository
        ] = PgRuntimeNetworkConnectionRepository,
    ) -> None:
        self._session_factory = session_factory
        self._event_repo_factory = event_repo_factory
        self._process_repo_factory = process_repo_factory
        self._connection_repo_factory = connection_repo_factory

    async def get_event(self, organization_id: str, event_id: UUID) -> RuntimeEventDTO:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._event_repo_factory(uow.session)
            event = await repo.get_by_id(event_id, organization_id=org)
            if event is None:
                raise RuntimeEventNotFoundError(str(event_id))
            return _event_dto(event)

    async def list_events(
        self,
        organization_id: str,
        *,
        since: datetime | None = None,
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[RuntimeEventDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._event_repo_factory(uow.session)
            events = await repo.list_by_organization(
                org,
                since=since,
                event_type=event_type,
                source=source,
                limit=limit,
                offset=offset,
            )
            return [_event_dto(e) for e in events]

    async def list_processes(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeProcessDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._process_repo_factory(uow.session)
            processes = await repo.list_by_organization(org, limit=limit, offset=offset)
            return [
                RuntimeProcessDTO(
                    process_id=str(p.id),
                    organization_id=str(p.organization_id),
                    runtime_event_id=str(p.runtime_event_id),
                    process_name=p.process_name,
                    executable_path=p.executable_path,
                    pid=p.pid,
                    parent_pid=p.parent_pid,
                    command_line=p.command_line,
                    user_name=p.user_name,
                    created_at=p.created_at,
                )
                for p in processes
            ]

    async def list_network_connections(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeNetworkConnectionDTO]:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            repo = self._connection_repo_factory(uow.session)
            connections = await repo.list_by_organization(org, limit=limit, offset=offset)
            return [
                RuntimeNetworkConnectionDTO(
                    connection_id=str(c.id),
                    organization_id=str(c.organization_id),
                    runtime_event_id=str(c.runtime_event_id),
                    direction=c.direction.value,
                    protocol=c.protocol.value,
                    local_address=c.local_address,
                    local_port=c.local_port,
                    remote_address=c.remote_address,
                    remote_port=c.remote_port,
                    created_at=c.created_at,
                )
                for c in connections
            ]

    async def summary(
        self, organization_id: str, *, since: datetime | None = None
    ) -> RuntimeSummaryDTO:
        org = OrganizationId(organization_id)
        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            events = await self._event_repo_factory(uow.session).list_by_organization(
                org, since=since, limit=1000, offset=0
            )
            processes = await self._process_repo_factory(uow.session).list_by_organization(
                org, limit=1000, offset=0
            )
            connections = await self._connection_repo_factory(uow.session).list_by_organization(
                org, limit=1000, offset=0
            )
            by_type = Counter(e.event_type.value for e in events)
            by_source = Counter(e.source.value for e in events)
            total = await self._event_repo_factory(uow.session).count_by_organization(
                org, since=since
            )
            return RuntimeSummaryDTO(
                organization_id=organization_id,
                total_events=total,
                by_event_type=dict(by_type),
                by_source=dict(by_source),
                process_count=len(processes),
                connection_count=len(connections),
            )
