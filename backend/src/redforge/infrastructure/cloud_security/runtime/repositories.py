"""PostgreSQL repositories for runtime visibility (dedup via ON CONFLICT DO NOTHING)."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, cast
from uuid import UUID

from sqlalchemy import Table, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from redforge.domain.cloud_security.runtime.entities import RuntimeArtifact
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.process import (
    RuntimeFileActivity,
    RuntimeNetworkConnection,
    RuntimeProcess,
)
from redforge.domain.cloud_security.runtime.session import (
    RuntimeExecutionContext,
    RuntimeIdentitySession,
)
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.runtime.mappings import (
    artifact_from_model,
    artifact_to_model,
    connection_from_model,
    connection_to_model,
    context_to_model,
    event_from_model,
    file_activity_to_model,
    process_from_model,
    process_to_model,
    session_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudRuntimeEventModel,
    RuntimeArtifactModel,
    RuntimeExecutionContextModel,
    RuntimeFileActivityModel,
    RuntimeIdentitySessionModel,
    RuntimeNetworkConnectionModel,
    RuntimeProcessModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _event_insert_values(event: CloudRuntimeEvent) -> dict[str, object]:
    return {
        "id": event.id.value,
        "organization_id": str(event.organization_id),
        "cloud_account_id": event.cloud_account_id.value,
        "event_type": event.event_type.value,
        "source": event.source.value,
        "severity": event.severity.value,
        "outcome": event.outcome.value,
        "event_time": event.event_time,
        "ingested_at": event.ingested_at,
        "provider_event_id": event.metadata.provider_event_id,
        "identity": event.identity.to_dict(),
        "host": event.host.to_dict(),
        "container": event.container.to_dict(),
        "metadata": event.metadata.to_dict(),
        "correlation_refs": event.correlation_refs.to_dict(),
        "correlation_links": [link.to_dict() for link in event.correlation_links],
        "artifacts": [art.to_dict() for art in event.artifacts],
        "evidence": [ev.to_dict() for ev in event.evidence],
        "raw_payload": dict(event.raw_payload),
        "source_ip": event.source_ip,
        "target_resource": event.target_resource,
        "created_at": event.created_at,
        "updated_at": event.updated_at,
        "row_version": event.row_version,
    }


class PgRuntimeEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, event: CloudRuntimeEvent) -> None:
        inserted = await self.save_batch([event])
        if inserted == 0:
            # Already present — no-op for idempotent ingest.
            return

    async def save_batch(self, events: list[CloudRuntimeEvent]) -> int:
        if not events:
            return 0
        inserted = 0
        # Use Core Table insert — ORM attribute name "metadata" collides with
        # DeclarativeBase.metadata (SQLAlchemy MetaData).
        table = cast("Table", CloudRuntimeEventModel.__table__)
        for event in events:
            stmt = (
                pg_insert(table)
                .values(**_event_insert_values(event))
                .on_conflict_do_nothing(
                    constraint="uq_cloud_runtime_events_org_source_provider"
                )
                .returning(table.c.id)
            )
            result = await self._session.execute(stmt)
            if result.scalar_one_or_none() is not None:
                inserted += 1
        await self._session.flush()
        return inserted

    async def get_by_id(
        self, event_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRuntimeEvent | None:
        result = await self._session.execute(
            select(CloudRuntimeEventModel).where(
                CloudRuntimeEventModel.id == event_id,
                CloudRuntimeEventModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return event_from_model(row) if row is not None else None

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        since: datetime | None = None,
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRuntimeEvent]:
        stmt = select(CloudRuntimeEventModel).where(
            CloudRuntimeEventModel.organization_id == str(organization_id)
        )
        if since is not None:
            stmt = stmt.where(CloudRuntimeEventModel.event_time >= since)
        if event_type is not None:
            stmt = stmt.where(CloudRuntimeEventModel.event_type == event_type)
        if source is not None:
            stmt = stmt.where(CloudRuntimeEventModel.source == source)
        result = await self._session.execute(
            stmt.order_by(CloudRuntimeEventModel.event_time.desc())
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [event_from_model(row) for row in result.scalars().all()]

    async def list_by_account(
        self,
        cloud_account_id: UUID,
        *,
        organization_id: OrganizationId,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRuntimeEvent]:
        stmt = select(CloudRuntimeEventModel).where(
            CloudRuntimeEventModel.cloud_account_id == cloud_account_id,
            CloudRuntimeEventModel.organization_id == str(organization_id),
        )
        if since is not None:
            stmt = stmt.where(CloudRuntimeEventModel.event_time >= since)
        result = await self._session.execute(
            stmt.order_by(CloudRuntimeEventModel.event_time.desc())
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [event_from_model(row) for row in result.scalars().all()]

    async def count_by_organization(
        self, organization_id: OrganizationId, *, since: datetime | None = None
    ) -> int:
        stmt = (
            select(func.count())
            .select_from(CloudRuntimeEventModel)
            .where(CloudRuntimeEventModel.organization_id == str(organization_id))
        )
        if since is not None:
            stmt = stmt.where(CloudRuntimeEventModel.event_time >= since)
        result = await self._session.execute(stmt)
        return int(result.scalar_one() or 0)


class PgRuntimeArtifactRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_for_event(
        self,
        *,
        organization_id: OrganizationId,
        runtime_event_id: UUID,
        artifacts: list[RuntimeArtifact],
    ) -> None:
        for art in artifacts:
            self._session.add(
                artifact_to_model(
                    organization_id=organization_id,
                    runtime_event_id=runtime_event_id,
                    artifact=art,
                )
            )
        await self._session.flush()

    async def list_by_event(
        self, runtime_event_id: UUID, *, organization_id: OrganizationId
    ) -> list[RuntimeArtifact]:
        result = await self._session.execute(
            select(RuntimeArtifactModel).where(
                RuntimeArtifactModel.runtime_event_id == runtime_event_id,
                RuntimeArtifactModel.organization_id == str(organization_id),
            )
        )
        return [artifact_from_model(row) for row in result.scalars().all()]


class PgRuntimeProcessRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, process: RuntimeProcess) -> None:
        existing = await self._session.get(RuntimeProcessModel, process.id.value)
        if existing is None:
            self._session.add(process_to_model(process))
        else:
            process_to_model(process, existing)
        await self._session.flush()

    async def save_batch(self, processes: list[RuntimeProcess]) -> None:
        for process in processes:
            await self.save(process)

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeProcess]:
        result = await self._session.execute(
            select(RuntimeProcessModel)
            .where(RuntimeProcessModel.organization_id == str(organization_id))
            .order_by(RuntimeProcessModel.created_at.desc())
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [process_from_model(row) for row in result.scalars().all()]


class PgRuntimeNetworkConnectionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, connection: RuntimeNetworkConnection) -> None:
        existing = await self._session.get(RuntimeNetworkConnectionModel, connection.id.value)
        if existing is None:
            self._session.add(connection_to_model(connection))
        else:
            connection_to_model(connection, existing)
        await self._session.flush()

    async def save_batch(self, connections: list[RuntimeNetworkConnection]) -> None:
        for connection in connections:
            await self.save(connection)

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeNetworkConnection]:
        result = await self._session.execute(
            select(RuntimeNetworkConnectionModel)
            .where(RuntimeNetworkConnectionModel.organization_id == str(organization_id))
            .order_by(RuntimeNetworkConnectionModel.created_at.desc())
            .limit(max(1, min(limit, 1000)))
            .offset(max(0, offset))
        )
        return [connection_from_model(row) for row in result.scalars().all()]


class PgRuntimeFileActivityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, activity: RuntimeFileActivity) -> None:
        existing = await self._session.get(RuntimeFileActivityModel, activity.id.value)
        if existing is None:
            self._session.add(file_activity_to_model(activity))
        else:
            file_activity_to_model(activity, existing)
        await self._session.flush()


class PgRuntimeIdentitySessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, identity_session: RuntimeIdentitySession) -> None:
        existing = await self._session.get(
            RuntimeIdentitySessionModel, identity_session.id.value
        )
        if existing is None:
            self._session.add(session_to_model(identity_session))
        else:
            session_to_model(identity_session, existing)
        await self._session.flush()


class PgRuntimeExecutionContextRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, context: RuntimeExecutionContext) -> None:
        existing = await self._session.get(RuntimeExecutionContextModel, context.id.value)
        if existing is None:
            self._session.add(context_to_model(context))
        else:
            context_to_model(context, existing)
        await self._session.flush()
