"""Ingest runtime event batches: normalize → correlate → persist → project."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from redforge.application.cloud_security.runtime.correlation_service import (
    RuntimeCorrelationService,
)
from redforge.application.cloud_security.runtime.dtos import (
    IngestResultDTO,
    IngestRuntimeEventsCommand,
    RuntimeEventDTO,
)
from redforge.application.cloud_security.runtime.normalization_service import (
    RuntimeNormalizationService,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.runtime.repositories import (
    PgRuntimeArtifactRepository,
    PgRuntimeEventRepository,
    PgRuntimeExecutionContextRepository,
    PgRuntimeFileActivityRepository,
    PgRuntimeIdentitySessionRepository,
    PgRuntimeNetworkConnectionRepository,
    PgRuntimeProcessRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


def _event_dto(event: Any) -> RuntimeEventDTO:
    return RuntimeEventDTO(
        event_id=str(event.id),
        organization_id=str(event.organization_id),
        cloud_account_id=str(event.cloud_account_id),
        event_type=event.event_type.value,
        source=event.source.value,
        severity=event.severity.value,
        outcome=event.outcome.value,
        event_time=event.event_time,
        ingested_at=event.ingested_at,
        event_name=event.metadata.event_name,
        provider_event_id=event.metadata.provider_event_id,
        source_ip=event.source_ip,
        target_resource=event.target_resource,
        identity=event.identity.to_dict(),
        host=event.host.to_dict(),
        container=event.container.to_dict(),
        correlation_refs=event.correlation_refs.to_dict(),
        cspm_snapshot=event.cspm_snapshot(),
        created_at=event.created_at,
        updated_at=event.updated_at,
    )


class RuntimeIngestionService:
    def __init__(
        self,
        session_factory: SessionFactory,
        *,
        normalization: RuntimeNormalizationService | None = None,
        correlation: RuntimeCorrelationService | None = None,
        graph_acl: Any | None = None,
        event_repo_factory: Callable[[AsyncSession], PgRuntimeEventRepository] = (
            PgRuntimeEventRepository
        ),
        process_repo_factory: Callable[[AsyncSession], PgRuntimeProcessRepository] = (
            PgRuntimeProcessRepository
        ),
        connection_repo_factory: Callable[
            [AsyncSession], PgRuntimeNetworkConnectionRepository
        ] = PgRuntimeNetworkConnectionRepository,
        file_repo_factory: Callable[[AsyncSession], PgRuntimeFileActivityRepository] = (
            PgRuntimeFileActivityRepository
        ),
        session_repo_factory: Callable[
            [AsyncSession], PgRuntimeIdentitySessionRepository
        ] = PgRuntimeIdentitySessionRepository,
        context_repo_factory: Callable[
            [AsyncSession], PgRuntimeExecutionContextRepository
        ] = PgRuntimeExecutionContextRepository,
        artifact_repo_factory: Callable[[AsyncSession], PgRuntimeArtifactRepository] = (
            PgRuntimeArtifactRepository
        ),
    ) -> None:
        self._session_factory = session_factory
        self._normalization = normalization or RuntimeNormalizationService()
        self._correlation = correlation or RuntimeCorrelationService()
        self._graph_acl = graph_acl
        self._event_repo_factory = event_repo_factory
        self._process_repo_factory = process_repo_factory
        self._connection_repo_factory = connection_repo_factory
        self._file_repo_factory = file_repo_factory
        self._session_repo_factory = session_repo_factory
        self._context_repo_factory = context_repo_factory
        self._artifact_repo_factory = artifact_repo_factory

    async def ingest(self, command: IngestRuntimeEventsCommand) -> IngestResultDTO:
        org = OrganizationId(command.organization_id)
        account = CloudAccountId(command.cloud_account_id)
        bundles = self._normalization.normalize_many(
            list(command.events),
            organization_id=org,
            cloud_account_id=account,
            source=command.source,
        )
        events = []
        for bundle in bundles:
            correlated = await self._correlation.correlate(bundle.event)
            events.append(correlated)
            bundle.event.bind_correlation_refs(correlated.correlation_refs)
            # Keep links from correlation on the same object.
            correlated.correlation_links = correlated.correlation_links

        async with SessionUnitOfWork(self._session_factory) as uow:  # type: ignore[arg-type]
            event_repo = self._event_repo_factory(uow.session)
            process_repo = self._process_repo_factory(uow.session)
            connection_repo = self._connection_repo_factory(uow.session)
            file_repo = self._file_repo_factory(uow.session)
            session_repo = self._session_repo_factory(uow.session)
            context_repo = self._context_repo_factory(uow.session)
            artifact_repo = self._artifact_repo_factory(uow.session)

            inserted = await event_repo.save_batch(events)
            for bundle, event in zip(bundles, events, strict=True):
                if bundle.process is not None:
                    await process_repo.save(bundle.process)
                if bundle.connection is not None:
                    await connection_repo.save(bundle.connection)
                if bundle.file_activity is not None:
                    await file_repo.save(bundle.file_activity)
                if bundle.identity_session is not None:
                    await session_repo.save(bundle.identity_session)
                if bundle.execution_context is not None:
                    await context_repo.save(bundle.execution_context)
                if event.artifacts:
                    await artifact_repo.save_for_event(
                        organization_id=org,
                        runtime_event_id=event.id.value,
                        artifacts=list(event.artifacts),
                    )
                # Drain domain events (observation-only).
                event.pop_events()
                if bundle.process is not None:
                    bundle.process.pop_events()
                if bundle.connection is not None:
                    bundle.connection.pop_events()
            await uow.commit()

        if self._graph_acl is not None:
            await self._graph_acl.project_batch(events=events)

        return IngestResultDTO(
            organization_id=command.organization_id,
            accepted=len(events),
            inserted=inserted,
            skipped_duplicates=max(0, len(events) - inserted),
            event_ids=[str(e.id) for e in events],
        )

    async def ingest_raw(
        self,
        *,
        organization_id: str,
        cloud_account_id: UUID,
        events: list[dict[str, Any]],
        source: str | None = None,
    ) -> IngestResultDTO:
        return await self.ingest(
            IngestRuntimeEventsCommand(
                organization_id=organization_id,
                cloud_account_id=cloud_account_id,
                events=events,
                source=source,
            )
        )
