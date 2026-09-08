"""Integration tests proving the application-layer transaction/event
flow (authorize -> validate -> load/dedupe -> mutate -> save -> commit
-> publish) against a real PostgreSQL-backed Unit of Work — not the
in-memory fakes used in `tests/ioc_intelligence/application/`."""

from __future__ import annotations

import uuid

import pytest

from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    ObserveGlobalIocCommand,
    SourceAttributionInput,
)
from ioc_intelligence.application.services.ioc_application_service import IOCApplicationService
from ioc_intelligence.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from redforge.shared.ioc_vocabulary import ProviderName
from tests.ioc_intelligence.application.fakes import (
    FakeEvidenceValidationPort,
    RecordingEventPublisher,
)
from tests.ioc_intelligence.infrastructure.helpers import random_ip

pytestmark = pytest.mark.integration

PLATFORM_ADMIN = (IocIntelRole.PLATFORM_ADMIN.value,)


class _FailingCommitUnitOfWork(SqlAlchemyUnitOfWork):
    """Wraps the real Unit of Work but forces `commit()` to fail — the
    underlying session/repository work is entirely real; only the
    final commit is simulated as failing (e.g. a deferred constraint
    violation or lost connection at commit time)."""

    async def commit(self) -> None:
        raise RuntimeError("simulated commit failure")


def _attribution() -> SourceAttributionInput:
    return SourceAttributionInput(
        source_system=ProviderName.ALIENVAULT_OTX.value,
        external_id="pulse-1",
        observed_at="2026-08-05T00:00:00+00:00",
        weight_applied=0.9,
        confidence="high",
    )


@pytest.mark.asyncio
async def test_commit_occurs_before_publish_against_real_db(ioc_session_factory) -> None:
    events = RecordingEventPublisher()
    service = IOCApplicationService(
        uow_factory=lambda: SqlAlchemyUnitOfWork(ioc_session_factory),
        event_publisher=events,
        evidence_validator=FakeEvidenceValidationPort(),
    )
    dto = await service.observe_global_ioc(
        ObserveGlobalIocCommand(
            ioc_type="ip",
            raw_value=random_ip(),
            source_attributions=(_attribution(),),
            actor_roles=PLATFORM_ADMIN,
        )
    )
    assert dto.ioc_id
    assert len(events.published_batches) == 1

    verify_session = ioc_session_factory()
    try:
        from ioc_intelligence.domain.value_objects.identifiers import IocId
        from ioc_intelligence.infrastructure.persistence.repositories.pg_ioc_repository import (
            PgIocRepository,
        )

        fetched = await PgIocRepository(verify_session).get(None, IocId(uuid.UUID(dto.ioc_id)))
        assert fetched is not None
    finally:
        await verify_session.close()


@pytest.mark.asyncio
async def test_failed_commit_publishes_nothing_and_persists_nothing(ioc_session_factory) -> None:
    events = RecordingEventPublisher()
    service = IOCApplicationService(
        uow_factory=lambda: _FailingCommitUnitOfWork(ioc_session_factory),
        event_publisher=events,
        evidence_validator=FakeEvidenceValidationPort(),
    )
    raw_value = random_ip()
    with pytest.raises(RuntimeError):
        await service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value=raw_value,
                source_attributions=(_attribution(),),
                actor_roles=PLATFORM_ADMIN,
            )
        )
    assert events.published_batches == []

    from ioc_intelligence.domain.value_objects.enums import IocType
    from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
    from ioc_intelligence.infrastructure.persistence.repositories.pg_ioc_repository import (
        PgIocRepository,
    )

    verify_session = ioc_session_factory()
    try:
        canonical_key = IndicatorCanonicalKey.for_type(IocType.IP, raw_value)
        fetched = await PgIocRepository(verify_session).get_by_canonical_key(None, canonical_key)
        assert fetched is None
    finally:
        await verify_session.close()


@pytest.mark.asyncio
async def test_events_publish_exactly_once_against_real_db(ioc_session_factory) -> None:
    events = RecordingEventPublisher()
    service = IOCApplicationService(
        uow_factory=lambda: SqlAlchemyUnitOfWork(ioc_session_factory),
        event_publisher=events,
        evidence_validator=FakeEvidenceValidationPort(),
    )
    await service.observe_global_ioc(
        ObserveGlobalIocCommand(
            ioc_type="ip",
            raw_value=random_ip(),
            source_attributions=(_attribution(),),
            actor_roles=PLATFORM_ADMIN,
        )
    )
    assert len(events.published_batches) == 1
    assert len(events.all_published) == 1
