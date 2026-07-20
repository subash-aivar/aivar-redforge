"""PostgreSQL integration tests for runtime visibility repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.runtime.entities import RuntimeArtifact, RuntimeMetadata
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.process import (
    RuntimeNetworkConnection,
    RuntimeProcess,
)
from redforge.domain.cloud_security.runtime.value_objects import (
    RuntimeDirection,
    RuntimeEventType,
    RuntimeProtocol,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId
from redforge.infrastructure.cloud_security.runtime.repositories import (
    PgRuntimeArtifactRepository,
    PgRuntimeEventRepository,
    PgRuntimeNetworkConnectionRepository,
    PgRuntimeProcessRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)
NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_runtime_repositories_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    account_id = CloudAccountId(uuid4())
    provider_event_id = f"prov-{uuid4()}"

    async with session_factory() as session, session.begin():
        events = PgRuntimeEventRepository(session)
        processes = PgRuntimeProcessRepository(session)
        connections = PgRuntimeNetworkConnectionRepository(session)
        artifacts = PgRuntimeArtifactRepository(session)

        event = CloudRuntimeEvent.ingest(
            organization_id=org,
            cloud_account_id=account_id,
            event_type=RuntimeEventType.API_ACTIVITY,
            source=RuntimeSource.CLOUDTRAIL,
            event_time=NOW,
            metadata=RuntimeMetadata(
                provider_event_id=provider_event_id,
                event_name="DescribeInstances",
                region="us-east-1",
            ),
            artifacts=[
                RuntimeArtifact(artifact_id="art-1", artifact_type="log", name="trail")
            ],
            now=NOW,
        )
        inserted = await events.save_batch([event])
        assert inserted == 1

        # Dedup — second insert of same org/source/provider/event_time skipped.
        dup = CloudRuntimeEvent.ingest(
            organization_id=org,
            cloud_account_id=account_id,
            event_type=RuntimeEventType.API_ACTIVITY,
            source=RuntimeSource.CLOUDTRAIL,
            event_time=NOW,
            metadata=RuntimeMetadata(
                provider_event_id=provider_event_id,
                event_name="DescribeInstances",
            ),
            now=NOW,
        )
        assert await events.save_batch([dup]) == 0

        loaded = await events.get_by_id(event.id.value, organization_id=org)
        assert loaded is not None
        assert loaded.metadata.provider_event_id == provider_event_id

        listed = await events.list_by_organization(org, event_type="API_ACTIVITY")
        assert any(e.id.value == event.id.value for e in listed)

        by_account = await events.list_by_account(
            account_id.value, organization_id=org
        )
        assert any(e.id.value == event.id.value for e in by_account)

        assert await events.count_by_organization(org) >= 1

        proc = RuntimeProcess.observe(
            organization_id=org,
            runtime_event_id=event.id,
            process_name="bash",
            executable_path="/bin/bash",
            pid=99,
            now=NOW,
        )
        await processes.save(proc)
        assert any(
            p.id.value == proc.id.value
            for p in await processes.list_by_organization(org)
        )

        conn = RuntimeNetworkConnection.observe(
            organization_id=org,
            runtime_event_id=event.id,
            direction=RuntimeDirection.OUTBOUND,
            protocol=RuntimeProtocol.TCP,
            remote_address="8.8.8.8",
            remote_port=53,
            now=NOW,
        )
        await connections.save_batch([conn])
        assert any(
            c.id.value == conn.id.value
            for c in await connections.list_by_organization(org)
        )

        await artifacts.save_for_event(
            organization_id=org,
            runtime_event_id=event.id.value,
            artifacts=list(event.artifacts),
        )
        arts = await artifacts.list_by_event(event.id.value, organization_id=org)
        assert len(arts) >= 1
