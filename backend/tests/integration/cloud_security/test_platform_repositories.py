"""PostgreSQL integration tests for platform orchestration repositories."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from ulid import ULID

from redforge.domain.cloud_security.platform.entities import (
    OrchestrationRun,
    OrchestrationStepResult,
)
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationScope,
    StepName,
    StepStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.platform.repositories import (
    PgOrchestrationRunRepository,
    PgPlatformValidationReportRepository,
)

pytestmark = pytest.mark.integration

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
async def session_factory() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    if not os.environ.get("TEST_DATABASE_URL"):
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_orchestration_run_round_trip(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        repo = PgOrchestrationRunRepository(session)
        run = OrchestrationRun.start(
            organization_id=org,
            scope=OrchestrationScope.ACCOUNT,
            target_id=str(uuid4()),
            operation_id="op_integ",
            correlation_id="corr",
            request_id="req",
            now=NOW,
        )
        run.record_step(
            OrchestrationStepResult(
                step_name=StepName.DISCOVER_ASSETS,
                status=StepStatus.COMPLETED,
                started_at=NOW,
                completed_at=NOW,
                duration_ms=10.0,
                message="ok",
            )
        )
        run.complete(now=NOW)
        await repo.save(run)

        loaded = await repo.get_by_id(run.id.value, organization_id=org)
        assert loaded is not None
        assert loaded.operation_id == "op_integ"
        assert loaded.status.value == "COMPLETED"
        assert len(loaded.steps) == 1

        listed = await repo.list_by_organization(org, limit=10, offset=0)
        assert any(str(r.id) == str(run.id) for r in listed)
        count = await repo.count_by_organization(org)
        assert count >= 1
        latest = await repo.get_latest(org)
        assert latest is not None


@pytest.mark.asyncio
async def test_orchestration_run_tenant_isolation(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org_a = OrganizationId(str(ULID()))
    org_b = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        repo = PgOrchestrationRunRepository(session)
        run = OrchestrationRun.start(
            organization_id=org_a,
            scope=OrchestrationScope.ORGANIZATION,
            target_id=str(org_a),
            operation_id="op_iso",
            now=NOW,
        )
        run.complete(now=NOW)
        await repo.save(run)
        assert await repo.get_by_id(run.id.value, organization_id=org_b) is None
        assert await repo.list_by_organization(org_b) == []


@pytest.mark.asyncio
async def test_validation_report_upsert(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    org = OrganizationId(str(ULID()))
    async with session_factory() as session, session.begin():
        repo = PgPlatformValidationReportRepository(session)
        await repo.save_report(
            org,
            {"overall_passed": True, "checks": [{"name": "ontology_version", "passed": True}]},
        )
        await repo.save_report(
            org,
            {"overall_passed": False, "checks": [{"name": "ontology_version", "passed": False}]},
        )
        stored = await repo.get_latest(org)
        assert stored is not None
        assert stored["report"]["overall_passed"] is False
