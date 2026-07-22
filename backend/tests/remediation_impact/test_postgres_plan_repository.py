"""Integration tests for PgExposureReductionPlanRepository against a live DB."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from remediation_impact.domain.aggregates.exposure_reduction_plan import ExposureReductionPlan
from remediation_impact.domain.value_objects.identifiers import (
    ExposureReductionPlanId,
    TenantId,
)
from remediation_impact.domain.value_objects.simulation_vos import PlanStep, SimulationResult
from remediation_impact.infrastructure.persistence.postgres_plan_repository import (
    PgExposureReductionPlanRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


def _simulation() -> SimulationResult:
    return SimulationResult(
        plan_steps=(
            PlanStep(
                remediation_id="rem-1",
                marginal_delta=1.5,
                affected_asset_refs=("asset-1", "asset-2"),
                rank=1,
            ),
        ),
        projected_exposure_reduction=4.2,
        algorithm="GreedyMarginalContribution",
        top_k=5,
        sample_size=100,
        approximation_mode="Exact",
        simulation_seed=42,
        score_input_version=3,
        estimated_business_impact=9000.0,
        total_assets=17,
        metadata={"note": "test"},
    )


@pytest.mark.asyncio
async def test_save_get_and_list_round_trip(session_factory) -> None:
    repo = PgExposureReductionPlanRepository(session_factory)
    tenant_id = TenantId(uuid7())
    plan_id = ExposureReductionPlanId.generate()

    plan = ExposureReductionPlan.create(
        plan_id, tenant_id, _simulation(), generated_at=datetime.now(UTC)
    )
    await repo.save(tenant_id, plan)

    fetched = await repo.get(tenant_id, plan_id)
    assert fetched is not None
    assert fetched.status.value == "Generated"
    assert fetched.simulation.total_assets == 17
    assert fetched.simulation.metadata == {"note": "test"}
    assert len(fetched.simulation.plan_steps) == 1
    assert fetched.simulation.plan_steps[0].remediation_id == "rem-1"

    listed = await repo.list_by_tenant(tenant_id)
    assert any(str(p.plan_id) == str(plan_id) for p in listed)


@pytest.mark.asyncio
async def test_commit_transition_persists(session_factory) -> None:
    repo = PgExposureReductionPlanRepository(session_factory)
    tenant_id = TenantId(uuid7())
    plan_id = ExposureReductionPlanId.generate()

    plan = ExposureReductionPlan.create(
        plan_id, tenant_id, _simulation(), generated_at=datetime.now(UTC)
    )
    await repo.save(tenant_id, plan)

    plan.commit(tenant_id, "analyst-1")
    await repo.save(tenant_id, plan)

    fetched = await repo.get(tenant_id, plan_id)
    assert fetched is not None
    assert fetched.status.value == "Committed"
    assert fetched.committed_by == "analyst-1"

    committed_only = await repo.list_by_tenant(tenant_id, status_filter="Committed")
    assert len(committed_only) == 1
    generated_only = await repo.list_by_tenant(tenant_id, status_filter="Generated")
    assert generated_only == []
