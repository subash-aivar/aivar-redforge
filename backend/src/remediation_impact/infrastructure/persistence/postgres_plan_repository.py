"""PgExposureReductionPlanRepository — production persistence.

Opens one session per call from an injected async_sessionmaker, mirroring
the incident bounded context's Pg* repositories: this container passes
concrete repository instances into ExposureReductionPlanService once at
construction time rather than through a per-request unit-of-work, so a
per-call session keeps that shape without a wider refactor.

PlanStep/RemediationCandidate/metadata are stored as JSONB — they're
already plain dataclasses of primitives, and the migration (0083) shaped
plan_steps_json/metadata_json for exactly this. total_assets has no
column of its own (not present in migration 0083), so it round-trips
through metadata_json.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from remediation_impact.domain.aggregates.exposure_reduction_plan import ExposureReductionPlan
from remediation_impact.domain.repositories.i_exposure_reduction_plan_repository import (
    IExposureReductionPlanRepository,
)
from remediation_impact.domain.value_objects.enums import PlanStatus
from remediation_impact.domain.value_objects.identifiers import ExposureReductionPlanId, TenantId
from remediation_impact.domain.value_objects.simulation_vos import PlanStep, SimulationResult
from remediation_impact.infrastructure.persistence.models.plan_models import (
    ExposureReductionPlanModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_TOTAL_ASSETS_KEY = "_total_assets"


def _plan_to_row(plan: ExposureReductionPlan) -> ExposureReductionPlanModel:
    sim = plan.simulation
    metadata = dict(sim.metadata)
    metadata[_TOTAL_ASSETS_KEY] = sim.total_assets
    return ExposureReductionPlanModel(
        id=plan.plan_id.value,
        tenant_id=plan.tenant_id.value,
        status=plan.status.value,
        generated_at=plan.generated_at,
        committed_at=plan.committed_at,
        committed_by=plan.committed_by,
        projected_exposure_reduction=sim.projected_exposure_reduction,
        estimated_business_impact=sim.estimated_business_impact,
        algorithm=sim.algorithm,
        top_k=sim.top_k,
        sample_size=sim.sample_size,
        approximation_mode=sim.approximation_mode,
        simulation_seed=sim.simulation_seed,
        score_input_version=sim.score_input_version,
        plan_steps_json=[
            {
                "remediation_id": s.remediation_id,
                "marginal_delta": s.marginal_delta,
                "affected_asset_refs": list(s.affected_asset_refs),
                "rank": s.rank,
            }
            for s in sim.plan_steps
        ],
        metadata_json=metadata,
    )


def _row_to_plan(row: ExposureReductionPlanModel) -> ExposureReductionPlan:
    metadata = dict(row.metadata_json or {})
    total_assets = metadata.pop(_TOTAL_ASSETS_KEY, 0)
    simulation = SimulationResult(
        plan_steps=tuple(
            PlanStep(
                remediation_id=str(s["remediation_id"]),
                marginal_delta=float(s["marginal_delta"]),
                affected_asset_refs=tuple(s["affected_asset_refs"]),
                rank=int(s["rank"]),
            )
            for s in (row.plan_steps_json or [])
        ),
        projected_exposure_reduction=row.projected_exposure_reduction,
        algorithm=row.algorithm,
        top_k=row.top_k,
        sample_size=row.sample_size,
        approximation_mode=row.approximation_mode,
        simulation_seed=row.simulation_seed,
        score_input_version=row.score_input_version,
        estimated_business_impact=row.estimated_business_impact,
        total_assets=int(total_assets),
        metadata=metadata,
    )
    return ExposureReductionPlan(
        plan_id=ExposureReductionPlanId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        simulation=simulation,
        status=PlanStatus(row.status),
        generated_at=row.generated_at,
        committed_at=row.committed_at,
        committed_by=row.committed_by,
    )


class PgExposureReductionPlanRepository(IExposureReductionPlanRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get(
        self, tenant_id: TenantId, plan_id: ExposureReductionPlanId
    ) -> ExposureReductionPlan | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ExposureReductionPlanModel).where(
                        ExposureReductionPlanModel.tenant_id == tenant_id.value,
                        ExposureReductionPlanModel.id == plan_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_plan(row) if row is not None else None

    async def save(self, tenant_id: TenantId, plan: ExposureReductionPlan) -> None:
        async with self._session_factory() as session:
            await session.merge(_plan_to_row(plan))
            await session.commit()

    async def list_by_tenant(
        self, tenant_id: TenantId, *, status_filter: str | None = None
    ) -> list[ExposureReductionPlan]:
        async with self._session_factory() as session:
            stmt = select(ExposureReductionPlanModel).where(
                ExposureReductionPlanModel.tenant_id == tenant_id.value
            )
            if status_filter:
                stmt = stmt.where(ExposureReductionPlanModel.status == status_filter)
            stmt = stmt.order_by(ExposureReductionPlanModel.generated_at.desc())
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_plan(r) for r in rows]
