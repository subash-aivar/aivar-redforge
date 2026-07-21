"""ExposureReductionPlanService — generate / commit / query (Phase 4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from remediation_impact.application._auth import require_at_least, require_simulation_read
from remediation_impact.application.dtos.plan_dtos import (
    ExposureReductionPlanDTO,
    PlanStepDTO,
)
from remediation_impact.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from remediation_impact.domain.aggregates.exposure_reduction_plan import (
    ExposureReductionPlan,
)
from remediation_impact.domain.exceptions.domain_exceptions import (
    EmptyCandidateSet,
    RemediationImpactDomainError,
)
from remediation_impact.domain.services.greedy_marginal_contribution import (
    run_greedy_marginal_contribution,
)
from remediation_impact.domain.value_objects.enums import RemediationImpactRole
from remediation_impact.domain.value_objects.identifiers import (
    ExposureReductionPlanId,
    TenantId,
)
from remediation_impact.domain.value_objects.simulation_vos import RemediationCandidate

if TYPE_CHECKING:
    from uuid import UUID

    from remediation_impact.application.commands.plan_commands import (
        CommitExposureReductionPlanCommand,
        GenerateExposureReductionPlanCommand,
    )
    from remediation_impact.application.ports.i_event_publisher import IEventPublisher
    from remediation_impact.application.ports.i_exposure_score_query_port import (
        IExposureScoreQueryPort,
    )
    from remediation_impact.domain.repositories.i_exposure_reduction_plan_repository import (
        IExposureReductionPlanRepository,
    )


def _to_dto(plan: ExposureReductionPlan) -> ExposureReductionPlanDTO:
    sim = plan.simulation
    return ExposureReductionPlanDTO(
        plan_id=str(plan.plan_id),
        tenant_id=str(plan.tenant_id),
        status=plan.status.value,
        generated_at=plan.generated_at.isoformat(),
        committed_at=plan.committed_at.isoformat() if plan.committed_at else None,
        committed_by=plan.committed_by,
        is_stale=plan.is_stale(),
        projected_exposure_reduction=sim.projected_exposure_reduction,
        estimated_business_impact=sim.estimated_business_impact,
        algorithm=sim.algorithm,
        top_k=sim.top_k,
        sample_size=sim.sample_size,
        approximation_mode=sim.approximation_mode,
        simulation_seed=sim.simulation_seed,
        score_input_version=sim.score_input_version,
        plan_steps=[
            PlanStepDTO(
                remediation_id=s.remediation_id,
                marginal_delta=s.marginal_delta,
                affected_asset_refs=list(s.affected_asset_refs),
                rank=s.rank,
            )
            for s in sim.plan_steps
        ],
        metadata=dict(sim.metadata),
    )


class ExposureReductionPlanService:
    def __init__(
        self,
        repo: IExposureReductionPlanRepository,
        event_publisher: IEventPublisher,
        score_port: IExposureScoreQueryPort,
    ) -> None:
        self._repo = repo
        self._events = event_publisher
        self._scores = score_port

    async def generate(self, cmd: GenerateExposureReductionPlanCommand) -> ExposureReductionPlanDTO:
        require_at_least(cmd.actor_roles, RemediationImpactRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        now = datetime.now(UTC)
        scores = cmd.current_exposure_scores
        version = cmd.score_input_version
        if scores is None:
            scores = await self._scores.get_asset_scores(cmd.tenant_id)
            version = await self._scores.get_score_input_version(cmd.tenant_id)
        candidates = [
            RemediationCandidate(
                remediation_id=c.remediation_id,
                affected_asset_refs=c.affected_asset_refs,
                estimated_amplifier_removals=c.estimated_amplifier_removals,
                estimated_base_reduction=c.estimated_base_reduction,
            )
            for c in cmd.candidate_remediations
        ]
        try:
            simulation = run_greedy_marginal_contribution(
                candidates=candidates,
                current_exposure_scores=scores,
                plan_budget=cmd.plan_budget,
                top_k=cmd.top_k,
                sample_size=cmd.sample_size,
                plan_generated_at=now,
                score_input_version=version,
            )
        except EmptyCandidateSet as exc:
            raise ApplicationValidationError(str(exc)) from exc
        plan = ExposureReductionPlan.create(
            ExposureReductionPlanId.generate(), tenant, simulation, now
        )
        await self._repo.save(tenant, plan)
        await self._events.publish_batch(plan.pop_events())
        return _to_dto(plan)

    async def commit(self, cmd: CommitExposureReductionPlanCommand) -> ExposureReductionPlanDTO:
        require_at_least(cmd.actor_roles, RemediationImpactRole.ANALYST)
        tenant = TenantId(cmd.tenant_id)
        plan = await self._repo.get(tenant, ExposureReductionPlanId(cmd.plan_id))
        if plan is None:
            raise ApplicationNotFoundError(str(cmd.plan_id))
        try:
            plan.commit(tenant, cmd.committed_by)
        except RemediationImpactDomainError as exc:
            raise ApplicationValidationError(str(exc)) from exc
        await self._repo.save(tenant, plan)
        await self._events.publish_batch(plan.pop_events())
        return _to_dto(plan)

    async def get(
        self, tenant_id: UUID, plan_id: UUID, actor_roles: tuple[str, ...]
    ) -> ExposureReductionPlanDTO:
        require_simulation_read(actor_roles)
        plan = await self._repo.get(TenantId(tenant_id), ExposureReductionPlanId(plan_id))
        if plan is None:
            raise ApplicationNotFoundError(str(plan_id))
        return _to_dto(plan)

    async def list_plans(
        self,
        tenant_id: UUID,
        actor_roles: tuple[str, ...],
        status_filter: str | None = None,
    ) -> list[ExposureReductionPlanDTO]:
        require_simulation_read(actor_roles)
        plans = await self._repo.list_by_tenant(TenantId(tenant_id), status_filter=status_filter)
        return [_to_dto(p) for p in plans]
