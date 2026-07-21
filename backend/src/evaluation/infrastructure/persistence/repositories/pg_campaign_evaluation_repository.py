"""PostgreSQL repository for CampaignEvaluation aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import select

from evaluation.domain.aggregates.campaign_evaluation import CampaignEvaluation
from evaluation.domain.entities.evaluation_entities import (
    LateDetectionRecord,
    ObjectiveAssessment,
    TechniqueOutcomeRecord,
)
from evaluation.domain.exceptions.domain_exceptions import TenantMismatch
from evaluation.domain.repositories.i_campaign_evaluation_repository import (
    ICampaignEvaluationRepository,
)
from evaluation.domain.value_objects.enums import (
    CompositeOutcome,
    EvaluationState,
    ObjectiveOutcome,
)
from evaluation.domain.value_objects.evaluation_vos import (
    CampaignInstanceRef,
    ComplianceMappingResult,
    EvaluationMetrics,
    KillChainPhaseOutcome,
    KillChainProgressionMap,
    MitreAttackRef,
    ObjectiveSpec,
)
from evaluation.domain.value_objects.identifiers import (
    CampaignEvaluationId,
    ObjectiveAssessmentId,
    TenantId,
)
from evaluation.infrastructure.persistence.models.evaluation_models import (
    CampaignEvaluationModel,
)

if TYPE_CHECKING:

    from sqlalchemy.ext.asyncio import AsyncSession


def _metrics_to_json(m: EvaluationMetrics | None) -> dict[str, Any]:
    if m is None:
        return {}
    return {
        "detection_coverage_percent": m.detection_coverage_percent,
        "technique_success_rate": m.technique_success_rate,
        "evasion_rate": m.evasion_rate,
        "mean_time_to_detect_seconds": m.mean_time_to_detect_seconds,
        "actions_executed_count": m.actions_executed_count,
        "actions_failed_count": m.actions_failed_count,
        "objectives_achieved_count": m.objectives_achieved_count,
        "objectives_failed_count": m.objectives_failed_count,
        "campaign_duration_seconds": m.campaign_duration_seconds,
        "kill_chain_phases_covered": list(m.kill_chain_phases_covered),
    }


def _metrics_from_json(data: dict[str, Any]) -> EvaluationMetrics:
    return EvaluationMetrics(
        detection_coverage_percent=float(data.get("detection_coverage_percent", 0.0)),
        technique_success_rate=float(data.get("technique_success_rate", 0.0)),
        evasion_rate=float(data.get("evasion_rate", 0.0)),
        mean_time_to_detect_seconds=data.get("mean_time_to_detect_seconds"),
        actions_executed_count=int(data.get("actions_executed_count", 0)),
        actions_failed_count=int(data.get("actions_failed_count", 0)),
        objectives_achieved_count=int(data.get("objectives_achieved_count", 0)),
        objectives_failed_count=int(data.get("objectives_failed_count", 0)),
        campaign_duration_seconds=data.get("campaign_duration_seconds"),
        kill_chain_phases_covered=tuple(data.get("kill_chain_phases_covered") or ()),
    )


def _from_row(row: CampaignEvaluationModel) -> CampaignEvaluation:
    assessments = [
        ObjectiveAssessment(
            assessment_id=ObjectiveAssessmentId(UUID(a["assessment_id"])),
            objective_id=a["objective_id"],
            objective_type=a["objective_type"],
            outcome=ObjectiveOutcome(a["outcome"]),
            evidence_refs=list(a.get("evidence_refs") or []),
            reason=a.get("reason", ""),
            assessed_at=None,
        )
        for a in (row.assessments_json or [])
    ]
    technique_outcomes = [
        TechniqueOutcomeRecord(
            technique_ref=MitreAttackRef(
                technique_id=t["technique_id"],
                technique_name=t.get("technique_name", t["technique_id"]),
            ),
            succeeded=bool(t["succeeded"]),
            detected=bool(t["detected"]),
            evaded=bool(t["evaded"]),
            action_ids=list(t.get("action_ids") or []),
            finding_ids=list(t.get("finding_ids") or []),
        )
        for t in (row.technique_outcomes_json or [])
    ]
    late = [
        LateDetectionRecord(
            finding_id=ld["finding_id"],
            technique_id=ld["technique_id"],
            delay_seconds=float(ld["delay_seconds"]),
        )
        for ld in (row.late_detections_json or [])
    ]
    specs = [
        ObjectiveSpec(
            objective_id=s["objective_id"],
            objective_type=s["objective_type"],
            is_required=bool(s.get("is_required", True)),
            condition_type=s["condition_type"],
            parameters=dict(s.get("parameters") or {}),
        )
        for s in (row.objective_specs_json or [])
    ]
    kill_chain = None
    if row.kill_chain_json:
        phases = tuple(
            KillChainPhaseOutcome(
                phase_name=p["phase_name"],
                tasks_planned=int(p["tasks_planned"]),
                tasks_completed=int(p["tasks_completed"]),
                tasks_failed=int(p["tasks_failed"]),
            )
            for p in (row.kill_chain_json.get("phase_outcomes") or [])
        )
        kill_chain = KillChainProgressionMap(phase_outcomes=phases)

    compliance = [
        ComplianceMappingResult(
            control_id=c["control_id"],
            control_name=c["control_name"],
            framework=c["framework"],
            outcome=c["outcome"],
            objective_id=c["objective_id"],
        )
        for c in (row.compliance_mappings_json or [])
    ]

    return CampaignEvaluation(
        evaluation_id=CampaignEvaluationId(row.id),
        tenant_id=TenantId(row.tenant_id),
        campaign_instance_ref=CampaignInstanceRef(
            instance_id=row.campaign_instance_id,
            campaign_id=row.campaign_id,
            tenant_id=row.tenant_id,
            run_number=row.run_number,
        ),
        state=EvaluationState(row.state),
        objective_specs=specs,
        assessments=assessments,
        technique_outcomes=technique_outcomes,
        late_detections=late,
        metrics=_metrics_from_json(row.metrics_json or {}),
        composite_outcome=(
            CompositeOutcome(row.composite_outcome) if row.composite_outcome else None
        ),
        kill_chain_progression=kill_chain,
        compliance_mappings=compliance,
        correlation_window_minutes=row.correlation_window_minutes,
        execution_failed=row.execution_failed,
        version=row.row_version,
    )


class PgCampaignEvaluationRepository(ICampaignEvaluationRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, evaluation: CampaignEvaluation) -> None:
        assessments_json = [
            {
                "assessment_id": str(a.assessment_id),
                "objective_id": a.objective_id,
                "objective_type": a.objective_type,
                "outcome": a.outcome.value,
                "evidence_refs": a.evidence_refs,
                "reason": a.reason,
            }
            for a in evaluation.assessments
        ]
        technique_json = [
            {
                "technique_id": t.technique_id,
                "technique_name": t.technique_ref.technique_name,
                "succeeded": t.succeeded,
                "detected": t.detected,
                "evaded": t.evaded,
                "action_ids": t.action_ids,
                "finding_ids": t.finding_ids,
            }
            for t in evaluation.technique_outcomes
        ]
        late_json = [
            {
                "finding_id": ld.finding_id,
                "technique_id": ld.technique_id,
                "delay_seconds": ld.delay_seconds,
            }
            for ld in evaluation.late_detections
        ]
        specs_json = [
            {
                "objective_id": s.objective_id,
                "objective_type": s.objective_type,
                "is_required": s.is_required,
                "condition_type": s.condition_type,
                "parameters": dict(s.parameters),
            }
            for s in evaluation.objective_specs
        ]
        kill_json = None
        if evaluation.kill_chain_progression:
            kill_json = {
                "phase_outcomes": [
                    {
                        "phase_name": p.phase_name,
                        "tasks_planned": p.tasks_planned,
                        "tasks_completed": p.tasks_completed,
                        "tasks_failed": p.tasks_failed,
                    }
                    for p in evaluation.kill_chain_progression.phase_outcomes
                ]
            }
        compliance_json = [
            {
                "control_id": c.control_id,
                "control_name": c.control_name,
                "framework": c.framework,
                "outcome": c.outcome,
                "objective_id": c.objective_id,
            }
            for c in evaluation.compliance_mappings
        ]

        existing = await self._session.get(
            CampaignEvaluationModel, evaluation.evaluation_id.value
        )
        if existing is None:
            row = CampaignEvaluationModel(
                id=evaluation.evaluation_id.value,
                tenant_id=evaluation.tenant_id.value,
                campaign_instance_id=evaluation.campaign_instance_ref.instance_id,
                campaign_id=evaluation.campaign_instance_ref.campaign_id,
                run_number=evaluation.campaign_instance_ref.run_number,
                state=evaluation.state.value,
                composite_outcome=(
                    evaluation.composite_outcome.value
                    if evaluation.composite_outcome
                    else None
                ),
                execution_failed=evaluation.execution_failed,
                correlation_window_minutes=evaluation.correlation_window_minutes,
                objective_specs_json=specs_json,
                assessments_json=assessments_json,
                technique_outcomes_json=technique_json,
                late_detections_json=late_json,
                metrics_json=_metrics_to_json(evaluation.metrics),
                kill_chain_json=kill_json,
                compliance_mappings_json=compliance_json,
                row_version=evaluation.version,
            )
            self._session.add(row)
        else:
            if existing.tenant_id != evaluation.tenant_id.value:
                raise TenantMismatch(evaluation.tenant_id, existing.tenant_id)
            existing.state = evaluation.state.value
            existing.composite_outcome = (
                evaluation.composite_outcome.value
                if evaluation.composite_outcome
                else None
            )
            existing.execution_failed = evaluation.execution_failed
            existing.correlation_window_minutes = evaluation.correlation_window_minutes
            existing.objective_specs_json = specs_json
            existing.assessments_json = assessments_json
            existing.technique_outcomes_json = technique_json
            existing.late_detections_json = late_json
            existing.metrics_json = _metrics_to_json(evaluation.metrics)
            existing.kill_chain_json = kill_json
            existing.compliance_mappings_json = compliance_json
            existing.row_version = evaluation.version

    async def find_by_id(
        self,
        evaluation_id: CampaignEvaluationId,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        row = await self._session.get(CampaignEvaluationModel, evaluation_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return _from_row(row)

    async def find_by_campaign_instance(
        self,
        campaign_instance_id: str,
        tenant_id: TenantId,
    ) -> CampaignEvaluation | None:
        stmt = select(CampaignEvaluationModel).where(
            CampaignEvaluationModel.campaign_instance_id
            == UUID(campaign_instance_id),
            CampaignEvaluationModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _from_row(row)
