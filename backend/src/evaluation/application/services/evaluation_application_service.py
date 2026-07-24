"""EvaluationApplicationService — EvaluateCampaign orchestration."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from evaluation.application.dtos.evaluation_dtos import (
    DetectionCoverageTrendDTO,
    EvaluationDTO,
    MetricsSnapshotDTO,
    ObjectiveAssessmentDTO,
    TechniqueOutcomeDTO,
)
from evaluation.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from evaluation.domain.aggregates.campaign_evaluation import CampaignEvaluation
from evaluation.domain.aggregates.campaign_metrics_snapshot import CampaignMetricsSnapshot
from evaluation.domain.exceptions.domain_exceptions import ObjectiveAlreadyAssessed
from evaluation.domain.services.detection_coverage_calculator import (
    DetectionCoverageCalculator,
)
from evaluation.domain.services.objective_evaluation_engine import ObjectiveEvaluationEngine
from evaluation.domain.value_objects.enums import EvaluationState
from evaluation.domain.value_objects.evaluation_vos import (
    CampaignInstanceRef,
    DetectionCorrelationConfig,
    KillChainProgressionMap,
)
from evaluation.domain.value_objects.identifiers import (
    CampaignEvaluationId,
    CampaignMetricsSnapshotId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from evaluation.application.commands.evaluation_commands import (
        EvaluateCampaignCommand,
        GetEvaluationQuery,
        GetMetricsTrendQuery,
        ResolveEvaluationReviewCommand,
    )
    from evaluation.application.ports.i_event_publisher import IEventPublisher
    from evaluation.application.ports.i_unit_of_work import IUnitOfWork
    from evaluation.domain.events.base import BaseDomainEvent
    from evaluation.domain.ports.i_attack_action_query_port import IAttackActionQueryPort
    from evaluation.domain.ports.i_compliance_query_port import IComplianceQueryPort
    from evaluation.domain.ports.i_detection_finding_query_port import (
        IDetectionFindingQueryPort,
    )
    from evaluation.domain.ports.i_evidence_query_port import IEvidenceQueryPort
    from evaluation.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


def _to_evaluation_dto(evaluation: CampaignEvaluation) -> EvaluationDTO:
    metrics = evaluation.metrics
    return EvaluationDTO(
        evaluation_id=str(evaluation.evaluation_id),
        tenant_id=str(evaluation.tenant_id),
        campaign_instance_id=str(evaluation.campaign_instance_ref.instance_id),
        campaign_id=str(evaluation.campaign_instance_ref.campaign_id),
        run_number=evaluation.campaign_instance_ref.run_number,
        state=evaluation.state.value,
        composite_outcome=(
            evaluation.composite_outcome.value if evaluation.composite_outcome else None
        ),
        detection_coverage_percent=(metrics.detection_coverage_percent if metrics else 0.0),
        technique_success_rate=metrics.technique_success_rate if metrics else 0.0,
        evasion_rate=metrics.evasion_rate if metrics else 0.0,
        mean_time_to_detect_seconds=(metrics.mean_time_to_detect_seconds if metrics else None),
        objectives_achieved=metrics.objectives_achieved_count if metrics else 0,
        objectives_failed=metrics.objectives_failed_count if metrics else 0,
        correlation_window_minutes=evaluation.correlation_window_minutes,
        late_detections_count=len(evaluation.late_detections),
        assessments=[
            ObjectiveAssessmentDTO(
                objective_id=a.objective_id,
                objective_type=a.objective_type,
                outcome=a.outcome.value,
                evidence_refs=a.evidence_refs,
                reason=a.reason,
            )
            for a in evaluation.assessments
        ],
        technique_outcomes=[
            TechniqueOutcomeDTO(
                technique_id=t.technique_id,
                succeeded=t.succeeded,
                detected=t.detected,
                evaded=t.evaded,
            )
            for t in evaluation.technique_outcomes
        ],
    )


def _compute_trend_direction(values: list[float]) -> str:
    """better = coverage rising; worse = falling; same = flat."""
    if len(values) < 2:
        return "same"
    # Use last three runs when available (quality gate)
    window = values[-3:] if len(values) >= 3 else values
    deltas = [window[i + 1] - window[i] for i in range(len(window) - 1)]
    if all(d > 0 for d in deltas):
        return "better"
    if all(d < 0 for d in deltas):
        return "worse"
    if all(d == 0 for d in deltas):
        return "same"
    # Net direction across window
    net = window[-1] - window[0]
    if net > 0:
        return "better"
    if net < 0:
        return "worse"
    return "same"


class EvaluationApplicationService:
    """Orchestrates EvaluateCampaign and metrics trend queries."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        attack_action_port: IAttackActionQueryPort,
        detection_finding_port: IDetectionFindingQueryPort,
        evidence_port: IEvidenceQueryPort,
        compliance_port: IComplianceQueryPort | None = None,
        graph_write_port: ISecurityGraphWritePort | None = None,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._attack_port = attack_action_port
        self._finding_port = detection_finding_port
        self._evidence_port = evidence_port
        self._compliance_port = compliance_port
        self._graph_port = graph_write_port
        self._objective_engine = ObjectiveEvaluationEngine()
        self._coverage_calculator = DetectionCoverageCalculator()

    async def _publish(self, events: list[BaseDomainEvent]) -> None:
        if events:
            await self._publisher.publish_batch(events)

    async def evaluate_campaign(self, cmd: EvaluateCampaignCommand) -> EvaluationDTO:
        """Full evaluation pipeline: assess objectives → coverage → complete → snapshot → graph."""
        tenant_id = cmd.tenant_id
        instance_id = str(cmd.campaign_instance_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            existing = await uow.evaluations.find_by_campaign_instance(instance_id, tenant_id)
            if existing is not None and existing.state in {
                EvaluationState.COMPLETE,
                EvaluationState.REQUIRES_REVIEW,
                EvaluationState.EVALUATING,
            }:
                # Idempotent: return existing evaluation for same instance
                if existing.state == EvaluationState.COMPLETE:
                    return _to_evaluation_dto(existing)
                if existing.state == EvaluationState.REQUIRES_REVIEW:
                    return _to_evaluation_dto(existing)
                raise ApplicationConflictError(
                    f"Evaluation already in progress for instance {instance_id}"
                )

            instance_ref = CampaignInstanceRef(
                instance_id=cmd.campaign_instance_id,
                campaign_id=cmd.campaign_id,
                tenant_id=cmd.tenant_id,
                run_number=cmd.run_number,
            )
            evaluation = CampaignEvaluation.start(
                evaluation_id=CampaignEvaluationId.generate(),
                tenant_id=tenant_id,
                campaign_instance_ref=instance_ref,
                objective_specs=list(cmd.objective_specs),
                correlation_window_minutes=cmd.correlation_window_minutes,
                execution_failed=cmd.execution_failed,
                now=now,
            )

            actions = await self._attack_port.list_by_campaign_instance(instance_id, str(tenant_id))
            started = cmd.started_at or now.isoformat()
            completed = cmd.completed_at or now.isoformat()
            findings = await self._finding_port.list_by_campaign_instance(
                instance_id, str(tenant_id), started, completed
            )
            evidence = await self._evidence_port.list_by_campaign_instance(
                instance_id, str(tenant_id)
            )

            for spec in cmd.objective_specs:
                assessment = self._objective_engine.evaluate(spec, actions, findings, evidence, now)
                with contextlib.suppress(ObjectiveAlreadyAssessed):
                    evaluation.record_assessment(tenant_id, assessment, now)

            config = DetectionCorrelationConfig(
                correlation_window_minutes=cmd.correlation_window_minutes,
            )
            coverage = self._coverage_calculator.compute(actions, findings, config)
            evaluation.record_coverage(
                tenant_id=tenant_id,
                metrics=coverage.metrics,
                technique_outcomes=list(coverage.technique_outcomes),
                late_detections=list(coverage.late_detections),
                techniques_executed=coverage.techniques_executed,
                techniques_detected=coverage.techniques_detected,
                now=now,
            )
            evaluation.set_per_phase_coverage(tenant_id, coverage.per_phase_coverage)

            if cmd.kill_chain_phases:
                evaluation.set_kill_chain_progression(
                    tenant_id,
                    KillChainProgressionMap(phase_outcomes=tuple(cmd.kill_chain_phases)),
                )

            if self._compliance_port is not None:
                mappings = await self._compliance_port.map_objectives(
                    str(cmd.campaign_id),
                    str(tenant_id),
                    [s.objective_id for s in cmd.objective_specs],
                )
                evaluation.set_compliance_mappings(tenant_id, mappings)

            evaluation.complete(tenant_id, now)

            await uow.evaluations.save(evaluation)

            snapshot: CampaignMetricsSnapshot | None = None
            if evaluation.state == EvaluationState.COMPLETE and evaluation.metrics:
                snapshot = CampaignMetricsSnapshot.create(
                    snapshot_id=CampaignMetricsSnapshotId.generate(),
                    tenant_id=tenant_id,
                    campaign_id=str(cmd.campaign_id),
                    run_number=cmd.run_number,
                    metrics=evaluation.metrics,
                    composite_outcome=(
                        evaluation.composite_outcome.value
                        if evaluation.composite_outcome
                        else "Inconclusive"
                    ),
                    now=now,
                )
                await uow.metrics_snapshots.save(snapshot)

            await uow.commit()

            events = evaluation.pop_events()
            if snapshot is not None:
                events.extend(snapshot.pop_events())
            await self._publish(events)

            if self._graph_port is not None and evaluation.state == EvaluationState.COMPLETE:
                await self._write_graph(evaluation)

            return _to_evaluation_dto(evaluation)

    async def _write_graph(self, evaluation: CampaignEvaluation) -> None:
        assert self._graph_port is not None
        tenant = str(evaluation.tenant_id)
        eval_id = str(evaluation.evaluation_id)
        instance_id = str(evaluation.campaign_instance_ref.instance_id)
        coverage = evaluation.metrics.detection_coverage_percent if evaluation.metrics else 0.0
        outcome = (
            evaluation.composite_outcome.value if evaluation.composite_outcome else "Inconclusive"
        )
        await self._graph_port.upsert_campaign_evaluation_node(
            tenant_id=tenant,
            evaluation_id=eval_id,
            campaign_instance_id=instance_id,
            composite_outcome=outcome,
            detection_coverage_pct=coverage,
        )
        await self._graph_port.upsert_evaluated_by_edge(
            tenant_id=tenant,
            campaign_instance_id=instance_id,
            evaluation_id=eval_id,
        )
        technique_refs = [t.technique_ref for t in evaluation.technique_outcomes]
        detected = frozenset(t.technique_id for t in evaluation.technique_outcomes if t.detected)
        succeeded = frozenset(t.technique_id for t in evaluation.technique_outcomes if t.succeeded)
        await self._graph_port.upsert_covered_technique_edges(
            tenant_id=tenant,
            evaluation_id=eval_id,
            technique_refs=technique_refs,
            detected_technique_ids=detected,
            succeeded_technique_ids=succeeded,
        )

    async def resolve_review(self, cmd: ResolveEvaluationReviewCommand) -> EvaluationDTO:
        tenant_id = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            evaluation = await uow.evaluations.find_by_id(
                CampaignEvaluationId(cmd.evaluation_id), tenant_id
            )
            if evaluation is None:
                raise ApplicationNotFoundError("CampaignEvaluation", str(cmd.evaluation_id))
            if not cmd.documented_reason.strip():
                raise ApplicationValidationError("documented_reason is required")

            evaluation.mark_review_resolved(tenant_id, now, cmd.documented_reason)
            await uow.evaluations.save(evaluation)

            snapshot = None
            if evaluation.metrics is not None:
                snapshot = CampaignMetricsSnapshot.create(
                    snapshot_id=CampaignMetricsSnapshotId.generate(),
                    tenant_id=tenant_id,
                    campaign_id=str(evaluation.campaign_instance_ref.campaign_id),
                    run_number=evaluation.campaign_instance_ref.run_number,
                    metrics=evaluation.metrics,
                    composite_outcome=(
                        evaluation.composite_outcome.value
                        if evaluation.composite_outcome
                        else "Inconclusive"
                    ),
                    now=now,
                )
                await uow.metrics_snapshots.save(snapshot)

            await uow.commit()
            events = evaluation.pop_events()
            if snapshot is not None:
                events.extend(snapshot.pop_events())
            await self._publish(events)

            if self._graph_port is not None:
                await self._write_graph(evaluation)

            return _to_evaluation_dto(evaluation)

    async def get_evaluation(self, query: GetEvaluationQuery) -> EvaluationDTO | None:
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            evaluation = await uow.evaluations.find_by_campaign_instance(
                str(query.campaign_instance_id), tenant_id
            )
            if evaluation is None:
                return None
            return _to_evaluation_dto(evaluation)

    async def get_metrics_trend(self, query: GetMetricsTrendQuery) -> DetectionCoverageTrendDTO:
        tenant_id = query.tenant_id
        async with self._uow_factory() as uow:
            snapshots = await uow.metrics_snapshots.find_by_campaign(
                str(query.campaign_id), tenant_id, limit=query.limit
            )
        # find_by_campaign returns newest first — reverse for chronological trend
        chronological = list(reversed(snapshots))
        values = [s.metrics.detection_coverage_percent for s in chronological]
        return DetectionCoverageTrendDTO(
            campaign_id=str(query.campaign_id),
            run_count=len(values),
            coverage_values=values,
            trend_direction=_compute_trend_direction(values),
            latest_coverage=values[-1] if values else 0.0,
        )

    async def list_metrics_snapshots(
        self, tenant_id: TenantId, campaign_id: UUID, limit: int = 50
    ) -> list[MetricsSnapshotDTO]:
        tid = tenant_id
        async with self._uow_factory() as uow:
            snapshots = await uow.metrics_snapshots.find_by_campaign(
                str(campaign_id), tid, limit=limit
            )
        return [
            MetricsSnapshotDTO(
                snapshot_id=str(s.snapshot_id),
                campaign_id=s.campaign_id,
                run_number=s.run_number,
                snapshot_timestamp=s.snapshot_timestamp,
                detection_coverage_percent=s.metrics.detection_coverage_percent,
                technique_success_rate=s.metrics.technique_success_rate,
                evasion_rate=s.metrics.evasion_rate,
                composite_outcome=s.composite_outcome,
            )
            for s in snapshots
        ]
