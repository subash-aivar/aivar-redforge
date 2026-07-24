from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from ai_agent_governance.application._auth import require_at_least
from ai_agent_governance.application.dtos.governance_dtos import (
    DeviationDTO,
    ReportActionResultDTO,
)
from ai_agent_governance.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_agent_governance.domain.exceptions.domain_exceptions import (
    AgentGovernanceDomainError,
)
from ai_agent_governance.domain.services.envelope_compliance_evaluation_service import (
    EnvelopeComplianceEvaluationService,
)
from ai_agent_governance.domain.value_objects.enums import (
    AIPostureRole,
    AuthorizedActionCategory,
    DataSensitivityClassification,
)
from ai_agent_governance.domain.value_objects.governance_vos import ObservedAction
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentDeviationEventId,
    AISystemAssetId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_agent_governance.application.commands.governance_commands import (
        ReportAgentActionCommand,
        ReviewDeviationCommand,
    )
    from ai_agent_governance.application.ports.i_event_publisher import IEventPublisher
    from ai_agent_governance.application.ports.i_unit_of_work import IUnitOfWork
    from ai_agent_governance.domain.aggregates.agent_deviation_event import (
        AgentDeviationEvent,
    )


def _dev_dto(d: AgentDeviationEvent) -> DeviationDTO:
    return DeviationDTO(
        deviation_id=str(d.deviation_id),
        tenant_id=str(d.tenant_id),
        ai_system_asset_id=str(d.ai_system_asset_id),
        deviation_type=d.deviation_type.value,
        severity=d.severity.value,
        review_state=d.review_state.value,
        envelope_version=d.envelope_ref.envelope_version,
        review_notes=d.review_notes,
    )


class DeviationApplicationService:
    """ReportAgentAction is idempotent and may be batched by callers."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._evaluator = EnvelopeComplianceEvaluationService()

    async def report_action(self, cmd: ReportAgentActionCommand) -> ReportActionResultDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            first = await uow.deviations.record_idempotent_action(
                tenant, cmd.idempotency_key, "pending"
            )
            if not first:
                existing = await uow.deviations.find_by_idempotency_key(tenant, cmd.idempotency_key)
                return ReportActionResultDTO(
                    status="duplicate",
                    deviation=_dev_dto(existing) if existing else None,
                )
            envelope = await uow.envelopes.find_active_version_at(
                AISystemAssetId(cmd.asset_id), cmd.occurred_at, tenant
            )
            if envelope is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.asset_id))
            action = ObservedAction(
                action_category=AuthorizedActionCategory(cmd.action_category),
                resource=cmd.resource,
                data_sensitivity=DataSensitivityClassification(cmd.data_sensitivity),
                human_approval_present=cmd.human_approval_present,
                occurred_at=cmd.occurred_at,
                idempotency_key=cmd.idempotency_key,
                metadata={},
            )
            deviation = self._evaluator.evaluate(envelope, action, tenant, now)
            if deviation is None:
                await uow.deviations.record_idempotent_action(
                    tenant, cmd.idempotency_key, "compliant"
                )
                await uow.commit()
                return ReportActionResultDTO(status="compliant", deviation=None)
            await uow.deviations.save(deviation)
            await uow.deviations.record_idempotent_action(tenant, cmd.idempotency_key, "deviation")
            await uow.commit()
            await self._publisher.publish_batch(deviation.pop_events())
        return ReportActionResultDTO(status="deviation", deviation=_dev_dto(deviation))

    async def review(self, cmd: ReviewDeviationCommand) -> DeviationDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ANALYST)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            deviation = await uow.deviations.find_by_id(
                AgentDeviationEventId(cmd.deviation_id), tenant
            )
            if deviation is None:
                raise ApplicationNotFoundError("AgentDeviationEvent", str(cmd.deviation_id))
            try:
                if deviation.review_state.value == "Unreviewed":
                    deviation.begin_review(tenant, now)
                if cmd.decision == "confirm":
                    deviation.confirm_deviation(tenant, cmd.notes, now)
                elif cmd.decision == "benign":
                    deviation.dismiss_benign(tenant, cmd.notes, now)
                elif cmd.decision == "envelope_updated":
                    deviation.close_as_envelope_updated(tenant, cmd.linked_revision_event_id, now)
                else:
                    raise ApplicationValidationError("invalid decision")
            except AgentGovernanceDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.deviations.save(deviation)
            await uow.commit()
            await self._publisher.publish_batch(deviation.pop_events())
        return _dev_dto(deviation)

    async def recent_deviation_count(
        self, tenant_id: TenantId, asset_id: UUID, *, limit: int = 100
    ) -> int:
        """Used by ai_posture ACL for agent risk component."""
        tenant = tenant_id
        async with self._uow_factory() as uow:
            items = await uow.deviations.find_by_asset(AISystemAssetId(asset_id), tenant, limit)
        return len(items)
