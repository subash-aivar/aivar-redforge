"""Agent governance CQRS query handlers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent_governance.application._auth import require_at_least
from ai_agent_governance.application.dtos.governance_dtos import (
    AdvisoryDTO,
    DeviationDTO,
    EnvelopeDTO,
)
from ai_agent_governance.application.exceptions import ApplicationNotFoundError
from ai_agent_governance.domain.services.envelope_revision_advisory_service import (
    EnvelopeRevisionAdvisoryService,
)
from ai_agent_governance.domain.value_objects.enums import AIPostureRole
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
    AISystemAssetId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_agent_governance.application.ports.i_unit_of_work import IUnitOfWork
    from ai_agent_governance.application.queries.governance_queries import (
        CountRecentDeviationsForAssetQuery,
        GetEnvelopeAdvisoriesQuery,
        GetEnvelopeQuery,
        ListUnreviewedDeviationsQuery,
    )
    from ai_agent_governance.domain.aggregates.agent_deviation_event import (
        AgentDeviationEvent,
    )
    from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
        AgentOperationalEnvelope,
    )


def _envelope_dto(env: AgentOperationalEnvelope) -> EnvelopeDTO:
    return EnvelopeDTO(
        envelope_id=str(env.envelope_id),
        tenant_id=str(env.tenant_id),
        ai_system_asset_id=str(env.ai_system_asset_id),
        state=env.state.value,
        envelope_version=env.envelope_version,
        action_categories=[a.category.value for a in env.actions],
        requires_human_approval_for=[c.value for c in env.requires_human_approval_for],
        approved_by=env.approved_by.approver_id if env.approved_by else None,
    )


def _deviation_dto(d: AgentDeviationEvent) -> DeviationDTO:
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


class GovernanceQueryHandler:
    def __init__(self, uow_factory: Callable[[], IUnitOfWork]) -> None:
        self._uow_factory = uow_factory
        self._advisory = EnvelopeRevisionAdvisoryService()

    async def get_envelope(self, query: GetEnvelopeQuery) -> EnvelopeDTO:
        require_at_least(query.actor_roles, AIPostureRole.READER)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(query.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(query.envelope_id))
        return _envelope_dto(env)

    async def get_advisories(self, query: GetEnvelopeAdvisoriesQuery) -> list[AdvisoryDTO]:
        require_at_least(query.actor_roles, AIPostureRole.ANALYST)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(query.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(query.envelope_id))
            deviations = await uow.deviations.find_by_asset(env.ai_system_asset_id, tenant, 500)
        return [
            AdvisoryDTO(
                envelope_id=a.envelope_id,
                deviation_type=a.deviation_type,
                confirmed_benign_count=a.confirmed_benign_count,
                recommendation=a.recommendation,
            )
            for a in self._advisory.advise(env.envelope_id, deviations)
        ]

    async def list_unreviewed(self, query: ListUnreviewedDeviationsQuery) -> list[DeviationDTO]:
        require_at_least(query.actor_roles, AIPostureRole.ANALYST)
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            items = await uow.deviations.find_unreviewed_by_tenant(tenant)
        return [_deviation_dto(d) for d in items]

    async def count_recent_deviations(self, query: CountRecentDeviationsForAssetQuery) -> int:
        tenant = query.tenant_id
        async with self._uow_factory() as uow:
            items = await uow.deviations.find_by_asset(
                AISystemAssetId(query.asset_id), tenant, query.limit
            )
        return len(items)
