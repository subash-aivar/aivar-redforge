from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from ai_agent_governance.application._auth import is_admin, require_at_least
from ai_agent_governance.application.dtos.governance_dtos import AdvisoryDTO, EnvelopeDTO
from ai_agent_governance.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
    AgentOperationalEnvelope,
)
from ai_agent_governance.domain.exceptions.domain_exceptions import (
    AgentGovernanceDomainError,
)
from ai_agent_governance.domain.services.envelope_revision_advisory_service import (
    EnvelopeRevisionAdvisoryService,
)
from ai_agent_governance.domain.value_objects.enums import (
    AIPostureRole,
    AuthorizedActionCategory,
    DataSensitivityClassification,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
    AISystemAssetId,
    TenantId,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from ai_agent_governance.application.commands.governance_commands import (
        AddAuthorizedActionCommand,
        ApproveEnvelopeCommand,
        DraftEnvelopeCommand,
        RetireEnvelopeCommand,
        ReviseEnvelopeCommand,
        SuspendEnvelopeCommand,
    )
    from ai_agent_governance.application.ports.i_event_publisher import IEventPublisher
    from ai_agent_governance.application.ports.i_unit_of_work import IUnitOfWork


def _to_dto(env: AgentOperationalEnvelope) -> EnvelopeDTO:
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


class EnvelopeApplicationService:
    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._publisher = event_publisher
        self._advisory = EnvelopeRevisionAdvisoryService()

    async def draft(self, cmd: DraftEnvelopeCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        human = {AuthorizedActionCategory(x) for x in cmd.requires_human_approval_for}
        async with self._uow_factory() as uow:
            existing = await uow.envelopes.find_by_asset(AISystemAssetId(cmd.asset_id), tenant)
            if existing is not None:
                return _to_dto(existing)
            env = AgentOperationalEnvelope.draft(
                AgentOperationalEnvelopeId.generate(),
                tenant,
                AISystemAssetId(cmd.asset_id),
                DataSensitivityClassification(cmd.max_data_sensitivity),
                now,
                requires_human_approval_for=human,
            )
            await uow.envelopes.save(env)
            await uow.envelopes.save_version_snapshot(env)
            await uow.commit()
            await self._publisher.publish_batch(env.pop_events())
        return _to_dto(env)

    async def add_action(self, cmd: AddAuthorizedActionCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(cmd.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.envelope_id))
            try:
                env.add_action(tenant, AuthorizedActionCategory(cmd.category), cmd.description)
            except AgentGovernanceDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.envelopes.save(env)
            await uow.commit()
        return _to_dto(env)

    async def approve(self, cmd: ApproveEnvelopeCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.APPROVER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(cmd.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.envelope_id))
            try:
                env.approve(tenant, cmd.approver_id, now)
            except AgentGovernanceDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.envelopes.save(env)
            await uow.envelopes.save_version_snapshot(env)
            await uow.commit()
            await self._publisher.publish_batch(env.pop_events())
        return _to_dto(env)

    async def revise(self, cmd: ReviseEnvelopeCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ENGINEER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(cmd.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.envelope_id))
            try:
                env.revise(
                    tenant,
                    now,
                    new_actions=[(AuthorizedActionCategory(c), d) for c, d in cmd.new_actions]
                    or None,
                    remove_human_approval={
                        AuthorizedActionCategory(x) for x in cmd.remove_human_approval_for
                    }
                    or None,
                    actor_is_admin=is_admin(cmd.actor_roles),
                )
                if env.state.value == "UnderRevision" and env.approved_by is not None:
                    env.reactivate_after_revision(tenant, now)
            except AgentGovernanceDomainError as exc:
                raise ApplicationValidationError(str(exc)) from exc
            await uow.envelopes.save(env)
            await uow.envelopes.save_version_snapshot(env)
            await uow.commit()
            await self._publisher.publish_batch(env.pop_events())
        return _to_dto(env)

    async def suspend(self, cmd: SuspendEnvelopeCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.APPROVER)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(cmd.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.envelope_id))
            env.suspend(tenant, cmd.reason, now)
            await uow.envelopes.save(env)
            await uow.commit()
            await self._publisher.publish_batch(env.pop_events())
        return _to_dto(env)

    async def retire(self, cmd: RetireEnvelopeCommand) -> EnvelopeDTO:
        require_at_least(cmd.actor_roles, AIPostureRole.ADMIN)
        tenant = cmd.tenant_id
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(
                AgentOperationalEnvelopeId(cmd.envelope_id), tenant
            )
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(cmd.envelope_id))
            env.retire(tenant, cmd.reason, now)
            await uow.envelopes.save(env)
            await uow.commit()
            await self._publisher.publish_batch(env.pop_events())
        return _to_dto(env)

    async def advisories(self, tenant_id: TenantId, envelope_id: UUID) -> list[AdvisoryDTO]:
        tenant = tenant_id
        async with self._uow_factory() as uow:
            env = await uow.envelopes.find_by_id(AgentOperationalEnvelopeId(envelope_id), tenant)
            if env is None:
                raise ApplicationNotFoundError("AgentOperationalEnvelope", str(envelope_id))
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
