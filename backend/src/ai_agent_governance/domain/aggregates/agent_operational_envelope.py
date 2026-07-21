from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_agent_governance.domain.entities.authorized_action import AuthorizedAction
from ai_agent_governance.domain.events.governance_events import (
    AgentOperationalEnvelopeApproved,
    AgentOperationalEnvelopeDrafted,
    AgentOperationalEnvelopeRetired,
    AgentOperationalEnvelopeRevised,
    AgentOperationalEnvelopeSuspended,
)
from ai_agent_governance.domain.exceptions.domain_exceptions import (
    EnvelopeActivationRequirements,
    HumanApprovalCategoryLocked,
    InvalidEnvelopeTransition,
    TenantMismatch,
)
from ai_agent_governance.domain.value_objects.enums import EnvelopeState
from ai_agent_governance.domain.value_objects.governance_vos import EnvelopeApprovedBy
from ai_agent_governance.domain.value_objects.identifiers import AuthorizedActionId

if TYPE_CHECKING:
    from datetime import datetime

    from ai_agent_governance.domain.events.base import BaseDomainEvent
    from ai_agent_governance.domain.value_objects.enums import (
        AuthorizedActionCategory,
        DataSensitivityClassification,
    )
    from ai_agent_governance.domain.value_objects.governance_vos import (
        AuthorizedResourceScope,
        RateCeiling,
    )
    from ai_agent_governance.domain.value_objects.identifiers import (
        AgentOperationalEnvelopeId,
        AISystemAssetId,
        TenantId,
    )

_ALLOWED: dict[EnvelopeState, frozenset[EnvelopeState]] = {
    EnvelopeState.DRAFT: frozenset({EnvelopeState.ACTIVE, EnvelopeState.RETIRED}),
    EnvelopeState.ACTIVE: frozenset(
        {EnvelopeState.UNDER_REVISION, EnvelopeState.SUSPENDED, EnvelopeState.RETIRED}
    ),
    EnvelopeState.UNDER_REVISION: frozenset(
        {EnvelopeState.ACTIVE, EnvelopeState.SUSPENDED, EnvelopeState.RETIRED}
    ),
    EnvelopeState.SUSPENDED: frozenset({EnvelopeState.ACTIVE, EnvelopeState.RETIRED}),
    EnvelopeState.RETIRED: frozenset(),
}


class AgentOperationalEnvelope:
    __slots__ = (
        "_pending_events",
        "_version",
        "actions",
        "ai_system_asset_id",
        "approved_by",
        "effective_from",
        "effective_until",
        "envelope_id",
        "envelope_version",
        "max_authorized_data_sensitivity",
        "rate_ceilings",
        "requires_human_approval_for",
        "resource_scopes",
        "state",
        "tenant_id",
    )

    def __init__(
        self,
        envelope_id: AgentOperationalEnvelopeId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        state: EnvelopeState,
        envelope_version: int,
        actions: list[AuthorizedAction],
        resource_scopes: list[AuthorizedResourceScope],
        max_authorized_data_sensitivity: DataSensitivityClassification,
        rate_ceilings: list[RateCeiling],
        requires_human_approval_for: set[AuthorizedActionCategory],
        approved_by: EnvelopeApprovedBy | None,
        effective_from: datetime,
        effective_until: datetime | None,
        version: int,
    ) -> None:
        self.envelope_id = envelope_id
        self.tenant_id = tenant_id
        self.ai_system_asset_id = ai_system_asset_id
        self.state = state
        self.envelope_version = envelope_version
        self.actions = list(actions)
        self.resource_scopes = list(resource_scopes)
        self.max_authorized_data_sensitivity = max_authorized_data_sensitivity
        self.rate_ceilings = list(rate_ceilings)
        self.requires_human_approval_for = set(requires_human_approval_for)
        self.approved_by = approved_by
        self.effective_from = effective_from
        self.effective_until = effective_until
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: EnvelopeState) -> None:
        if to_state not in _ALLOWED.get(self.state, frozenset()):
            raise InvalidEnvelopeTransition(self.state.value, to_state.value)
        self.state = to_state

    @classmethod
    def draft(
        cls,
        envelope_id: AgentOperationalEnvelopeId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        max_sensitivity: DataSensitivityClassification,
        now: datetime,
        *,
        requires_human_approval_for: set[AuthorizedActionCategory] | None = None,
    ) -> AgentOperationalEnvelope:
        env = cls(
            envelope_id=envelope_id,
            tenant_id=tenant_id,
            ai_system_asset_id=ai_system_asset_id,
            state=EnvelopeState.DRAFT,
            envelope_version=1,
            actions=[],
            resource_scopes=[],
            max_authorized_data_sensitivity=max_sensitivity,
            rate_ceilings=[],
            requires_human_approval_for=requires_human_approval_for or set(),
            approved_by=None,
            effective_from=now,
            effective_until=None,
            version=1,
        )
        env._emit(
            AgentOperationalEnvelopeDrafted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(envelope_id),
                aggregate_type="AgentOperationalEnvelope",
                ai_system_asset_id=str(ai_system_asset_id),
                envelope_version=1,
            )
        )
        return env

    def add_action(
        self,
        tenant_id: TenantId,
        category: AuthorizedActionCategory,
        description: str,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.actions.append(AuthorizedAction(AuthorizedActionId.generate(), category, description))
        self._version += 1

    def add_resource_scope(self, tenant_id: TenantId, scope: AuthorizedResourceScope) -> None:
        self._assert_tenant(tenant_id)
        self.resource_scopes.append(scope)
        self._version += 1

    def approve(self, tenant_id: TenantId, approver_id: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not self.actions:
            raise EnvelopeActivationRequirements(
                "Active envelope requires at least one AuthorizedAction"
            )
        self.approved_by = EnvelopeApprovedBy(approver_id, now)
        self._transition(EnvelopeState.ACTIVE)
        self.effective_from = now
        self.effective_until = None
        self._version += 1
        self._emit(
            AgentOperationalEnvelopeApproved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.envelope_id),
                aggregate_type="AgentOperationalEnvelope",
                approver_id=approver_id,
                envelope_version=self.envelope_version,
            )
        )

    def revise(
        self,
        tenant_id: TenantId,
        now: datetime,
        *,
        new_actions: list[tuple[AuthorizedActionCategory, str]] | None = None,
        remove_human_approval: set[AuthorizedActionCategory] | None = None,
        actor_is_admin: bool = False,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {EnvelopeState.ACTIVE, EnvelopeState.UNDER_REVISION}:
            raise InvalidEnvelopeTransition(self.state.value, EnvelopeState.UNDER_REVISION.value)
        if remove_human_approval:
            if not actor_is_admin:
                raise HumanApprovalCategoryLocked()
            self.requires_human_approval_for -= remove_human_approval
        previous = self.envelope_version
        if self.state == EnvelopeState.ACTIVE:
            self._transition(EnvelopeState.UNDER_REVISION)
        if new_actions:
            self.actions = [
                AuthorizedAction(AuthorizedActionId.generate(), cat, desc)
                for cat, desc in new_actions
            ]
        self.envelope_version += 1
        self.effective_from = now
        self._version += 1
        self._emit(
            AgentOperationalEnvelopeRevised(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.envelope_id),
                aggregate_type="AgentOperationalEnvelope",
                previous_version=previous,
                new_version=self.envelope_version,
            )
        )

    def reactivate_after_revision(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not self.actions or self.approved_by is None:
            raise EnvelopeActivationRequirements(
                "Active envelope requires AuthorizedAction and EnvelopeApprovedBy"
            )
        self._transition(EnvelopeState.ACTIVE)
        self._version += 1

    def suspend(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(EnvelopeState.SUSPENDED)
        self._version += 1
        self._emit(
            AgentOperationalEnvelopeSuspended(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.envelope_id),
                aggregate_type="AgentOperationalEnvelope",
                reason=reason,
            )
        )

    def retire(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(EnvelopeState.RETIRED)
        self.effective_until = now
        self._version += 1
        self._emit(
            AgentOperationalEnvelopeRetired(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.envelope_id),
                aggregate_type="AgentOperationalEnvelope",
                reason=reason,
            )
        )

    def is_effective_at(self, at: datetime) -> bool:
        if at < self.effective_from:
            return False
        if self.effective_until is not None and at >= self.effective_until:
            return False
        return self.state in {
            EnvelopeState.ACTIVE,
            EnvelopeState.UNDER_REVISION,
            EnvelopeState.SUSPENDED,
        }
