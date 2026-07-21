"""EnvelopeComplianceEvaluationService — pure evaluation against pinned envelope version."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent_governance.domain.aggregates.agent_deviation_event import AgentDeviationEvent
from ai_agent_governance.domain.value_objects.enums import (
    DeviationSeverity,
    DeviationType,
    EnvelopeState,
    sensitivity_exceeds,
)
from ai_agent_governance.domain.value_objects.governance_vos import (
    AgentOperationalEnvelopeRef,
)
from ai_agent_governance.domain.value_objects.identifiers import AgentDeviationEventId

if TYPE_CHECKING:
    from datetime import datetime

    from ai_agent_governance.domain.aggregates.agent_operational_envelope import (
        AgentOperationalEnvelope,
    )
    from ai_agent_governance.domain.value_objects.governance_vos import ObservedAction
    from ai_agent_governance.domain.value_objects.identifiers import TenantId


class EnvelopeComplianceEvaluationService:
    def evaluate(
        self,
        envelope: AgentOperationalEnvelope,
        action: ObservedAction,
        tenant_id: TenantId,
        now: datetime,
    ) -> AgentDeviationEvent | None:
        """Evaluate against the envelope version active at action.occurred_at (caller pins)."""
        if envelope.state == EnvelopeState.SUSPENDED:
            return AgentDeviationEvent.detect(
                AgentDeviationEventId.generate(),
                tenant_id,
                AgentOperationalEnvelopeRef(envelope.envelope_id, envelope.envelope_version),
                envelope.ai_system_asset_id,
                DeviationType.UNAUTHORIZED_ACTION_CATEGORY,
                action,
                DeviationSeverity.CRITICAL,
                now,
            )
        allowed_categories = {a.category for a in envelope.actions}
        if action.action_category not in allowed_categories:
            return AgentDeviationEvent.detect(
                AgentDeviationEventId.generate(),
                tenant_id,
                AgentOperationalEnvelopeRef(envelope.envelope_id, envelope.envelope_version),
                envelope.ai_system_asset_id,
                DeviationType.UNAUTHORIZED_ACTION_CATEGORY,
                action,
                DeviationSeverity.HIGH,
                now,
            )
        if (
            action.action_category in envelope.requires_human_approval_for
            and not action.human_approval_present
        ):
            return AgentDeviationEvent.detect(
                AgentDeviationEventId.generate(),
                tenant_id,
                AgentOperationalEnvelopeRef(envelope.envelope_id, envelope.envelope_version),
                envelope.ai_system_asset_id,
                DeviationType.REQUIRED_APPROVAL_BYPASSED,
                action,
                DeviationSeverity.HIGH,
                now,
            )
        if sensitivity_exceeds(action.data_sensitivity, envelope.max_authorized_data_sensitivity):
            return AgentDeviationEvent.detect(
                AgentDeviationEventId.generate(),
                tenant_id,
                AgentOperationalEnvelopeRef(envelope.envelope_id, envelope.envelope_version),
                envelope.ai_system_asset_id,
                DeviationType.DATA_SENSITIVITY_EXCEEDED,
                action,
                DeviationSeverity.MEDIUM,
                now,
            )
        if envelope.resource_scopes and not any(
            self._resource_matches(action.resource, s.resource_pattern)
            for s in envelope.resource_scopes
        ):
            return AgentDeviationEvent.detect(
                AgentDeviationEventId.generate(),
                tenant_id,
                AgentOperationalEnvelopeRef(envelope.envelope_id, envelope.envelope_version),
                envelope.ai_system_asset_id,
                DeviationType.RESOURCE_SCOPE_VIOLATION,
                action,
                DeviationSeverity.MEDIUM,
                now,
            )
        return None

    @staticmethod
    def _resource_matches(resource: str, pattern: str) -> bool:
        if pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        return resource == pattern
