from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from automated_action.domain.value_objects.enums import ActionImpactLevel, EscalationResolution


@dataclass
class EscalationRequest:
    escalation_id: UUID
    step_number: int
    impact_level: ActionImpactLevel
    required_role: str
    trigger_operator_id: str
    escalated_at: datetime
    expires_at: datetime
    authorized_by: str | None = None
    authorized_at: datetime | None = None
    resolution: EscalationResolution | None = None

    @classmethod
    def create(
        cls,
        step_number: int,
        impact_level: ActionImpactLevel,
        required_role: str,
        trigger_operator_id: str,
        escalated_at: datetime,
        expires_at: datetime,
    ) -> EscalationRequest:
        return cls(
            uuid4(),
            step_number,
            impact_level,
            required_role,
            trigger_operator_id,
            escalated_at,
            expires_at,
        )
