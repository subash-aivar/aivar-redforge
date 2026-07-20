"""DTOs for RedTeamOperator API responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator


@dataclass(frozen=True, slots=True)
class OperatorDTO:
    operator_id: UUID
    tenant_id: UUID
    identity_ref: str
    display_name: str
    clearance_level: str
    max_impact_ceiling: str
    state: str
    certifications: list[str]
    approval_scopes: list[str]
    active_engagement_ids: list[UUID]
    status_reason: str | None
    status_authority: str | None
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_aggregate(cls, op: RedTeamOperator) -> OperatorDTO:
        return cls(
            operator_id=op.operator_id.value,
            tenant_id=op.tenant_id.value,
            identity_ref=op.identity_ref,
            display_name=op.display_name,
            clearance_level=op.clearance_level.value,
            max_impact_ceiling=op.max_impact_ceiling.value,
            state=op.state.value,
            certifications=list(op.certifications.categories),
            approval_scopes=[s.value for s in op.approval_authority.scopes],
            active_engagement_ids=list(op.active_engagements.engagement_ids),
            status_reason=op.status_reason,
            status_authority=op.status_authority,
            created_at=op.created_at,
            updated_at=op.updated_at,
            version=op.version,
        )
