"""Owned entities within the Engagement aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from engagement.domain.value_objects.engagement_vos import (
        ApprovalRecord,
        RoeConstraint,
        TargetRef,
    )
    from engagement.domain.value_objects.identifiers import (
        EngagementApprovalId,
        EngagementParticipantId,
        EngagementPhaseId,
    )


@dataclass(slots=True)
class EngagementPhase:
    phase_id: EngagementPhaseId
    name: str
    description: str | None = None
    sort_order: int = 0


@dataclass(slots=True)
class RulesOfEngagement:
    version: int
    constraints: RoeConstraint
    signed_by: str | None = None
    signature: str | None = None
    signed_at: datetime | None = None

    @property
    def is_signed(self) -> bool:
        return bool(self.signed_by and self.signature and self.signed_at)


@dataclass(slots=True)
class EngagementApproval:
    approval_id: EngagementApprovalId
    record: ApprovalRecord
    revoked: bool = False
    revoked_at: datetime | None = None
    revoked_by: str | None = None


@dataclass(slots=True)
class EngagementParticipant:
    participant_id: EngagementParticipantId
    operator_id: str
    role: str
    added_at: datetime
    removed_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.removed_at is None


@dataclass(slots=True)
class TargetScope:
    """Authorized target manifest — immutable once engagement is Approved."""

    targets: list[TargetRef] = field(default_factory=list)

    def asset_ids(self) -> frozenset[UUID]:
        return frozenset(t.asset_id for t in self.targets)

    def contains(self, asset_id: UUID) -> bool:
        return asset_id in self.asset_ids()
