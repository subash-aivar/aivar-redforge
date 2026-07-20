"""DTOs for engagement application layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class TargetRefDTO:
    asset_id: UUID
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class ApprovalDTO:
    approval_id: UUID
    approver_id: str
    timestamp: datetime
    signature: str
    approval_scope: str
    revoked: bool


@dataclass(frozen=True, slots=True)
class ParticipantDTO:
    participant_id: UUID
    operator_id: str
    role: str
    added_at: datetime
    removed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PhaseDTO:
    phase_id: UUID
    name: str
    description: str | None
    sort_order: int


@dataclass(frozen=True, slots=True)
class EngagementDTO:
    engagement_id: UUID
    tenant_id: UUID
    name: str
    classification: str
    owner_id: str
    state: str
    kill_switch_state: str
    engagement_version: int
    scope_hash: str | None
    row_version: int
    created_at: datetime
    updated_at: datetime
    authorized_start: datetime | None = None
    authorized_end: datetime | None = None
    operational_hours: dict[str, Any] = field(default_factory=dict)
    objectives_summary: str | None = None
    allowed_techniques: list[str] = field(default_factory=list)
    targets: list[TargetRefDTO] = field(default_factory=list)
    approvals: list[ApprovalDTO] = field(default_factory=list)
    participants: list[ParticipantDTO] = field(default_factory=list)
    phases: list[PhaseDTO] = field(default_factory=list)
    required_approver_count: int = 1
    quorum_type: str = "Majority"
    roe_version: int | None = None
    roe_signed: bool = False


@dataclass(frozen=True, slots=True)
class TargetAuthorizationDTO:
    authorization_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    asset_id: UUID
    display_name: str | None
    technique_ids: list[str]
    impact_ceiling: str
    max_execution_count: int
    state: str
    granted_by: str
    valid_until: datetime
    destruct_approval_granted: bool
    phase_id: UUID | None
    row_version: int
    created_at: datetime
    updated_at: datetime
