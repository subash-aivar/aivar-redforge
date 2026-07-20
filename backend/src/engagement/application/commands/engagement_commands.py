"""Commands for engagement lifecycle use cases."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CreateEngagementCommand:
    tenant_id: UUID
    name: str
    classification: str
    owner_id: str
    actor: str = "system"
    required_approver_count: int | None = None


@dataclass(frozen=True, slots=True)
class SubmitEngagementForApprovalCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class GrantEngagementApprovalCommand:
    tenant_id: UUID
    engagement_id: UUID
    approver_id: str
    signature: str | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ActivateEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class SuspendEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    reason: str
    authority: str
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ResumeEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    authority: str
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class CloseEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    reason: str | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ArchiveEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class DefineTargetScopeCommand:
    tenant_id: UUID
    engagement_id: UUID
    asset_ids: list[UUID]
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class SetRulesOfEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    allowed_techniques: list[str]
    forbidden_targets: list[str] = field(default_factory=list)
    rate_limits: dict[str, object] | None = None
    escalation_contacts: list[str] = field(default_factory=list)
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class SignRulesOfEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    owner_id: str
    signature: str | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class SetEngagementWindowCommand:
    tenant_id: UUID
    engagement_id: UUID
    authorized_start: datetime
    authorized_end: datetime
    operational_hours: dict[str, object] | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class AddParticipantCommand:
    tenant_id: UUID
    engagement_id: UUID
    operator_id: str
    role: str
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class RemoveParticipantCommand:
    tenant_id: UUID
    engagement_id: UUID
    operator_id: str
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class RequestScopeExpansionCommand:
    tenant_id: UUID
    engagement_id: UUID
    asset_ids: list[UUID]
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ApproveScopeExpansionCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class GrantTargetAuthorizationCommand:
    tenant_id: UUID
    engagement_id: UUID
    asset_id: UUID
    technique_ids: list[str]
    impact_ceiling: str
    max_execution_count: int
    valid_until: datetime
    granted_by: str
    destruct_approval_granted: bool = False
    phase_id: UUID | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class RevokeTargetAuthorizationCommand:
    tenant_id: UUID
    authorization_id: UUID
    reason: str
    revoked_by: str
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class SuspendTargetAuthorizationCommand:
    tenant_id: UUID
    authorization_id: UUID
    reason: str
    actor: str = "system"
