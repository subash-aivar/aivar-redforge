"""Commands for RedTeamOperator lifecycle and membership."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class ActivateOperatorCommand:
    tenant_id: UUID
    identity_ref: str
    clearance_level: str
    display_name: str | None = None
    certifications: list[str] = field(default_factory=list)
    approval_scopes: list[str] = field(default_factory=list)
    operator_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class SuspendOperatorCommand:
    tenant_id: UUID
    operator_id: UUID
    reason: str
    authority: str


@dataclass(frozen=True, slots=True)
class RevokeOperatorCommand:
    tenant_id: UUID
    operator_id: UUID
    reason: str
    authority: str


@dataclass(frozen=True, slots=True)
class ChangeOperatorClearanceCommand:
    tenant_id: UUID
    operator_id: UUID
    new_level: str
    authority: str


@dataclass(frozen=True, slots=True)
class AddOperatorToEngagementCommand:
    tenant_id: UUID
    operator_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class RemoveOperatorFromEngagementCommand:
    tenant_id: UUID
    operator_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class GrantApprovalAuthorityCommand:
    tenant_id: UUID
    operator_id: UUID
    scope: str


@dataclass(frozen=True, slots=True)
class RevokeApprovalAuthorityCommand:
    tenant_id: UUID
    operator_id: UUID
    scope: str
