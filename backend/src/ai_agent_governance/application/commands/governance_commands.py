from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ai_agent_governance.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class DraftEnvelopeCommand:
    tenant_id: TenantId
    asset_id: UUID
    max_data_sensitivity: str
    requires_human_approval_for: tuple[str, ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AddAuthorizedActionCommand:
    tenant_id: TenantId
    envelope_id: UUID
    category: str
    description: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApproveEnvelopeCommand:
    tenant_id: TenantId
    envelope_id: UUID
    approver_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviseEnvelopeCommand:
    tenant_id: TenantId
    envelope_id: UUID
    new_actions: tuple[tuple[str, str], ...] = ()
    remove_human_approval_for: tuple[str, ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SuspendEnvelopeCommand:
    tenant_id: TenantId
    envelope_id: UUID
    reason: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RetireEnvelopeCommand:
    tenant_id: TenantId
    envelope_id: UUID
    reason: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReportAgentActionCommand:
    tenant_id: TenantId
    asset_id: UUID
    action_category: str
    resource: str
    data_sensitivity: str
    human_approval_present: bool
    occurred_at: datetime
    idempotency_key: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewDeviationCommand:
    tenant_id: TenantId
    deviation_id: UUID
    decision: str  # confirm | benign | envelope_updated
    notes: str = ""
    linked_revision_event_id: str = ""
    actor_roles: tuple[str, ...] = ()
