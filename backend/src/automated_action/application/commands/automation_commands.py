from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from automated_action.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class TriggerPlaybookExecution:
    tenant_id: TenantId
    playbook_id: UUID
    version_number: int
    source_context: str
    source_event_type: str
    source_event_id: str
    operator_id: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizeAutomationStep:
    tenant_id: TenantId
    execution_id: UUID
    escalation_id: UUID
    authorizer_id: str
    authorizer_roles: tuple[str, ...]
    notes: str | None
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RequestRollback:
    tenant_id: TenantId
    execution_id: UUID
    record_id: UUID
    initiated_by: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CancelExecution:
    tenant_id: TenantId
    execution_id: UUID
    cancelled_by: str
    reason: str
    roles: tuple[str, ...]
