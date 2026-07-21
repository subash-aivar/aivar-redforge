from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class DeclareIncidentCommand:
    tenant_id: UUID
    title: str
    description: str
    trigger_type: str
    severity: str
    actor: str
    roles: tuple[str, ...]
    source_finding_id: str | None = None
    investigation_id: str | None = None


@dataclass(frozen=True, slots=True)
class ClassifyIncidentCommand:
    tenant_id: UUID
    incident_id: UUID
    severity: str
    method: str
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReclassifyIncidentCommand:
    tenant_id: UUID
    incident_id: UUID
    new_severity: str
    justification: str
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizeContainmentCommand:
    tenant_id: UUID
    incident_id: UUID
    action_type: str
    description: str
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompleteContainmentCommand:
    tenant_id: UUID
    action_id: UUID
    evidence_ref: str
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FailContainmentCommand:
    tenant_id: UUID
    action_id: UUID
    failure_reason: str
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SubmitEradicationCommand:
    tenant_id: UUID
    incident_id: UUID
    assertion: str
    evidence_ids: tuple[str, ...]
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifyEradicationCommand:
    tenant_id: UUID
    incident_id: UUID
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CloseIncidentCommand:
    tenant_id: UUID
    incident_id: UUID
    resolution_type: str
    actor: str
    roles: tuple[str, ...]
    force: bool = False
    force_justification: str | None = None


@dataclass(frozen=True, slots=True)
class AddRecoveryMilestoneCommand:
    tenant_id: UUID
    incident_id: UUID
    title: str
    description: str
    owner: str
    target_date: datetime
    actor: str
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CompleteRecoveryMilestoneCommand:
    tenant_id: UUID
    incident_id: UUID
    milestone_id: UUID
    notes: str
    actor: str
    roles: tuple[str, ...]
    mark_incident_recovered: bool = False


@dataclass(frozen=True, slots=True)
class LogCommunicationCommand:
    tenant_id: UUID
    incident_id: UUID
    content: str
    communication_type: str
    recipient_summary: str
    actor: str
    roles: tuple[str, ...]
