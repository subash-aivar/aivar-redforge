"""Frozen domain events for incident BC."""

from __future__ import annotations

from dataclasses import dataclass

from incident.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class IncidentDeclared(BaseDomainEvent):
    incident_id: str = ""
    trigger_type: str = ""
    severity: str = ""
    declared_at: str = ""


@dataclass(frozen=True, slots=True)
class IncidentClassified(BaseDomainEvent):
    incident_id: str = ""
    severity: str = ""
    classified_at: str = ""
    classification_method: str = ""
    trigger_type: str = ""
    source_finding_ref: str | None = None
    source_investigation_ref: str | None = None


@dataclass(frozen=True, slots=True)
class IncidentReclassified(BaseDomainEvent):
    incident_id: str = ""
    old_severity: str = ""
    new_severity: str = ""
    justification: str = ""
    reclassified_by: str = ""
    reclassified_at: str = ""


@dataclass(frozen=True, slots=True)
class IncidentContained(BaseDomainEvent):
    incident_id: str = ""
    contained_at: str = ""


@dataclass(frozen=True, slots=True)
class IncidentEradicated(BaseDomainEvent):
    incident_id: str = ""
    eradicated_at: str = ""


@dataclass(frozen=True, slots=True)
class IncidentRecovered(BaseDomainEvent):
    incident_id: str = ""
    recovered_at: str = ""


@dataclass(frozen=True, slots=True)
class IncidentClosed(BaseDomainEvent):
    incident_id: str = ""
    closed_at: str = ""
    resolution_type: str = ""
    classified_at: str = ""
    incident_duration_hours: float = 0.0


@dataclass(frozen=True, slots=True)
class IncidentTimelineUpdated(BaseDomainEvent):
    incident_id: str = ""
    entry_type: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentActionPendingAuthorization(BaseDomainEvent):
    action_id: str = ""
    incident_id: str = ""
    action_type: str = ""
    authorization_level_required: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentActionAuthorized(BaseDomainEvent):
    action_id: str = ""
    incident_id: str = ""
    authorized_by: str = ""
    authorized_at: str = ""
    action_type: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentActionCompleted(BaseDomainEvent):
    action_id: str = ""
    incident_id: str = ""
    completed_at: str = ""
    evidence_ref: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentActionFailed(BaseDomainEvent):
    action_id: str = ""
    incident_id: str = ""
    failure_reason: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentAuthorized(BaseDomainEvent):
    """Alias event name for mission checklist."""

    action_id: str = ""
    incident_id: str = ""
    authorized_by: str = ""


@dataclass(frozen=True, slots=True)
class ContainmentCompleted(BaseDomainEvent):
    action_id: str = ""
    incident_id: str = ""


@dataclass(frozen=True, slots=True)
class EradicationVerificationSubmitted(BaseDomainEvent):
    verification_id: str = ""
    incident_id: str = ""
    submitted_by: str = ""
    submitted_at: str = ""


@dataclass(frozen=True, slots=True)
class EradicationVerificationVerified(BaseDomainEvent):
    verification_id: str = ""
    incident_id: str = ""
    verified_by: str = ""
    verified_at: str = ""


@dataclass(frozen=True, slots=True)
class EradicationVerified(BaseDomainEvent):
    verification_id: str = ""
    incident_id: str = ""


@dataclass(frozen=True, slots=True)
class EradicationVerificationDisputed(BaseDomainEvent):
    verification_id: str = ""
    incident_id: str = ""
    dispute_reason: str = ""


@dataclass(frozen=True, slots=True)
class RecoveryMilestoneCompleted(BaseDomainEvent):
    milestone_id: str = ""
    incident_id: str = ""
    completed_at: str = ""


@dataclass(frozen=True, slots=True)
class RecoveryCompleted(BaseDomainEvent):
    incident_id: str = ""
    recovered_at: str = ""
