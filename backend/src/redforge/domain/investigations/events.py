"""Domain events for the Investigation bounded context — M21.

Domain events are collected by the aggregate root and dispatched by the
application service — never triggered directly by infrastructure code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.investigations.value_objects import (
    CaseEventType,
    CorrelationConfidence,
    InvestigationSeverity,
    InvestigationStatus,
    ResolutionReason,
    SourceDomain,
)


@dataclass(frozen=True, slots=True)
class InvestigationCaseOpened:
    """Fired when the correlation engine creates a new investigation case."""

    case_id: str
    organization_id: str
    title: str
    severity: InvestigationSeverity
    confidence: CorrelationConfidence
    correlation_key: str
    source_domains: tuple[SourceDomain, ...]
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.CASE_OPENED


@dataclass(frozen=True, slots=True)
class EvidenceAttached:
    """Fired when a new piece of source-domain evidence is linked."""

    case_id: str
    organization_id: str
    evidence_id: str
    source_domain: SourceDomain
    source_entity_id: str
    severity: InvestigationSeverity
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.EVIDENCE_ATTACHED


@dataclass(frozen=True, slots=True)
class SeverityEscalated:
    """Fired when case severity increases due to new evidence."""

    case_id: str
    organization_id: str
    old_severity: InvestigationSeverity
    new_severity: InvestigationSeverity
    reason: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.SEVERITY_ESCALATED


@dataclass(frozen=True, slots=True)
class ConfidenceIncreased:
    """Fired when case confidence increases due to new corroboration."""

    case_id: str
    organization_id: str
    old_confidence: CorrelationConfidence
    new_confidence: CorrelationConfidence
    reason: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.CONFIDENCE_INCREASED


@dataclass(frozen=True, slots=True)
class CaseAcknowledged:
    """Fired when an analyst acknowledges an investigation."""

    case_id: str
    organization_id: str
    actor_user_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.CASE_ACKNOWLEDGED


@dataclass(frozen=True, slots=True)
class InvestigationStarted:
    """Fired when an analyst moves a case to active investigation."""

    case_id: str
    organization_id: str
    actor_user_id: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.INVESTIGATION_STARTED


@dataclass(frozen=True, slots=True)
class CaseResolved:
    """Fired when an analyst resolves the investigation."""

    case_id: str
    organization_id: str
    actor_user_id: str
    resolution_reason: ResolutionReason
    notes: str
    final_status: InvestigationStatus = InvestigationStatus.RESOLVED
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.CASE_RESOLVED


@dataclass(frozen=True, slots=True)
class CaseReopened:
    """Fired when new evidence causes a resolved case to reopen."""

    case_id: str
    organization_id: str
    trigger_evidence_id: str
    trigger_source_domain: SourceDomain
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.CASE_REOPENED


@dataclass(frozen=True, slots=True)
class DomainJoined:
    """Fired when a new source domain contributes to an existing case."""

    case_id: str
    organization_id: str
    new_domain: SourceDomain
    total_domain_count: int
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    event_type: CaseEventType = CaseEventType.DOMAIN_JOINED


InvestigationDomainEvent = (
    InvestigationCaseOpened
    | EvidenceAttached
    | SeverityEscalated
    | ConfidenceIncreased
    | CaseAcknowledged
    | InvestigationStarted
    | CaseResolved
    | CaseReopened
    | DomainJoined
)
