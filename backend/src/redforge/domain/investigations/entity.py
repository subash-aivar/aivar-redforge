"""Investigation aggregate root — M21.

InvestigationCase is the central aggregate for cross-domain correlation.
All state transitions go through explicit domain methods.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from redforge.domain.investigations.events import (
    CaseAcknowledged,
    CaseReopened,
    CaseResolved,
    ConfidenceIncreased,
    DomainJoined,
    EvidenceAttached,
    InvestigationCaseOpened,
    InvestigationDomainEvent,
    InvestigationStarted,
    SeverityEscalated,
)
from redforge.domain.investigations.exceptions import (
    InvalidStatusTransitionError,
)
from redforge.domain.investigations.value_objects import (
    _CONFIDENCE_ORDER,
    _SEVERITY_ORDER,
    ACTIVE_STATUSES,
    CorrelationConfidence,
    InvestigationSeverity,
    InvestigationStatus,
    NormalizedEntity,
    ResolutionReason,
    SourceDomain,
    max_confidence,
    max_severity,
)


class InvestigationCase:
    """Cross-domain security investigation aggregate root.

    Invariants:
    - Status transitions are explicit and follow the defined lifecycle.
    - Severity only increases when new evidence is attached (monotonic).
    - Confidence only increases, never decreases due to new evidence.
    - Version column enables optimistic concurrency.
    - Cross-tenant evidence never joins this case.
    - All mutations produce domain events.
    """

    __slots__ = (
        "_acknowledged_at",
        "_confidence",
        "_correlation_key",
        "_created_at",
        "_events",
        "_evidence_count",
        "_first_observed_at",
        "_id",
        "_investigating_at",
        "_involved_entities",
        "_last_observed_at",
        "_opened_at",
        "_organization_id",
        "_resolution_notes",
        "_resolution_reason",
        "_resolved_at",
        "_severity",
        "_source_domains",
        "_status",
        "_summary",
        "_title",
        "_updated_at",
        "_version",
    )

    def __init__(
        self,
        *,
        id: str,
        organization_id: str,
        title: str,
        summary: str,
        status: InvestigationStatus,
        severity: InvestigationSeverity,
        confidence: CorrelationConfidence,
        correlation_key: str,
        source_domains: frozenset[SourceDomain],
        involved_entities: frozenset[NormalizedEntity],
        evidence_count: int,
        first_observed_at: datetime,
        last_observed_at: datetime,
        opened_at: datetime,
        acknowledged_at: datetime | None,
        investigating_at: datetime | None,
        resolved_at: datetime | None,
        resolution_reason: ResolutionReason | None,
        resolution_notes: str,
        version: int,
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._title = title
        self._summary = summary
        self._status = status
        self._severity = severity
        self._confidence = confidence
        self._correlation_key = correlation_key
        self._source_domains = source_domains
        self._involved_entities = involved_entities
        self._evidence_count = evidence_count
        self._first_observed_at = first_observed_at
        self._last_observed_at = last_observed_at
        self._opened_at = opened_at
        self._acknowledged_at = acknowledged_at
        self._investigating_at = investigating_at
        self._resolved_at = resolved_at
        self._resolution_reason = resolution_reason
        self._resolution_notes = resolution_notes
        self._version = version
        self._created_at = created_at
        self._updated_at = updated_at
        self._events: list[InvestigationDomainEvent] = []

    # ── Read accessors ────────────────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def title(self) -> str:
        return self._title

    @property
    def summary(self) -> str:
        return self._summary

    @property
    def status(self) -> InvestigationStatus:
        return self._status

    @property
    def severity(self) -> InvestigationSeverity:
        return self._severity

    @property
    def confidence(self) -> CorrelationConfidence:
        return self._confidence

    @property
    def correlation_key(self) -> str:
        return self._correlation_key

    @property
    def source_domains(self) -> frozenset[SourceDomain]:
        return self._source_domains

    @property
    def involved_entities(self) -> frozenset[NormalizedEntity]:
        return self._involved_entities

    @property
    def evidence_count(self) -> int:
        return self._evidence_count

    @property
    def first_observed_at(self) -> datetime:
        return self._first_observed_at

    @property
    def last_observed_at(self) -> datetime:
        return self._last_observed_at

    @property
    def opened_at(self) -> datetime:
        return self._opened_at

    @property
    def acknowledged_at(self) -> datetime | None:
        return self._acknowledged_at

    @property
    def investigating_at(self) -> datetime | None:
        return self._investigating_at

    @property
    def resolved_at(self) -> datetime | None:
        return self._resolved_at

    @property
    def resolution_reason(self) -> ResolutionReason | None:
        return self._resolution_reason

    @property
    def resolution_notes(self) -> str:
        return self._resolution_notes

    @property
    def version(self) -> int:
        return self._version

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    @property
    def is_active(self) -> bool:
        return self._status in ACTIVE_STATUSES

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def open(
        cls,
        *,
        id: str,
        organization_id: str,
        title: str,
        summary: str,
        severity: InvestigationSeverity,
        confidence: CorrelationConfidence,
        correlation_key: str,
        source_domains: frozenset[SourceDomain],
        involved_entities: frozenset[NormalizedEntity],
        first_observed_at: datetime,
        now: datetime | None = None,
    ) -> InvestigationCase:
        """Open a new investigation case.

        Only the correlation engine should call this. Source domain logic
        never opens cases directly.
        """
        now = now or datetime.now(UTC)
        case = cls(
            id=id,
            organization_id=organization_id,
            title=title,
            summary=summary,
            status=InvestigationStatus.OPEN,
            severity=severity,
            confidence=confidence,
            correlation_key=correlation_key,
            source_domains=source_domains,
            involved_entities=involved_entities,
            evidence_count=0,
            first_observed_at=first_observed_at,
            last_observed_at=first_observed_at,
            opened_at=now,
            acknowledged_at=None,
            investigating_at=None,
            resolved_at=None,
            resolution_reason=None,
            resolution_notes="",
            version=0,
            created_at=now,
            updated_at=now,
        )
        case._events.append(
            InvestigationCaseOpened(
                case_id=id,
                organization_id=organization_id,
                title=title,
                severity=severity,
                confidence=confidence,
                correlation_key=correlation_key,
                source_domains=tuple(source_domains),
                occurred_at=now,
            )
        )
        return case

    # ── Evidence attachment ───────────────────────────────────────────────────

    def attach_evidence(
        self,
        *,
        evidence_id: str,
        source_domain: SourceDomain,
        source_entity_id: str,
        new_severity: InvestigationSeverity,
        new_confidence: CorrelationConfidence,
        new_entities: frozenset[NormalizedEntity],
        observed_at: datetime,
        now: datetime | None = None,
    ) -> None:
        """Attach source-domain evidence to this case.

        Severity and confidence only increase (monotonic). New entities
        are union-merged into the case's entity set.
        """
        now = now or datetime.now(UTC)

        # Severity monotonically increases
        old_severity = self._severity
        updated_severity = max_severity(self._severity, new_severity)

        # Confidence monotonically increases
        old_confidence = self._confidence
        updated_confidence = max_confidence(self._confidence, new_confidence)

        self._evidence_count += 1
        self._last_observed_at = max(self._last_observed_at, observed_at)
        self._updated_at = now

        # Merge entities
        len(self._involved_entities)
        self._involved_entities = self._involved_entities | new_entities

        # Track new domain participation
        is_new_domain = source_domain not in self._source_domains
        if is_new_domain:
            self._source_domains = self._source_domains | {source_domain}
            self._events.append(
                DomainJoined(
                    case_id=self._id,
                    organization_id=self._organization_id,
                    new_domain=source_domain,
                    total_domain_count=len(self._source_domains),
                    occurred_at=now,
                )
            )

        self._events.append(
            EvidenceAttached(
                case_id=self._id,
                organization_id=self._organization_id,
                evidence_id=evidence_id,
                source_domain=source_domain,
                source_entity_id=source_entity_id,
                severity=new_severity,
                occurred_at=now,
            )
        )

        if _SEVERITY_ORDER[updated_severity] > _SEVERITY_ORDER[old_severity]:
            self._severity = updated_severity
            self._events.append(
                SeverityEscalated(
                    case_id=self._id,
                    organization_id=self._organization_id,
                    old_severity=old_severity,
                    new_severity=updated_severity,
                    reason=f"New {source_domain.value} evidence with severity {new_severity.value}",
                    occurred_at=now,
                )
            )

        if _CONFIDENCE_ORDER[updated_confidence] > _CONFIDENCE_ORDER[old_confidence]:
            self._confidence = updated_confidence
            self._events.append(
                ConfidenceIncreased(
                    case_id=self._id,
                    organization_id=self._organization_id,
                    old_confidence=old_confidence,
                    new_confidence=updated_confidence,
                    reason=f"New {source_domain.value} evidence corroborates the investigation",
                    occurred_at=now,
                )
            )

    # ── Lifecycle transitions ─────────────────────────────────────────────────

    def acknowledge(self, *, actor_user_id: str, now: datetime | None = None) -> None:
        """Analyst acknowledges the investigation."""
        now = now or datetime.now(UTC)
        if self._status not in (InvestigationStatus.OPEN,):
            raise InvalidStatusTransitionError(
                f"Cannot acknowledge investigation in status {self._status!r}. "
                "Only OPEN cases can be acknowledged."
            )
        self._status = InvestigationStatus.ACKNOWLEDGED
        self._acknowledged_at = now
        self._updated_at = now
        self._events.append(
            CaseAcknowledged(
                case_id=self._id,
                organization_id=self._organization_id,
                actor_user_id=actor_user_id,
                occurred_at=now,
            )
        )

    def start_investigation(
        self, *, actor_user_id: str, now: datetime | None = None
    ) -> None:
        """Analyst moves the case into active investigation."""
        now = now or datetime.now(UTC)
        if self._status not in (
            InvestigationStatus.OPEN,
            InvestigationStatus.ACKNOWLEDGED,
        ):
            raise InvalidStatusTransitionError(
                f"Cannot start investigation in status {self._status!r}. "
                "Only OPEN or ACKNOWLEDGED cases can be moved to INVESTIGATING."
            )
        self._status = InvestigationStatus.INVESTIGATING
        self._investigating_at = now
        self._updated_at = now
        self._events.append(
            InvestigationStarted(
                case_id=self._id,
                organization_id=self._organization_id,
                actor_user_id=actor_user_id,
                occurred_at=now,
            )
        )

    def resolve(
        self,
        *,
        actor_user_id: str,
        resolution_reason: ResolutionReason,
        notes: str,
        now: datetime | None = None,
    ) -> None:
        """Analyst resolves the investigation."""
        now = now or datetime.now(UTC)
        if self._status not in ACTIVE_STATUSES:
            raise InvalidStatusTransitionError(
                f"Cannot resolve investigation in status {self._status!r}. "
                "Only active cases can be resolved."
            )
        self._status = InvestigationStatus.RESOLVED
        self._resolved_at = now
        self._resolution_reason = resolution_reason
        self._resolution_notes = notes
        self._updated_at = now
        self._events.append(
            CaseResolved(
                case_id=self._id,
                organization_id=self._organization_id,
                actor_user_id=actor_user_id,
                resolution_reason=resolution_reason,
                notes=notes,
                occurred_at=now,
            )
        )

    def reopen(
        self,
        *,
        trigger_evidence_id: str,
        trigger_source_domain: SourceDomain,
        now: datetime | None = None,
    ) -> None:
        """Reopen a resolved investigation due to new related evidence.

        Only valid if the case is RESOLVED and the evidence arrives within
        the reopen window. The caller is responsible for checking the window.
        """
        now = now or datetime.now(UTC)
        if self._status != InvestigationStatus.RESOLVED:
            raise InvalidStatusTransitionError(
                f"Cannot reopen investigation in status {self._status!r}. "
                "Only RESOLVED cases can be reopened."
            )
        self._status = InvestigationStatus.OPEN
        self._resolved_at = None
        self._resolution_reason = None
        self._resolution_notes = ""
        self._updated_at = now
        self._events.append(
            CaseReopened(
                case_id=self._id,
                organization_id=self._organization_id,
                trigger_evidence_id=trigger_evidence_id,
                trigger_source_domain=trigger_source_domain,
                occurred_at=now,
            )
        )

    # ── Domain events ─────────────────────────────────────────────────────────

    def collect_events(self) -> list[InvestigationDomainEvent]:
        """Return and clear pending domain events."""
        events = list(self._events)
        self._events.clear()
        return events

    # ── Snapshot ──────────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Snapshot for API responses. Immutable projection."""
        return {
            "id": self._id,
            "organization_id": self._organization_id,
            "title": self._title,
            "summary": self._summary,
            "status": self._status.value,
            "severity": self._severity.value,
            "confidence": self._confidence.value,
            "correlation_key": self._correlation_key,
            "source_domains": sorted(d.value for d in self._source_domains),
            "involved_entity_count": len(self._involved_entities),
            "involved_entities": [
                {"type": e.entity_type.value, "id": e.entity_id}
                for e in sorted(self._involved_entities, key=str)
            ],
            "evidence_count": self._evidence_count,
            "first_observed_at": self._first_observed_at.isoformat(),
            "last_observed_at": self._last_observed_at.isoformat(),
            "opened_at": self._opened_at.isoformat(),
            "acknowledged_at": (
                self._acknowledged_at.isoformat() if self._acknowledged_at else None
            ),
            "investigating_at": (
                self._investigating_at.isoformat() if self._investigating_at else None
            ),
            "resolved_at": (
                self._resolved_at.isoformat() if self._resolved_at else None
            ),
            "resolution_reason": (
                self._resolution_reason.value if self._resolution_reason else None
            ),
            "resolution_notes": self._resolution_notes,
            "version": self._version,
            "created_at": self._created_at.isoformat(),
            "updated_at": self._updated_at.isoformat(),
        }
