"""Finding aggregate root.

A Finding is a derived security assessment generated from one or more
Evidence records. It is NOT the source of truth — Evidence is.

Key principles:
- Findings reference Evidence by ID only (never embed).
- Findings can always be regenerated from Evidence.
- Deleting a Finding never deletes Evidence.
- Evidence can exist without Findings.
"""

from typing import Self

from redforge.domain.findings.events import (
    FindingClosed,
    FindingCreated,
    FindingEvent,
    FindingReopened,
    FindingRiskAccepted,
    _now,
)
from redforge.domain.findings.exceptions import (
    FindingClosedError,
    InvalidFindingTransitionError,
)
from redforge.domain.findings.value_objects import (
    ComplianceReference,
    FindingStatus,
    MitreReference,
    OwaspReference,
    RiskScore,
    Severity,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class Finding:
    """Finding aggregate root.

    Invariants:
    - Always references at least one Evidence record.
    - Always belongs to an Organization, Target, and ValidationRun.
    - Status transitions follow defined rules.
    - Closed findings cannot be modified (except reopen).
    - Evidence references are IDs only — no embedding.
    """

    __slots__ = (
        "_compliance_refs",
        "_description",
        "_events",
        "_evidence_ids",
        "_id",
        "_mitre_refs",
        "_organization_id",
        "_owasp_refs",
        "_recommendation",
        "_risk_score",
        "_run_id",
        "_severity",
        "_status",
        "_target_id",
        "_timestamps",
        "_title",
    )

    def __init__(
        self,
        id: EntityId,
        organization_id: EntityId,
        run_id: EntityId,
        target_id: EntityId,
        evidence_ids: list[EntityId],
        title: str,
        description: str,
        severity: Severity,
        risk_score: RiskScore,
        status: FindingStatus,
        recommendation: str,
        compliance_refs: list[ComplianceReference],
        mitre_refs: list[MitreReference],
        owasp_refs: list[OwaspReference],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._run_id = run_id
        self._target_id = target_id
        self._evidence_ids = evidence_ids
        self._title = title
        self._description = description
        self._severity = severity
        self._risk_score = risk_score
        self._status = status
        self._recommendation = recommendation
        self._compliance_refs = compliance_refs
        self._mitre_refs = mitre_refs
        self._owasp_refs = owasp_refs
        self._timestamps = timestamps
        self._events: list[FindingEvent] = []

    @classmethod
    def create_from_evidence(
        cls,
        organization_id: EntityId,
        run_id: EntityId,
        target_id: EntityId,
        evidence_ids: list[EntityId],
        title: str,
        description: str,
        severity: Severity,
        risk_score: RiskScore,
        recommendation: str = "",
    ) -> Self:
        """Create a Finding derived from one or more Evidence records.

        Findings are always OPEN on creation.
        """
        if not evidence_ids:
            raise ValueError("A Finding must reference at least one Evidence record")
        if not title or len(title.strip()) < 5:
            raise ValueError("Finding title must be at least 5 characters")

        finding = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            run_id=run_id,
            target_id=target_id,
            evidence_ids=list(evidence_ids),
            title=title.strip(),
            description=description.strip(),
            severity=severity,
            risk_score=risk_score,
            status=FindingStatus.OPEN,
            recommendation=recommendation.strip(),
            compliance_refs=[],
            mitre_refs=[],
            owasp_refs=[],
            timestamps=AuditTimestamps.create(),
        )
        finding._record_event(
            FindingCreated(
                occurred_at=_now(),
                finding_id=str(finding._id),
                target_id=str(target_id),
                severity=str(severity),
                title=title.strip(),
            )
        )
        return finding

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def run_id(self) -> EntityId:
        return self._run_id

    @property
    def target_id(self) -> EntityId:
        return self._target_id

    @property
    def evidence_ids(self) -> tuple[EntityId, ...]:
        return tuple(self._evidence_ids)

    @property
    def title(self) -> str:
        return self._title

    @property
    def description(self) -> str:
        return self._description

    @property
    def severity(self) -> Severity:
        return self._severity

    @property
    def risk_score(self) -> RiskScore:
        return self._risk_score

    @property
    def status(self) -> FindingStatus:
        return self._status

    @property
    def recommendation(self) -> str:
        return self._recommendation

    @property
    def compliance_refs(self) -> tuple[ComplianceReference, ...]:
        return tuple(self._compliance_refs)

    @property
    def mitre_refs(self) -> tuple[MitreReference, ...]:
        return tuple(self._mitre_refs)

    @property
    def owasp_refs(self) -> tuple[OwaspReference, ...]:
        return tuple(self._owasp_refs)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_open(self) -> bool:
        return self._status in {FindingStatus.OPEN, FindingStatus.REOPENED}

    # ─── Behavior ─────────────────────────────────────────────────────────

    def accept_risk(self) -> None:
        """Accept the risk of this finding (acknowledged but not fixed).

        Transitions: OPEN/REOPENED → ACCEPTED
        """
        self._require_open()
        self._status = FindingStatus.ACCEPTED
        self._touch()
        self._record_event(
            FindingRiskAccepted(occurred_at=_now(), finding_id=str(self._id))
        )

    def close(self) -> None:
        """Close the finding (resolved or mitigated).

        Transitions: OPEN/REOPENED/ACCEPTED → CLOSED
        """
        if self._status == FindingStatus.CLOSED:
            raise InvalidFindingTransitionError(str(self._status), "closed")
        self._status = FindingStatus.CLOSED
        self._touch()
        self._record_event(
            FindingClosed(occurred_at=_now(), finding_id=str(self._id))
        )

    def reopen(self) -> None:
        """Reopen a previously closed or accepted finding.

        Transitions: CLOSED/ACCEPTED → REOPENED
        """
        if self._status not in {FindingStatus.CLOSED, FindingStatus.ACCEPTED}:
            raise InvalidFindingTransitionError(str(self._status), "reopened")
        self._status = FindingStatus.REOPENED
        self._touch()
        self._record_event(
            FindingReopened(occurred_at=_now(), finding_id=str(self._id))
        )

    def attach_recommendation(self, recommendation: str) -> None:
        """Set or update the remediation recommendation."""
        self._require_not_closed()
        self._recommendation = recommendation.strip()
        self._touch()

    def add_compliance_reference(self, ref: ComplianceReference) -> None:
        """Add a compliance framework reference."""
        self._require_not_closed()
        self._compliance_refs.append(ref)
        self._touch()

    def add_mitre_reference(self, ref: MitreReference) -> None:
        """Add a MITRE ATLAS technique reference."""
        self._require_not_closed()
        self._mitre_refs.append(ref)
        self._touch()

    def add_owasp_reference(self, ref: OwaspReference) -> None:
        """Add an OWASP LLM Top 10 reference."""
        self._require_not_closed()
        self._owasp_refs.append(ref)
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[FindingEvent]:
        """Return and clear all pending domain events."""
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_open(self) -> None:
        if not self.is_open:
            raise InvalidFindingTransitionError(str(self._status), "requires open")

    def _require_not_closed(self) -> None:
        if self._status == FindingStatus.CLOSED:
            raise FindingClosedError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: FindingEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Finding):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"Finding(id={self._id}, severity={self._severity}, "
            f"status={self._status})"
        )
