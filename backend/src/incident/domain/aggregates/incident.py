"""Incident aggregate — lifecycle DECLARED → CLOSED."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from incident.domain.entities.timeline_entry import IncidentTimelineEntry
from incident.domain.events.incident_events import (
    IncidentClassified,
    IncidentClosed,
    IncidentContained,
    IncidentDeclared,
    IncidentEradicated,
    IncidentReclassified,
    IncidentRecovered,
    IncidentTimelineUpdated,
    RecoveryCompleted,
)
from incident.domain.exceptions.domain_exceptions import (
    ClosureRequirementsNotMet,
    DomainInvariantViolation,
    InvalidPhaseTransition,
    TenantMismatch,
)
from incident.domain.value_objects.enums import (
    IncidentPhase,
    IncidentSeverity,
    IncidentTriggerType,
    ResolutionType,
    SeverityClassificationMethod,
    TimelineEntryType,
)
from incident.domain.value_objects.identifiers import IncidentId, TenantId
from incident.domain.value_objects.refs import (
    EscalatedFindingRef,
    ExposureScopeRef,
    InvestigationRef,
)


@dataclass
class IncidentTag:
    key: str
    value: str


class Incident:
    __slots__ = (
        "_pending_events",
        "classification_method",
        "classified_at",
        "closed_at",
        "contained_at",
        "description",
        "eradicated_at",
        "exposure_scope_refs",
        "force_close_justification",
        "incident_id",
        "investigation_ref",
        "phase",
        "recovered_at",
        "resolution_type",
        "severity",
        "source_finding_ref",
        "tags",
        "tenant_id",
        "timeline",
        "title",
        "trigger_type",
        "version",
    )

    def __init__(
        self,
        incident_id: IncidentId,
        tenant_id: TenantId,
        title: str,
        description: str,
        phase: IncidentPhase,
        severity: IncidentSeverity,
        trigger_type: IncidentTriggerType,
        classification_method: SeverityClassificationMethod | None,
        created_at: datetime,
        *,
        source_finding_ref: EscalatedFindingRef | None = None,
        investigation_ref: InvestigationRef | None = None,
        exposure_scope_refs: list[ExposureScopeRef] | None = None,
        classified_at: datetime | None = None,
        contained_at: datetime | None = None,
        eradicated_at: datetime | None = None,
        recovered_at: datetime | None = None,
        closed_at: datetime | None = None,
        resolution_type: ResolutionType | None = None,
        tags: list[IncidentTag] | None = None,
        timeline: list[IncidentTimelineEntry] | None = None,
        version: int = 1,
        force_close_justification: str | None = None,
    ) -> None:
        self.incident_id = incident_id
        self.tenant_id = tenant_id
        self.title = title
        self.description = description
        self.phase = phase
        self.severity = severity
        self.trigger_type = trigger_type
        self.classification_method = classification_method
        self.source_finding_ref = source_finding_ref
        self.investigation_ref = investigation_ref
        self.exposure_scope_refs = list(exposure_scope_refs or [])
        self.classified_at = classified_at
        self.contained_at = contained_at
        self.eradicated_at = eradicated_at
        self.recovered_at = recovered_at
        self.closed_at = closed_at
        self.resolution_type = resolution_type
        self.tags = list(tags or [])
        self.timeline = list(timeline or [])
        self.version = version
        self.force_close_justification = force_close_justification
        self._pending_events: list[Any] = []
        del created_at

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: Any) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    def _append_timeline(
        self,
        entry_type: TimelineEntryType,
        summary: str,
        actor: str,
        at: datetime,
        details: dict[str, str] | None = None,
    ) -> None:
        entry = IncidentTimelineEntry.create(entry_type, summary, actor, at, details)
        self.timeline.append(entry)
        self._emit(
            IncidentTimelineUpdated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                entry_type=entry_type.value,
            )
        )

    @classmethod
    def declare(
        cls,
        incident_id: IncidentId,
        tenant_id: TenantId,
        title: str,
        description: str,
        trigger_type: IncidentTriggerType,
        severity: IncidentSeverity,
        at: datetime,
        *,
        source_finding_ref: EscalatedFindingRef | None = None,
        investigation_ref: InvestigationRef | None = None,
        actor: str = "system",
    ) -> Incident:
        inc = cls(
            incident_id,
            tenant_id,
            title,
            description,
            IncidentPhase.DECLARED,
            severity,
            trigger_type,
            None,
            at,
            source_finding_ref=source_finding_ref,
            investigation_ref=investigation_ref,
        )
        inc._append_timeline(
            TimelineEntryType.PHASE_TRANSITION,
            "Incident declared",
            actor,
            at,
            {"phase": IncidentPhase.DECLARED.value},
        )
        inc._emit(
            IncidentDeclared(
                tenant_id=str(tenant_id),
                aggregate_id=str(incident_id),
                incident_id=str(incident_id),
                trigger_type=trigger_type.value,
                severity=severity.value,
                declared_at=at.isoformat(),
            )
        )
        return inc

    def classify(
        self,
        tenant_id: TenantId,
        severity: IncidentSeverity,
        method: SeverityClassificationMethod,
        at: datetime,
        actor: str,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.phase != IncidentPhase.DECLARED:
            raise InvalidPhaseTransition("classify only from DECLARED")
        if self.classified_at is not None:
            raise DomainInvariantViolation("classified_at immutable")
        self.severity = severity
        self.classification_method = method
        self.classified_at = at
        self.phase = IncidentPhase.CLASSIFIED
        self.version += 1
        self._append_timeline(
            TimelineEntryType.PHASE_TRANSITION,
            "Incident classified",
            actor,
            at,
            {"severity": severity.value, "method": method.value},
        )
        finding = self.source_finding_ref.finding_id if self.source_finding_ref else None
        investigation = self.investigation_ref.investigation_id if self.investigation_ref else None
        self._emit(
            IncidentClassified(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                severity=severity.value,
                classified_at=at.isoformat(),
                classification_method=method.value,
                trigger_type=self.trigger_type.value,
                source_finding_ref=finding,
                source_investigation_ref=investigation,
            )
        )

    def reclassify(
        self,
        tenant_id: TenantId,
        new_severity: IncidentSeverity,
        justification: str,
        reclassified_by: str,
        at: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.phase == IncidentPhase.CLOSED:
            raise InvalidPhaseTransition("cannot reclassify closed incident")
        if len(justification.strip()) < 20:
            raise DomainInvariantViolation("justification must be >= 20 characters")
        old = self.severity
        self.severity = new_severity
        self.classification_method = SeverityClassificationMethod.COMMANDER_OVERRIDE
        self.version += 1
        self._append_timeline(
            TimelineEntryType.SEVERITY_RECLASSIFIED,
            f"Severity {old.value} → {new_severity.value}",
            reclassified_by,
            at,
            {"justification": justification},
        )
        self._emit(
            IncidentReclassified(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                old_severity=old.value,
                new_severity=new_severity.value,
                justification=justification,
                reclassified_by=reclassified_by,
                reclassified_at=at.isoformat(),
            )
        )

    def mark_contained(self, tenant_id: TenantId, at: datetime, actor: str) -> None:
        self._assert_tenant(tenant_id)
        if self.phase != IncidentPhase.CLASSIFIED:
            raise InvalidPhaseTransition("contain only from CLASSIFIED")
        self.phase = IncidentPhase.CONTAINED
        self.contained_at = at
        self.version += 1
        self._append_timeline(
            TimelineEntryType.PHASE_TRANSITION, "Containment complete", actor, at, {}
        )
        self._emit(
            IncidentContained(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                contained_at=at.isoformat(),
            )
        )

    def mark_eradicated(self, tenant_id: TenantId, at: datetime, actor: str) -> None:
        self._assert_tenant(tenant_id)
        if self.phase != IncidentPhase.CONTAINED:
            raise InvalidPhaseTransition("eradicate only from CONTAINED")
        self.phase = IncidentPhase.ERADICATED
        self.eradicated_at = at
        self.version += 1
        self._append_timeline(
            TimelineEntryType.ERADICATION_VERIFIED, "Eradication verified", actor, at, {}
        )
        self._emit(
            IncidentEradicated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                eradicated_at=at.isoformat(),
            )
        )

    def mark_recovered(self, tenant_id: TenantId, at: datetime, actor: str) -> None:
        self._assert_tenant(tenant_id)
        if self.phase != IncidentPhase.ERADICATED:
            raise InvalidPhaseTransition("recover only from ERADICATED")
        self.phase = IncidentPhase.RECOVERED
        self.recovered_at = at
        self.version += 1
        self._append_timeline(
            TimelineEntryType.RECOVERY_COMPLETED, "Recovery complete", actor, at, {}
        )
        self._emit(
            IncidentRecovered(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                recovered_at=at.isoformat(),
            )
        )
        self._emit(
            RecoveryCompleted(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                recovered_at=at.isoformat(),
            )
        )

    def close(
        self,
        tenant_id: TenantId,
        resolution_type: ResolutionType,
        at: datetime,
        actor: str,
        *,
        eradication_verified: bool,
        force: bool = False,
        force_justification: str | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.phase == IncidentPhase.CLOSED:
            raise InvalidPhaseTransition("already closed")
        allowed_fp = resolution_type in {ResolutionType.FALSE_POSITIVE, ResolutionType.DUPLICATE}
        if not eradication_verified and not allowed_fp and not force:
            raise ClosureRequirementsNotMet(
                "CLOSED requires VERIFIED eradication, FALSE_POSITIVE/DUPLICATE, or CISO override"
            )
        if force:
            if not force_justification or len(force_justification.strip()) < 20:
                raise DomainInvariantViolation("force-close justification >= 20 chars")
            self.force_close_justification = force_justification
        if self.classified_at is None:
            raise ClosureRequirementsNotMet("incident must be classified before close")
        self.phase = IncidentPhase.CLOSED
        self.closed_at = at
        self.resolution_type = resolution_type
        self.version += 1
        duration = (at - self.classified_at).total_seconds() / 3600.0
        self._append_timeline(
            TimelineEntryType.INCIDENT_CLOSED,
            "Incident closed",
            actor,
            at,
            {"resolution": resolution_type.value, "force": str(force)},
        )
        self._emit(
            IncidentClosed(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.incident_id),
                incident_id=str(self.incident_id),
                closed_at=at.isoformat(),
                resolution_type=resolution_type.value,
                classified_at=self.classified_at.isoformat(),
                incident_duration_hours=duration,
            )
        )
