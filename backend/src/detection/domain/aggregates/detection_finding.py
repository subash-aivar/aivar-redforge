"""DetectionFinding aggregate root with deduplication support."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.events.finding_events import (
    DetectionFindingClosed,
    DetectionFindingConfirmed,
    DetectionFindingEscalated,
    DetectionFindingMarkedFalsePositive,
    DetectionFindingProduced,
    DetectionFindingSuppressed,
    DetectionFindingTriaged,
)
from detection.domain.exceptions.domain_exceptions import (
    FindingLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from detection.domain.value_objects.enums import FindingState
from detection.domain.value_objects.execution_finding import (
    AnalystNote,
    FindingCorrelation,
)
from detection.domain.value_objects.identifiers import DetectionFindingId

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import FindingConfidence, FindingSeverity
    from detection.domain.value_objects.execution_finding import (
        AssetRef,
        DetectionExecutionRef,
        DetectionRuleRef,
        EscalationRef,
        FindingKey,
        MitreAttackRef,
        TelemetryFingerprint,
        TelemetrySignalRef,
    )
    from detection.domain.value_objects.identifiers import TenantId

_ALLOWED: dict[FindingState, frozenset[FindingState]] = {
    FindingState.NEW: frozenset(
        {
            FindingState.TRIAGED,
            FindingState.CONFIRMED,
            FindingState.FALSE_POSITIVE,
            FindingState.SUPPRESSED,
            FindingState.ESCALATED_TO_INVESTIGATION,
            FindingState.CLOSED,
        }
    ),
    FindingState.TRIAGED: frozenset(
        {
            FindingState.CONFIRMED,
            FindingState.FALSE_POSITIVE,
            FindingState.SUPPRESSED,
            FindingState.ESCALATED_TO_INVESTIGATION,
            FindingState.CLOSED,
        }
    ),
    FindingState.CONFIRMED: frozenset(
        {
            FindingState.FALSE_POSITIVE,
            FindingState.ESCALATED_TO_INVESTIGATION,
            FindingState.CLOSED,
        }
    ),
    FindingState.FALSE_POSITIVE: frozenset({FindingState.CLOSED}),
    FindingState.SUPPRESSED: frozenset({FindingState.CLOSED}),
    FindingState.ESCALATED_TO_INVESTIGATION: frozenset({FindingState.CLOSED}),
    FindingState.CLOSED: frozenset(),
}


class DetectionFinding:
    """Atomic detection match output with lifecycle and dedup identity."""

    __slots__ = (
        "_pending_events",
        "_version",
        "analyst_note",
        "asset_ref",
        "confidence",
        "correlation",
        "created_at",
        "detected_at",
        "escalation_ref",
        "execution_ref",
        "finding_id",
        "finding_key",
        "last_seen_at",
        "mitre_ref",
        "observed_at",
        "reopened_from",
        "rule_ref",
        "severity",
        "state",
        "telemetry_fingerprint",
        "telemetry_signal",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        finding_id: DetectionFindingId,
        tenant_id: TenantId,
        finding_key: FindingKey,
        rule_ref: DetectionRuleRef,
        execution_ref: DetectionExecutionRef,
        asset_ref: AssetRef,
        telemetry_signal: TelemetrySignalRef,
        telemetry_fingerprint: TelemetryFingerprint,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        observed_at: datetime,
        detected_at: datetime,
        last_seen_at: datetime,
        state: FindingState,
        mitre_ref: MitreAttackRef | None,
        correlation: FindingCorrelation,
        analyst_note: AnalystNote | None,
        escalation_ref: EscalationRef | None,
        reopened_from: DetectionFindingId | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.finding_id = finding_id
        self.tenant_id = tenant_id
        self.finding_key = finding_key
        self.rule_ref = rule_ref
        self.execution_ref = execution_ref
        self.asset_ref = asset_ref
        self.telemetry_signal = telemetry_signal
        self.telemetry_fingerprint = telemetry_fingerprint
        self.severity = severity
        self.confidence = confidence
        self.observed_at = observed_at
        self.detected_at = detected_at
        self.last_seen_at = last_seen_at
        self.state = state
        self.mitre_ref = mitre_ref
        self.correlation = correlation
        self.analyst_note = analyst_note
        self.escalation_ref = escalation_ref
        self.reopened_from = reopened_from
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def is_open(self) -> bool:
        return self.state not in {
            FindingState.CLOSED,
            FindingState.FALSE_POSITIVE,
            FindingState.SUPPRESSED,
        }

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: FindingState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(self.state.value, to_state.value)
        self.state = to_state

    @classmethod
    def produce(
        cls,
        *,
        tenant_id: TenantId,
        finding_key: FindingKey,
        rule_ref: DetectionRuleRef,
        execution_ref: DetectionExecutionRef,
        asset_ref: AssetRef,
        telemetry_signal: TelemetrySignalRef,
        telemetry_fingerprint: TelemetryFingerprint,
        severity: FindingSeverity,
        confidence: FindingConfidence,
        observed_at: datetime,
        now: datetime,
        mitre_ref: MitreAttackRef | None = None,
        reopened_from: DetectionFindingId | None = None,
        finding_id: DetectionFindingId | None = None,
    ) -> DetectionFinding:
        fid = finding_id or DetectionFindingId.generate()
        aggregate = cls(
            finding_id=fid,
            tenant_id=tenant_id,
            finding_key=finding_key,
            rule_ref=rule_ref,
            execution_ref=execution_ref,
            asset_ref=asset_ref,
            telemetry_signal=telemetry_signal,
            telemetry_fingerprint=telemetry_fingerprint,
            severity=severity,
            confidence=confidence,
            observed_at=observed_at,
            detected_at=now,
            last_seen_at=now,
            state=FindingState.NEW,
            mitre_ref=mitre_ref,
            correlation=FindingCorrelation.placeholder(),
            analyst_note=None,
            escalation_ref=None,
            reopened_from=reopened_from,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            DetectionFindingProduced(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(fid),
                aggregate_type="DetectionFinding",
                rule_id=rule_ref.rule_id,
                rule_version=rule_ref.rule_version,
                execution_id=execution_ref.execution_id,
                finding_key=str(finding_key),
                asset_id=str(asset_ref),
                severity=severity.value,
            )
        )
        return aggregate

    def touch_last_seen(self, *, tenant_id: TenantId, now: datetime) -> None:
        """Dedup path: same FindingKey within window updates last_seen_at only."""
        self._assert_tenant(tenant_id)
        if self.state == FindingState.CLOSED:
            raise FindingLifecycleBlocked("cannot update last_seen on closed finding")
        self.last_seen_at = now
        self._mutate(now)

    def triage(
        self,
        *,
        tenant_id: TenantId,
        analyst: str,
        note: AnalystNote | None = None,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not analyst.strip():
            raise InvalidArgument("analyst", "required")
        self._transition(FindingState.TRIAGED)
        if note is not None:
            self.analyst_note = note
        self._mutate(now)
        self._emit(
            DetectionFindingTriaged(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                analyst=analyst.strip(),
                note=note.text if note else None,
            )
        )

    def confirm(self, *, tenant_id: TenantId, analyst: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not analyst.strip():
            raise InvalidArgument("analyst", "required")
        self._transition(FindingState.CONFIRMED)
        self._mutate(now)
        self._emit(
            DetectionFindingConfirmed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                analyst=analyst.strip(),
            )
        )

    def mark_false_positive(
        self,
        *,
        tenant_id: TenantId,
        analyst: str,
        justification: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not analyst.strip():
            raise InvalidArgument("analyst", "required")
        if not justification.strip():
            raise InvalidArgument("justification", "required")
        self._transition(FindingState.FALSE_POSITIVE)
        self.analyst_note = AnalystNote(text=justification, author=analyst.strip())
        self._mutate(now)
        self._emit(
            DetectionFindingMarkedFalsePositive(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                analyst=analyst.strip(),
                justification=justification.strip()[:4096],
            )
        )

    def suppress(
        self,
        *,
        tenant_id: TenantId,
        analyst: str,
        justification: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not analyst.strip():
            raise InvalidArgument("analyst", "required")
        if not justification.strip():
            raise InvalidArgument("justification", "required")
        self._transition(FindingState.SUPPRESSED)
        self._mutate(now)
        self._emit(
            DetectionFindingSuppressed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                analyst=analyst.strip(),
                justification=justification.strip()[:4096],
            )
        )

    def escalate(
        self,
        *,
        tenant_id: TenantId,
        analyst: str,
        escalation_ref: EscalationRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not analyst.strip():
            raise InvalidArgument("analyst", "required")
        self._transition(FindingState.ESCALATED_TO_INVESTIGATION)
        self.escalation_ref = escalation_ref
        self._mutate(now)
        self._emit(
            DetectionFindingEscalated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                analyst=analyst.strip(),
                investigation_id=escalation_ref.investigation_id,
            )
        )

    def close(self, *, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(FindingState.CLOSED)
        self._mutate(now)
        self._emit(
            DetectionFindingClosed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.finding_id),
                aggregate_type="DetectionFinding",
                reason=reason.strip()[:1024],
            )
        )

    def enrich_correlation(
        self,
        *,
        tenant_id: TenantId,
        correlation: FindingCorrelation,
        now: datetime,
    ) -> None:
        """Apply asynchronous CorrelationContext enrichment (never blocks produce)."""
        self._assert_tenant(tenant_id)
        self.correlation = correlation
        self._mutate(now)
