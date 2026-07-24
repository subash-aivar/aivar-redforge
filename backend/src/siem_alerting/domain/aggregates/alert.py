"""Alert aggregate — severity, dedup, suppression, escalation, workflow
handoff (M37 §2.2, §8).

Deliberately **not** the same aggregate as `incident` (existing
context): an `Alert` is a detection-pipeline output; an `Incident` is a
human/workflow construct that may aggregate multiple alerts.
`siem_alerting` publishes; `incident` subscribes and decides whether to
open/attach — this aggregate never reaches into `incident`'s domain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_alerting.domain.events.alert_events import (
    AlertAcknowledged,
    AlertClosed,
    AlertDeduplicated,
    AlertEscalated,
    AlertRaised,
    AlertSuppressed,
)
from siem_alerting.domain.exceptions.domain_exceptions import (
    EmptyDedupKeyError,
    InvalidAlertTransition,
    TenantMismatch,
)
from siem_alerting.domain.value_objects.enums import AlertSourceKind, AlertStatus

if TYPE_CHECKING:
    from datetime import datetime

    from siem_alerting.domain.events.base import BaseDomainEvent
    from siem_alerting.domain.value_objects.enums import AlertSeverity
    from siem_alerting.domain.value_objects.identifiers import AlertId, TenantId

# Valid predecessor statuses for each transition — enforced explicitly so
# an under- or over-permissive transition can never slip in silently
# (M42 Phase 8's named risk: dedup/suppression logic getting subtly wrong).
_DEDUPLICATE_FROM = {AlertStatus.RAISED}
_SUPPRESS_FROM = {AlertStatus.RAISED}
_ESCALATE_FROM = {AlertStatus.RAISED}
_ACKNOWLEDGE_FROM = {AlertStatus.ESCALATED}
_CLOSE_FROM = {
    AlertStatus.ACKNOWLEDGED,
    AlertStatus.SUPPRESSED,
    AlertStatus.DEDUPLICATED,
}


class Alert:
    __slots__ = (
        "_pending_events",
        "acknowledged_by",
        "alert_id",
        "closed_by",
        "dedup_key",
        "raised_at",
        "resolution",
        "severity",
        "source_kind",
        "source_ref",
        "status",
        "suppression_reason",
        "tenant_id",
    )

    def __init__(
        self,
        alert_id: AlertId,
        tenant_id: TenantId,
        dedup_key: str,
        severity: AlertSeverity,
        source_kind: AlertSourceKind,
        source_ref: str,
        status: AlertStatus,
        raised_at: datetime,
        suppression_reason: str | None = None,
        acknowledged_by: str | None = None,
        closed_by: str | None = None,
        resolution: str | None = None,
    ) -> None:
        self.alert_id = alert_id
        self.tenant_id = tenant_id
        self.dedup_key = dedup_key
        self.severity = severity
        self.source_kind = source_kind
        self.source_ref = source_ref
        self.status = status
        self.raised_at = raised_at
        self.suppression_reason = suppression_reason
        self.acknowledged_by = acknowledged_by
        self.closed_by = closed_by
        self.resolution = resolution
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def raise_alert(
        cls,
        alert_id: AlertId,
        tenant_id: TenantId,
        dedup_key: str,
        severity: AlertSeverity,
        source_kind: AlertSourceKind,
        source_ref: str,
        now: datetime,
    ) -> Alert:
        if not dedup_key.strip():
            raise EmptyDedupKeyError()
        alert = cls(
            alert_id=alert_id,
            tenant_id=tenant_id,
            dedup_key=dedup_key,
            severity=severity,
            source_kind=source_kind,
            source_ref=source_ref,
            status=AlertStatus.RAISED,
            raised_at=now,
        )
        alert._emit(
            AlertRaised(
                tenant_id=str(tenant_id),
                aggregate_id=str(alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                dedup_key=dedup_key,
                severity=severity,
            )
        )
        return alert

    def deduplicate(self, tenant_id: TenantId, original_alert_id: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _DEDUPLICATE_FROM:
            raise InvalidAlertTransition(self.status.value, AlertStatus.DEDUPLICATED.value)
        self.status = AlertStatus.DEDUPLICATED
        self._emit(
            AlertDeduplicated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                dedup_key=self.dedup_key,
                original_alert_id=original_alert_id,
            )
        )

    def suppress(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _SUPPRESS_FROM:
            raise InvalidAlertTransition(self.status.value, AlertStatus.SUPPRESSED.value)
        if not reason.strip():
            raise ValueError("suppression reason must be a non-empty string")
        self.status = AlertStatus.SUPPRESSED
        self.suppression_reason = reason.strip()
        self._emit(
            AlertSuppressed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                suppression_reason=self.suppression_reason,
            )
        )

    def escalate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _ESCALATE_FROM:
            raise InvalidAlertTransition(self.status.value, AlertStatus.ESCALATED.value)
        self.status = AlertStatus.ESCALATED
        self._emit(
            AlertEscalated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                severity=self.severity,
            )
        )

    def acknowledge(self, tenant_id: TenantId, acknowledged_by: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _ACKNOWLEDGE_FROM:
            raise InvalidAlertTransition(self.status.value, AlertStatus.ACKNOWLEDGED.value)
        if not acknowledged_by.strip():
            raise ValueError("acknowledged_by must be a non-empty string")
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_by = acknowledged_by.strip()
        self._emit(
            AlertAcknowledged(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                acknowledged_by=self.acknowledged_by,
            )
        )

    def close(self, tenant_id: TenantId, closed_by: str, resolution: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in _CLOSE_FROM:
            raise InvalidAlertTransition(self.status.value, AlertStatus.CLOSED.value)
        if not closed_by.strip():
            raise ValueError("closed_by must be a non-empty string")
        self.status = AlertStatus.CLOSED
        self.closed_by = closed_by.strip()
        self.resolution = resolution.strip()
        self._emit(
            AlertClosed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.alert_id),
                aggregate_type="Alert",
                occurred_at=now,
                closed_by=self.closed_by,
                resolution=self.resolution,
            )
        )
