from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_alerting.domain.aggregates.alert import Alert
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
from siem_alerting.domain.value_objects.enums import AlertSeverity, AlertSourceKind, AlertStatus
from siem_alerting.domain.value_objects.identifiers import AlertId

NOW = datetime.now(UTC)


def _tenant() -> EntityId:
    return EntityId.generate()


def _raised(tenant_id: EntityId | None = None, dedup_key: str = "dedup-1") -> Alert:
    return Alert.raise_alert(
        alert_id=AlertId.generate(),
        tenant_id=tenant_id or _tenant(),
        dedup_key=dedup_key,
        severity=AlertSeverity.HIGH,
        source_kind=AlertSourceKind.DETECTION,
        source_ref="rule-1",
        now=NOW,
    )


def test_raise_alert_starts_raised_and_emits_event() -> None:
    alert = _raised()
    assert alert.status == AlertStatus.RAISED
    events = alert.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], AlertRaised)


def test_raise_alert_rejects_blank_dedup_key() -> None:
    with pytest.raises(EmptyDedupKeyError):
        Alert.raise_alert(
            alert_id=AlertId.generate(),
            tenant_id=_tenant(),
            dedup_key="  ",
            severity=AlertSeverity.LOW,
            source_kind=AlertSourceKind.CORRELATION,
            source_ref="session-1",
            now=NOW,
        )


def test_two_matching_detections_dedupe_to_one_alert_not_two() -> None:
    """The under-dedup failure mode named in M42 Phase 8's risk register:
    two detections sharing a dedup key must genuinely collapse to one
    surfaced alert, not silently produce two RAISED alerts."""
    tenant_id = _tenant()
    first = _raised(tenant_id, dedup_key="shared-key")
    second = _raised(tenant_id, dedup_key="shared-key")

    second.deduplicate(tenant_id, str(first.alert_id), NOW)

    assert first.status == AlertStatus.RAISED
    assert second.status == AlertStatus.DEDUPLICATED
    events = second.pop_events()
    assert isinstance(events[-1], AlertDeduplicated)
    assert events[-1].original_alert_id == str(first.alert_id)


def test_suppress_requires_a_real_alert_to_still_exist() -> None:
    """The over-suppress failure mode: suppression must record a reason
    and transition explicitly, never delete/hide the alert silently."""
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.suppress(tenant_id, "known benign scanner", NOW)

    assert alert.status == AlertStatus.SUPPRESSED
    assert alert.suppression_reason == "known benign scanner"
    events = alert.pop_events()
    assert isinstance(events[-1], AlertSuppressed)


def test_suppress_requires_non_empty_reason() -> None:
    alert = _raised()
    tenant_id = alert.tenant_id
    with pytest.raises(ValueError, match="reason"):
        alert.suppress(tenant_id, "  ", NOW)


def test_escalate_from_raised_emits_event() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.pop_events()
    alert.escalate(tenant_id, NOW)

    assert alert.status == AlertStatus.ESCALATED
    events = alert.pop_events()
    assert isinstance(events[0], AlertEscalated)


def test_escalate_after_suppress_raises() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.suppress(tenant_id, "benign", NOW)
    with pytest.raises(InvalidAlertTransition):
        alert.escalate(tenant_id, NOW)


def test_acknowledge_requires_escalated_first() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    with pytest.raises(InvalidAlertTransition):
        alert.acknowledge(tenant_id, "analyst-1", NOW)


def test_full_lifecycle_raised_escalated_acknowledged_closed() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.escalate(tenant_id, NOW)
    alert.acknowledge(tenant_id, "analyst-1", NOW)
    alert.close(tenant_id, "analyst-1", "confirmed and remediated", NOW)

    assert alert.status == AlertStatus.CLOSED
    assert alert.closed_by == "analyst-1"
    assert alert.resolution == "confirmed and remediated"


def test_close_from_suppressed_is_allowed() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.suppress(tenant_id, "benign", NOW)
    alert.close(tenant_id, "analyst-1", "no action needed", NOW)
    assert alert.status == AlertStatus.CLOSED


def test_close_from_deduplicated_is_allowed() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.deduplicate(tenant_id, "orig-1", NOW)
    alert.close(tenant_id, "analyst-1", "handled via original alert", NOW)
    assert alert.status == AlertStatus.CLOSED


def test_close_from_raised_is_rejected() -> None:
    """A RAISED alert cannot skip straight to CLOSED — it must pass
    through the escalate/acknowledge (or suppress/dedupe) path."""
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    with pytest.raises(InvalidAlertTransition):
        alert.close(tenant_id, "analyst-1", "skipped workflow", NOW)


def test_close_twice_raises() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.escalate(tenant_id, NOW)
    alert.acknowledge(tenant_id, "analyst-1", NOW)
    alert.close(tenant_id, "analyst-1", "done", NOW)
    with pytest.raises(InvalidAlertTransition):
        alert.close(tenant_id, "analyst-1", "done again", NOW)


def test_wrong_tenant_raises_tenant_mismatch() -> None:
    alert = _raised()
    with pytest.raises(TenantMismatch):
        alert.escalate(_tenant(), NOW)


def test_acknowledged_event_carries_who() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.escalate(tenant_id, NOW)
    alert.pop_events()
    alert.acknowledge(tenant_id, "  analyst-9  ", NOW)
    events = alert.pop_events()
    assert isinstance(events[0], AlertAcknowledged)
    assert events[0].acknowledged_by == "analyst-9"


def test_close_event_carries_resolution() -> None:
    tenant_id = _tenant()
    alert = _raised(tenant_id)
    alert.escalate(tenant_id, NOW)
    alert.acknowledge(tenant_id, "analyst-1", NOW)
    alert.pop_events()
    alert.close(tenant_id, "analyst-1", "false positive", NOW)
    events = alert.pop_events()
    assert isinstance(events[0], AlertClosed)
    assert events[0].resolution == "false positive"
