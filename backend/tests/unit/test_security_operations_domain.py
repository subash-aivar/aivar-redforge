"""Pure domain/application unit tests for the Security Operations
bounded context (M15) — no database, no HTTP."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.application.security_operations.execution_phase import phase_for_event_type
from redforge.application.security_operations.projection_registry import (
    project_execution_event,
    project_policy_lifecycle_event,
    project_runtime_transition,
)
from redforge.application.security_operations.stream_service import (
    make_cursor,
    parse_cursor_timestamp,
)
from redforge.domain.security_operations.operational_event import OperationalEvent
from redforge.domain.security_operations.value_objects import (
    BoundedPeriod,
    ExecutionPhase,
    OperationalImportance,
    SourceDomain,
    bounded_period_seconds,
)


def test_bounded_period_seconds_closed_mapping() -> None:
    assert bounded_period_seconds(BoundedPeriod.ONE_HOUR) == 3600
    assert bounded_period_seconds(BoundedPeriod.TWENTY_FOUR_HOURS) == 86400
    assert bounded_period_seconds(BoundedPeriod.SEVEN_DAYS) == 7 * 86400
    assert bounded_period_seconds(BoundedPeriod.THIRTY_DAYS) == 30 * 86400


def test_unknown_execution_event_type_not_projected() -> None:
    """An internal event type this registry doesn't recognize must be
    silently skipped, never crash and never fabricate an entry."""
    result = project_execution_event(
        event_type="policy_check_started", payload={}, execution_id="exec-1",
        organization_id="org-1", occurred_at="2026-01-01T00:00:00+00:00",
    )
    assert result is None


def test_known_execution_event_type_projects_with_bounded_fields() -> None:
    result = project_execution_event(
        event_type="policy_denied", payload={"reason_code": "no_authorization"},
        execution_id="exec-1", organization_id="org-1",
        occurred_at="2026-01-01T00:00:00+00:00",
    )
    assert result is not None
    assert result.source_domain == SourceDomain.VALIDATION
    assert result.importance == OperationalImportance.WARNING
    assert "no_authorization" in result.summary
    assert result.entity_id == "exec-1"


def test_policy_lifecycle_disabled_is_warning_others_are_notice() -> None:
    disabled = project_policy_lifecycle_event(
        event_id="e1", event_type="disabled", policy_id="p1",
        organization_id="org-1", occurred_at="2026-01-01T00:00:00+00:00",
    )
    activated = project_policy_lifecycle_event(
        event_id="e2", event_type="activated", policy_id="p1",
        organization_id="org-1", occurred_at="2026-01-01T00:00:00+00:00",
    )
    assert disabled.importance == OperationalImportance.WARNING
    assert activated.importance == OperationalImportance.NOTICE


def test_runtime_transition_to_unhealthy_is_high_importance() -> None:
    unhealthy = project_runtime_transition(
        transition_id="t1", component_id="database", old_status="healthy",
        new_status="unhealthy", organization_id="org-1",
        occurred_at="2026-01-01T00:00:00+00:00",
    )
    recovered = project_runtime_transition(
        transition_id="t2", component_id="database", old_status="unhealthy",
        new_status="healthy", organization_id="org-1",
        occurred_at="2026-01-01T00:00:00+00:00",
    )
    assert unhealthy.importance == OperationalImportance.HIGH
    assert recovered.importance == OperationalImportance.NOTICE


def test_phase_for_event_type_unknown_resolves_to_unknown() -> None:
    assert phase_for_event_type("some_future_event_type") == ExecutionPhase.UNKNOWN


def test_phase_for_protocol_step_refines_to_protocol_validation() -> None:
    assert (
        phase_for_event_type("step_completed", "ssh_banner")
        == ExecutionPhase.PROTOCOL_VALIDATION
    )
    assert phase_for_event_type("step_completed", "port_discovery") != (
        ExecutionPhase.PROTOCOL_VALIDATION
    )


def test_operational_event_title_and_summary_are_bounded() -> None:
    huge = "x" * 10_000
    event = OperationalEvent(
        cursor="c1", event_id="e1", organization_id="org-1",
        source_domain=SourceDomain.VALIDATION, importance=OperationalImportance.INFO,
        title=huge, summary=huge, entity_type="validation_execution", entity_id="exec-1",
        occurred_at="2026-01-01T00:00:00+00:00",
    )
    assert len(event.title) <= 240
    assert len(event.summary) <= 240


def test_make_cursor_is_lexicographically_chronological() -> None:
    """ISO-8601-fixed-width timestamps must sort the same way
    lexicographically as chronologically, including the case where one
    timestamp has microsecond == 0 (which datetime.isoformat() would
    otherwise silently omit, breaking fixed-width comparison)."""
    earlier = datetime(2026, 1, 1, 0, 0, 0, 0, tzinfo=UTC)
    later = datetime(2026, 1, 1, 0, 0, 0, 500000, tzinfo=UTC)
    cursor_earlier = make_cursor(earlier, "E", "row-a")
    cursor_later = make_cursor(later, "E", "row-b")
    assert cursor_earlier < cursor_later


def test_parse_cursor_timestamp_roundtrips_valid_cursor() -> None:
    now = datetime(2026, 6, 1, 12, 30, 45, 123456, tzinfo=UTC)
    cursor = make_cursor(now, "D", "row-x")
    parsed = parse_cursor_timestamp(cursor)
    assert parsed == now


@pytest.mark.parametrize("garbage", ["not-a-cursor", "", "12345", "E|row-only"])
def test_parse_cursor_timestamp_returns_none_for_malformed_input(garbage: str) -> None:
    """Never raises — a malformed cursor must degrade to None (caller
    treats this as 'read from the beginning'), never a 500."""
    assert parse_cursor_timestamp(garbage) is None
