from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_correlation.domain.aggregates.correlation_session import CorrelationSession
from siem_correlation.domain.events.correlation_events import (
    CorrelationMatched,
    CorrelationSessionExpired,
    CorrelationSessionOpened,
)
from siem_correlation.domain.exceptions.domain_exceptions import (
    EmptyRuleIdError,
    SessionAlreadyExpiredError,
    SessionAlreadyMatchedError,
    TenantMismatch,
    WindowExpiryNotInFutureError,
)
from siem_correlation.domain.value_objects.enums import CorrelationKind, CorrelationSessionStatus
from siem_correlation.domain.value_objects.identifiers import CorrelationSessionId

OPENED_AT = datetime.now(UTC)
EXPIRES_AT = OPENED_AT + timedelta(minutes=15)


def _tenant() -> EntityId:
    return EntityId.generate()


def _open(tenant_id: EntityId | None = None) -> CorrelationSession:
    return CorrelationSession.open(
        session_id=CorrelationSessionId.generate(),
        tenant_id=tenant_id or _tenant(),
        rule_id="rule-brute-force",
        correlation_kind=CorrelationKind.ENTITY,
        window_started_at=OPENED_AT,
        window_expires_at=EXPIRES_AT,
    )


def test_open_starts_open_and_emits_event() -> None:
    session = _open()
    assert session.status == CorrelationSessionStatus.OPEN
    events = session.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], CorrelationSessionOpened)


def test_open_rejects_blank_rule_id() -> None:
    with pytest.raises(EmptyRuleIdError):
        CorrelationSession.open(
            session_id=CorrelationSessionId.generate(),
            tenant_id=_tenant(),
            rule_id="  ",
            correlation_kind=CorrelationKind.ENTITY,
            window_started_at=OPENED_AT,
            window_expires_at=EXPIRES_AT,
        )


def test_open_rejects_non_future_expiry() -> None:
    with pytest.raises(WindowExpiryNotInFutureError):
        CorrelationSession.open(
            session_id=CorrelationSessionId.generate(),
            tenant_id=_tenant(),
            rule_id="rule-1",
            correlation_kind=CorrelationKind.ENTITY,
            window_started_at=OPENED_AT,
            window_expires_at=OPENED_AT,
        )


def test_accumulate_within_window_appends_event() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=1))
    session.accumulate(tenant_id, "evt-2", OPENED_AT + timedelta(minutes=2))
    assert session.correlated_event_ids == ["evt-1", "evt-2"]


def test_accumulate_is_deduplicated() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=1))
    session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=2))
    assert session.correlated_event_ids == ["evt-1"]


def test_accumulate_after_window_elapsed_raises_not_silently_ignored() -> None:
    """The top-named architecture risk (M37 §6/§22): a session that
    keeps accumulating past its window is the unbounded-growth failure
    mode. This must be a hard error, never a silent no-op."""
    tenant_id = _tenant()
    session = _open(tenant_id)
    with pytest.raises(SessionAlreadyExpiredError):
        session.accumulate(tenant_id, "evt-late", EXPIRES_AT + timedelta(seconds=1))


def test_accumulate_after_explicit_expire_raises() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.expire(tenant_id, OPENED_AT + timedelta(minutes=1))
    with pytest.raises(SessionAlreadyExpiredError):
        session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=2))


def test_accumulate_wrong_tenant_raises_tenant_mismatch() -> None:
    session = _open()
    with pytest.raises(TenantMismatch):
        session.accumulate(_tenant(), "evt-1", OPENED_AT + timedelta(minutes=1))


def test_match_transitions_and_emits_correlated_event_ids() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=1))
    session.pop_events()
    session.match(tenant_id, OPENED_AT + timedelta(minutes=2))

    assert session.status == CorrelationSessionStatus.MATCHED
    events = session.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], CorrelationMatched)
    assert events[0].correlated_event_ids == ("evt-1",)


def test_match_after_expire_raises() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.expire(tenant_id, OPENED_AT + timedelta(minutes=1))
    with pytest.raises(SessionAlreadyExpiredError):
        session.match(tenant_id, OPENED_AT + timedelta(minutes=2))


def test_match_twice_raises_already_matched() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.match(tenant_id, OPENED_AT + timedelta(minutes=1))
    with pytest.raises(SessionAlreadyMatchedError):
        session.match(tenant_id, OPENED_AT + timedelta(minutes=2))


def test_expire_transitions_and_emits_accumulated_count() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.accumulate(tenant_id, "evt-1", OPENED_AT + timedelta(minutes=1))
    session.accumulate(tenant_id, "evt-2", OPENED_AT + timedelta(minutes=2))
    session.pop_events()
    session.expire(tenant_id, EXPIRES_AT)

    assert session.status == CorrelationSessionStatus.EXPIRED
    events = session.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], CorrelationSessionExpired)
    assert events[0].accumulated_event_count == 2


def test_expire_twice_raises_not_a_silent_no_op() -> None:
    """A session must never expire more than once — this is the bounded-
    lifetime guarantee M37 §6 requires be genuinely enforced, not merely
    documented."""
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.expire(tenant_id, EXPIRES_AT)
    with pytest.raises(SessionAlreadyExpiredError):
        session.expire(tenant_id, EXPIRES_AT + timedelta(seconds=1))


def test_expire_after_match_raises() -> None:
    tenant_id = _tenant()
    session = _open(tenant_id)
    session.match(tenant_id, OPENED_AT + timedelta(minutes=1))
    with pytest.raises(SessionAlreadyMatchedError):
        session.expire(tenant_id, EXPIRES_AT)


def test_is_window_elapsed() -> None:
    session = _open()
    assert session.is_window_elapsed(EXPIRES_AT - timedelta(seconds=1)) is False
    assert session.is_window_elapsed(EXPIRES_AT) is True
