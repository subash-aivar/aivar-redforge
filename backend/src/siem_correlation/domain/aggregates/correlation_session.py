"""CorrelationSession aggregate — a bounded, time-windowed accumulation
of related events under evaluation (M37 §2.2).

This is the architecture's highest-execution-risk component (M37 §6,
§22): the aggregate must never accumulate unboundedly. Every mutating
method here enforces the window boundary explicitly rather than
trusting a caller to check `is_expired` first — accumulating into or
matching an already-expired session is a domain error, not a silent
no-op, so the "session that never closes" failure mode cannot occur
through this aggregate's own API surface.

This aggregate owns session bookkeeping only — it must never embed
detection logic itself (M37 §2.2: `siem_detection` owns the rule
definition, `siem_correlation` owns execution/window management).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from datetime import datetime

    from siem_correlation.domain.events.base import BaseDomainEvent
    from siem_correlation.domain.value_objects.identifiers import (
        CorrelationSessionId,
        TenantId,
    )


class CorrelationSession:
    __slots__ = (
        "_pending_events",
        "correlated_event_ids",
        "correlation_kind",
        "rule_id",
        "session_id",
        "status",
        "tenant_id",
        "window_expires_at",
        "window_started_at",
    )

    def __init__(
        self,
        session_id: CorrelationSessionId,
        tenant_id: TenantId,
        rule_id: str,
        correlation_kind: CorrelationKind,
        window_started_at: datetime,
        window_expires_at: datetime,
        status: CorrelationSessionStatus,
        correlated_event_ids: list[str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.rule_id = rule_id
        self.correlation_kind = correlation_kind
        self.window_started_at = window_started_at
        self.window_expires_at = window_expires_at
        self.status = status
        self.correlated_event_ids = list(correlated_event_ids or [])
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

    def is_window_elapsed(self, now: datetime) -> bool:
        return now >= self.window_expires_at

    @classmethod
    def open(
        cls,
        session_id: CorrelationSessionId,
        tenant_id: TenantId,
        rule_id: str,
        correlation_kind: CorrelationKind,
        window_started_at: datetime,
        window_expires_at: datetime,
    ) -> CorrelationSession:
        if not rule_id.strip():
            raise EmptyRuleIdError()
        if window_expires_at <= window_started_at:
            raise WindowExpiryNotInFutureError()
        session = cls(
            session_id=session_id,
            tenant_id=tenant_id,
            rule_id=rule_id,
            correlation_kind=correlation_kind,
            window_started_at=window_started_at,
            window_expires_at=window_expires_at,
            status=CorrelationSessionStatus.OPEN,
        )
        session._emit(
            CorrelationSessionOpened(
                tenant_id=str(tenant_id),
                aggregate_id=str(session_id),
                aggregate_type="CorrelationSession",
                occurred_at=window_started_at,
                rule_id=rule_id,
                window_expires_at=window_expires_at.isoformat(),
            )
        )
        return session

    def accumulate(self, tenant_id: TenantId, event_id: str, now: datetime) -> None:
        """Add a correlated event to the session. Raises rather than
        silently ignoring the call once the session is no longer OPEN —
        an expired-but-still-accumulating session is exactly the
        unbounded-growth failure mode this aggregate exists to prevent."""
        self._assert_tenant(tenant_id)
        if self.status != CorrelationSessionStatus.OPEN or self.is_window_elapsed(now):
            raise SessionAlreadyExpiredError(self.session_id)
        if event_id not in self.correlated_event_ids:
            self.correlated_event_ids.append(event_id)

    def match(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.status == CorrelationSessionStatus.EXPIRED:
            raise SessionAlreadyExpiredError(self.session_id)
        if self.status == CorrelationSessionStatus.MATCHED:
            raise SessionAlreadyMatchedError(self.session_id)
        self.status = CorrelationSessionStatus.MATCHED
        self._emit(
            CorrelationMatched(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.session_id),
                aggregate_type="CorrelationSession",
                occurred_at=now,
                rule_id=self.rule_id,
                correlated_event_ids=tuple(self.correlated_event_ids),
            )
        )

    def expire(self, tenant_id: TenantId, now: datetime) -> None:
        """Close out the session's bounded lifetime. Idempotent by
        design against an already-expired session is deliberately NOT
        allowed — expiring twice would double-emit `RetentionExpired`-
        shaped side effects downstream, so this is a hard transition
        guard, not a no-op."""
        self._assert_tenant(tenant_id)
        if self.status == CorrelationSessionStatus.EXPIRED:
            raise SessionAlreadyExpiredError(self.session_id)
        if self.status == CorrelationSessionStatus.MATCHED:
            raise SessionAlreadyMatchedError(self.session_id)
        self.status = CorrelationSessionStatus.EXPIRED
        self._emit(
            CorrelationSessionExpired(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.session_id),
                aggregate_type="CorrelationSession",
                occurred_at=now,
                rule_id=self.rule_id,
                accumulated_event_count=len(self.correlated_event_ids),
            )
        )
