"""CorrelationApplicationService — the Correlation Engine's single
application-layer entrypoint (M42 Phase 7 / M44B).

Orchestrates, in order: authorization, tenant/input validation, loading
or opening the tenant's `CorrelationSession` for the given correlation
rule (`ICorrelationSessionProvider`), session-lifecycle checks (closed/
expired), duplicate-event and capacity checks, evaluator selection
(`ICorrelationEvaluatorRegistry`), accumulation (reusing
`CorrelationSession.accumulate`/`match`/`expire` — never reimplementing
window logic), execution, and `CorrelationResult` construction for
anything that matched. This service never creates an `Alert`, never
opens an investigation, never scores risk, and holds no state of its
own between calls — every session mutation is handed to
`ICorrelationSessionWriter` immediately.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_correlation.application import _auth
from siem_correlation.application.dtos.correlation_outcome import (
    BatchCorrelationResult,
    CorrelationFailure,
    CorrelationOutcome,
    CorrelationStatus,
)
from siem_correlation.application.dtos.correlation_result import CorrelationResult
from siem_correlation.application.exceptions import (
    DetectionMatchEventMismatchError,
    EmptyBatchCorrelationError,
    EvaluatorSelectionError,
    SessionAtCapacityError,
    TenantContextMismatchError,
)
from siem_correlation.domain.aggregates.correlation_session import CorrelationSession
from siem_correlation.domain.value_objects.enums import CorrelationRole, CorrelationSessionStatus
from siem_correlation.domain.value_objects.identifiers import CorrelationSessionId

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_correlation.application.commands.correlation_commands import (
        CorrelateBatchCommand,
        CorrelateDetectionMatchCommand,
        CorrelationInput,
    )
    from siem_correlation.application.ports.i_correlation_evaluator_registry import (
        ICorrelationEvaluatorRegistry,
    )
    from siem_correlation.application.ports.i_correlation_session_provider import (
        ICorrelationSessionProvider,
    )
    from siem_correlation.application.ports.i_correlation_session_writer import (
        ICorrelationSessionWriter,
    )

_DEFAULT_WINDOW = timedelta(minutes=15)
_DEFAULT_MAX_CORRELATION_SIZE = 100


def _to_failure(stage: str, exc: Exception) -> CorrelationFailure:
    return CorrelationFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class CorrelationApplicationService:
    def __init__(
        self,
        session_provider: ICorrelationSessionProvider,
        session_writer: ICorrelationSessionWriter,
        evaluator_registry: ICorrelationEvaluatorRegistry,
        max_correlation_size: int = _DEFAULT_MAX_CORRELATION_SIZE,
        default_window: timedelta = _DEFAULT_WINDOW,
    ) -> None:
        self._session_provider = session_provider
        self._session_writer = session_writer
        self._registry = evaluator_registry
        self._max_correlation_size = max_correlation_size
        self._default_window = default_window

    def correlate(self, cmd: CorrelateDetectionMatchCommand) -> CorrelationOutcome:
        _auth.require_at_least(cmd.actor_roles, CorrelationRole.EXECUTOR)
        return self._process(cmd.tenant_id, cmd.item, utc_now())

    def correlate_batch(self, cmd: CorrelateBatchCommand) -> BatchCorrelationResult:
        _auth.require_at_least(cmd.actor_roles, CorrelationRole.EXECUTOR)
        if not cmd.items:
            raise EmptyBatchCorrelationError()

        now = utc_now()
        outcomes = tuple(self._process(cmd.tenant_id, item, now) for item in cmd.items)
        succeeded = sum(1 for o in outcomes if o.status == CorrelationStatus.SUCCEEDED)

        if succeeded == len(outcomes):
            overall = CorrelationStatus.SUCCEEDED
        elif succeeded == 0:
            overall = CorrelationStatus.FAILED
        else:
            overall = CorrelationStatus.PARTIALLY_SUCCEEDED

        return BatchCorrelationResult(status=overall, outcomes=outcomes)

    def _process(
        self, tenant_id: EntityId, item: CorrelationInput, now: datetime
    ) -> CorrelationOutcome:
        rule_id = item.correlation_rule_id

        if item.canonical_event.tenant.tenant_id != tenant_id:
            failure = _to_failure(
                "tenant_validation",
                TenantContextMismatchError(tenant_id, item.canonical_event.tenant.tenant_id),
            )
            return CorrelationOutcome(
                correlation_rule_id=rule_id,
                status=CorrelationStatus.EVALUATION_REJECTED,
                failures=(failure,),
            )

        event_id = str(item.canonical_event.identity.event_id)
        if item.detection_match.event_id != event_id:
            failure = _to_failure(
                "input_validation",
                DetectionMatchEventMismatchError(item.detection_match.event_id, event_id),
            )
            return CorrelationOutcome(
                correlation_rule_id=rule_id,
                status=CorrelationStatus.EVALUATION_REJECTED,
                failures=(failure,),
            )

        session = self._session_provider.find_open_session(tenant_id, rule_id)
        if session is None:
            session = CorrelationSession.open(
                session_id=CorrelationSessionId.generate(),
                tenant_id=tenant_id,
                rule_id=rule_id,
                correlation_kind=item.correlation_kind,
                window_started_at=now,
                window_expires_at=now + self._default_window,
            )

        if session.status == CorrelationSessionStatus.MATCHED:
            return CorrelationOutcome(
                correlation_rule_id=rule_id, status=CorrelationStatus.SESSION_CLOSED
            )

        if session.status == CorrelationSessionStatus.EXPIRED or session.is_window_elapsed(now):
            if session.status != CorrelationSessionStatus.EXPIRED:
                session.expire(tenant_id, now)
                self._session_writer.write(session)
            return CorrelationOutcome(
                correlation_rule_id=rule_id, status=CorrelationStatus.SESSION_EXPIRED
            )

        if event_id in session.correlated_event_ids:
            return CorrelationOutcome(
                correlation_rule_id=rule_id, status=CorrelationStatus.DUPLICATE_EVENT
            )

        if len(session.correlated_event_ids) >= self._max_correlation_size:
            failure = _to_failure(
                "capacity",
                SessionAtCapacityError(str(session.session_id), self._max_correlation_size),
            )
            return CorrelationOutcome(
                correlation_rule_id=rule_id,
                status=CorrelationStatus.SESSION_AT_CAPACITY,
                failures=(failure,),
            )

        try:
            evaluator = self._registry.resolve(
                rule_id, item.canonical_event.metadata.schema_version
            )
        except EvaluatorSelectionError as exc:
            return CorrelationOutcome(
                correlation_rule_id=rule_id,
                status=CorrelationStatus.UNSUPPORTED_EVALUATOR,
                failures=(_to_failure("evaluator_selection", exc),),
            )

        session.accumulate(tenant_id, event_id, now)

        try:
            evaluation = evaluator.evaluate(
                correlated_event_ids=tuple(session.correlated_event_ids),
                new_match=item.detection_match,
                new_event=item.canonical_event,
            )
        except Exception as exc:
            # An untrusted evaluator's execution failure must never
            # crash the pipeline (same discipline as M43D/M44A) —
            # caught broadly and deliberately. The accumulation itself
            # still stands: the event genuinely arrived in this window.
            self._session_writer.write(session)
            return CorrelationOutcome(
                correlation_rule_id=rule_id,
                status=CorrelationStatus.FAILED,
                failures=(_to_failure("execution", exc),),
            )

        result = None
        if evaluation.matched:
            session.match(tenant_id, now)
            result = CorrelationResult(
                session_id=str(session.session_id),
                correlation_rule_id=rule_id,
                correlated_event_ids=tuple(session.correlated_event_ids),
                detection_match_refs=(f"{item.detection_match.rule_id}:{event_id}",),
                confidence=evaluation.confidence,
                reason=evaluation.reason,
                window_started_at=session.window_started_at,
                window_expires_at=session.window_expires_at,
            )

        self._session_writer.write(session)
        return CorrelationOutcome(
            correlation_rule_id=rule_id, status=CorrelationStatus.SUCCEEDED, result=result
        )
