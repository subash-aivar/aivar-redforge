"""AlertApplicationService — the Alert Engine's single application-layer
entrypoint (M42 Phase 8 / M44C).

Orchestrates, in order: authorization, evaluator selection
(`IAlertEvaluatorRegistry`) for evaluation-driven creation, execution,
`Alert.raise_alert()` (M43A, reused verbatim), suppression (only when
the evaluator explicitly decided it), and deduplication against any
existing non-`CLOSED` alert sharing the same dedup key
(`IAlertProvider`) — all via `Alert`'s own lifecycle methods, never a
parallel implementation. This service never opens an Investigation,
never scores risk, and holds no state of its own between calls; every
alert is handed to `IAlertWriter` immediately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_alerting.application import _auth
from siem_alerting.application.dtos.alert_outcome import (
    AlertFailure,
    AlertOutcome,
    AlertOutcomeStatus,
    BatchAlertResult,
)
from siem_alerting.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchAlertEvaluationError,
    EvaluatorSelectionError,
)
from siem_alerting.domain.aggregates.alert import Alert
from siem_alerting.domain.exceptions.domain_exceptions import SiemAlertingDomainError
from siem_alerting.domain.value_objects.enums import AlertEngineRole, AlertSourceKind, AlertStatus
from siem_alerting.domain.value_objects.identifiers import AlertId
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_alerting.application.commands.alert_commands import (
        AlertEvaluationInput,
        CreateAlertCommand,
        EvaluateBatchCommand,
        EvaluateCorrelationResultCommand,
    )
    from siem_alerting.application.ports.i_alert_evaluator_registry import IAlertEvaluatorRegistry
    from siem_alerting.application.ports.i_alert_provider import IAlertProvider
    from siem_alerting.application.ports.i_alert_writer import IAlertWriter
    from siem_alerting.domain.value_objects.enums import AlertSeverity

_VALIDATION_ERRORS = (ApplicationValidationError, SiemAlertingDomainError, SiemSharedDomainError)
_ERROR_STATUSES = frozenset({AlertOutcomeStatus.FAILED, AlertOutcomeStatus.UNSUPPORTED_EVALUATOR})


def _to_failure(stage: str, exc: Exception) -> AlertFailure:
    return AlertFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class AlertApplicationService:
    def __init__(
        self,
        alert_provider: IAlertProvider,
        alert_writer: IAlertWriter,
        evaluator_registry: IAlertEvaluatorRegistry,
    ) -> None:
        self._alert_provider = alert_provider
        self._alert_writer = alert_writer
        self._registry = evaluator_registry

    def create_alert(self, cmd: CreateAlertCommand) -> AlertOutcome:
        _auth.require_at_least(cmd.actor_roles, AlertEngineRole.EXECUTOR)
        return self._create_and_resolve(
            tenant_id=cmd.tenant_id,
            dedup_key=cmd.dedup_key,
            severity=cmd.severity,
            source_kind=cmd.source_kind,
            source_ref=cmd.source_ref,
            suppress=False,
            suppression_reason=None,
            decision_reason=None,
            now=utc_now(),
        )

    def evaluate_correlation_result(self, cmd: EvaluateCorrelationResultCommand) -> AlertOutcome:
        _auth.require_at_least(cmd.actor_roles, AlertEngineRole.EXECUTOR)
        return self._process(cmd.tenant_id, cmd.item, utc_now())

    def evaluate_batch(self, cmd: EvaluateBatchCommand) -> BatchAlertResult:
        _auth.require_at_least(cmd.actor_roles, AlertEngineRole.EXECUTOR)
        if not cmd.items:
            raise EmptyBatchAlertEvaluationError()

        now = utc_now()
        outcomes = tuple(self._process(cmd.tenant_id, item, now) for item in cmd.items)
        errored = sum(1 for o in outcomes if o.status in _ERROR_STATUSES)

        if errored == 0:
            overall = AlertOutcomeStatus.SUCCEEDED
        elif errored == len(outcomes):
            overall = AlertOutcomeStatus.FAILED
        else:
            overall = AlertOutcomeStatus.PARTIALLY_SUCCEEDED

        return BatchAlertResult(status=overall, outcomes=outcomes)

    def _process(
        self, tenant_id: EntityId, item: AlertEvaluationInput, now: datetime
    ) -> AlertOutcome:
        try:
            schema_version = SchemaVersion.parse(item.schema_version_raw)
        except _VALIDATION_ERRORS as exc:
            return AlertOutcome(
                status=AlertOutcomeStatus.REJECTED,
                failures=(_to_failure("schema_version_parse", exc),),
            )

        try:
            evaluator = self._registry.resolve(item.alert_rule_id, schema_version)
        except EvaluatorSelectionError as exc:
            return AlertOutcome(
                status=AlertOutcomeStatus.UNSUPPORTED_EVALUATOR,
                failures=(_to_failure("evaluator_selection", exc),),
            )

        try:
            evaluation = evaluator.evaluate(item.correlation_result)
        except Exception as exc:
            # An untrusted evaluator's execution failure must never
            # crash the pipeline (same discipline as M44A/M44B) —
            # caught broadly and deliberately.
            return AlertOutcome(
                status=AlertOutcomeStatus.FAILED, failures=(_to_failure("execution", exc),)
            )

        if not evaluation.should_alert:
            return AlertOutcome(
                status=AlertOutcomeStatus.REJECTED, decision_reason=evaluation.reason
            )

        dedup_key = (
            f"{item.alert_rule_id}:{item.correlation_result.correlation_rule_id}:"
            f"{item.correlation_result.session_id}"
        )
        return self._create_and_resolve(
            tenant_id=tenant_id,
            dedup_key=dedup_key,
            severity=evaluation.severity,
            source_kind=AlertSourceKind.CORRELATION,
            source_ref=item.correlation_result.session_id,
            suppress=evaluation.suppress,
            suppression_reason=evaluation.suppression_reason,
            decision_reason=evaluation.reason,
            now=now,
        )

    def _create_and_resolve(
        self,
        *,
        tenant_id: EntityId,
        dedup_key: str,
        severity: AlertSeverity,
        source_kind: AlertSourceKind,
        source_ref: str,
        suppress: bool,
        suppression_reason: str | None,
        decision_reason: str | None,
        now: datetime,
    ) -> AlertOutcome:
        try:
            alert = Alert.raise_alert(
                alert_id=AlertId.generate(),
                tenant_id=tenant_id,
                dedup_key=dedup_key,
                severity=severity,
                source_kind=source_kind,
                source_ref=source_ref,
                now=now,
            )
        except _VALIDATION_ERRORS as exc:
            return AlertOutcome(
                status=AlertOutcomeStatus.REJECTED,
                dedup_key=dedup_key,
                failures=(_to_failure("alert_creation", exc),),
            )

        if suppress:
            alert.suppress(tenant_id, suppression_reason or "", now)
            self._alert_writer.write(alert)
            return AlertOutcome(
                status=AlertOutcomeStatus.SUPPRESSED,
                alert_id=str(alert.alert_id),
                dedup_key=dedup_key,
                decision_reason=decision_reason,
            )

        existing = self._alert_provider.find_by_dedup_key(tenant_id, dedup_key)
        if existing is not None and existing.status != AlertStatus.CLOSED:
            alert.deduplicate(tenant_id, str(existing.alert_id), now)
            self._alert_writer.write(alert)
            return AlertOutcome(
                status=AlertOutcomeStatus.DEDUPLICATED,
                alert_id=str(alert.alert_id),
                dedup_key=dedup_key,
                original_alert_id=str(existing.alert_id),
                decision_reason=decision_reason,
            )

        self._alert_writer.write(alert)
        return AlertOutcome(
            status=AlertOutcomeStatus.CREATED,
            alert_id=str(alert.alert_id),
            dedup_key=dedup_key,
            decision_reason=decision_reason,
        )
