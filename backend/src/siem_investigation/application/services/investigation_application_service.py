"""InvestigationApplicationService — the Investigation Engine's single
application-layer entrypoint (M42 Phase 9 / M44D).

Orchestrates, in order: authorization, loading any open
`InvestigationTimeline` for the target scope (`IInvestigationProvider`
— a closed investigation is simply never returned, mirroring M44C's
identical "closed Alert never deduplicated against" pattern),
`InvestigationTimeline.create()`/`.add_entry()` (M43A, reused
verbatim — this service never touches `.entries` or any other field
directly), and — for evaluation-driven attachment — evaluator
selection (`IInvestigationEvaluatorRegistry`) and execution. This
service never calculates risk, never scores executively, and holds no
state of its own between calls; every timeline mutation is handed to
`IInvestigationWriter` immediately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_investigation.application import _auth
from siem_investigation.application.dtos.investigation_outcome import (
    BatchInvestigationResult,
    InvestigationFailure,
    InvestigationOutcome,
    InvestigationOutcomeStatus,
)
from siem_investigation.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchInvestigationError,
    EvaluatorSelectionError,
    InvestigationAlreadyOpenError,
    TenantContextMismatchError,
)
from siem_investigation.domain.aggregates.investigation_timeline import InvestigationTimeline
from siem_investigation.domain.exceptions.domain_exceptions import SiemInvestigationDomainError
from siem_investigation.domain.value_objects.enums import InvestigationEngineRole
from siem_investigation.domain.value_objects.identifiers import InvestigationTimelineId
from siem_investigation.domain.value_objects.timeline_entry import TimelineEntry
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_alerting.domain.aggregates.alert import Alert
    from siem_investigation.application.commands.investigation_commands import (
        AttachAlertCommand,
        EvaluateAlertCommand,
        EvaluateBatchCommand,
        InvestigationEvaluationInput,
        OpenInvestigationCommand,
    )
    from siem_investigation.application.ports.i_investigation_evaluator_registry import (
        IInvestigationEvaluatorRegistry,
    )
    from siem_investigation.application.ports.i_investigation_provider import (
        IInvestigationProvider,
    )
    from siem_investigation.application.ports.i_investigation_writer import (
        IInvestigationWriter,
    )
    from siem_investigation.domain.value_objects.enums import TimelineScopeType

_VALIDATION_ERRORS = (
    ApplicationValidationError,
    SiemInvestigationDomainError,
    SiemSharedDomainError,
    ValueError,
)
_ERROR_STATUSES = frozenset(
    {InvestigationOutcomeStatus.FAILED, InvestigationOutcomeStatus.UNSUPPORTED_EVALUATOR}
)


def _to_failure(stage: str, exc: Exception) -> InvestigationFailure:
    return InvestigationFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class InvestigationApplicationService:
    def __init__(
        self,
        investigation_provider: IInvestigationProvider,
        investigation_writer: IInvestigationWriter,
        evaluator_registry: IInvestigationEvaluatorRegistry,
    ) -> None:
        self._provider = investigation_provider
        self._writer = investigation_writer
        self._registry = evaluator_registry

    def open_investigation(self, cmd: OpenInvestigationCommand) -> InvestigationOutcome:
        _auth.require_at_least(cmd.actor_roles, InvestigationEngineRole.EXECUTOR)
        existing = self._provider.find_open_timeline(cmd.tenant_id, cmd.scope_type, cmd.scope_ref)
        if existing is not None:
            failure = _to_failure(
                "lifecycle",
                InvestigationAlreadyOpenError(cmd.scope_type, cmd.scope_ref),
            )
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED, failures=(failure,)
            )

        try:
            timeline = InvestigationTimeline.create(
                timeline_id=InvestigationTimelineId.generate(),
                tenant_id=cmd.tenant_id,
                scope_type=cmd.scope_type,
                scope_ref=cmd.scope_ref,
            )
        except _VALIDATION_ERRORS as exc:
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED,
                failures=(_to_failure("timeline_creation", exc),),
            )

        self._writer.write(timeline)
        return InvestigationOutcome(
            status=InvestigationOutcomeStatus.OPENED,
            timeline_id=str(timeline.timeline_id),
            scope_ref=timeline.scope_ref,
            entry_count=len(timeline.entries),
        )

    def attach_alert(self, cmd: AttachAlertCommand) -> InvestigationOutcome:
        _auth.require_at_least(cmd.actor_roles, InvestigationEngineRole.EXECUTOR)
        if cmd.alert.tenant_id != cmd.tenant_id:
            failure = _to_failure(
                "tenant_validation",
                TenantContextMismatchError(cmd.tenant_id, cmd.alert.tenant_id),
            )
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED, failures=(failure,)
            )

        summary = f"Alert {cmd.alert.alert_id} ({cmd.alert.severity.value}): {cmd.alert.dedup_key}"
        return self._attach(
            cmd.tenant_id, cmd.scope_type, cmd.scope_ref, cmd.alert, summary, utc_now()
        )

    def evaluate_alert(self, cmd: EvaluateAlertCommand) -> InvestigationOutcome:
        _auth.require_at_least(cmd.actor_roles, InvestigationEngineRole.EXECUTOR)
        return self._process(cmd.tenant_id, cmd.item, utc_now())

    def evaluate_batch(self, cmd: EvaluateBatchCommand) -> BatchInvestigationResult:
        _auth.require_at_least(cmd.actor_roles, InvestigationEngineRole.EXECUTOR)
        if not cmd.items:
            raise EmptyBatchInvestigationError()

        now = utc_now()
        outcomes = tuple(self._process(cmd.tenant_id, item, now) for item in cmd.items)
        errored = sum(1 for o in outcomes if o.status in _ERROR_STATUSES)

        if errored == 0:
            overall = InvestigationOutcomeStatus.SUCCEEDED
        elif errored == len(outcomes):
            overall = InvestigationOutcomeStatus.FAILED
        else:
            overall = InvestigationOutcomeStatus.PARTIALLY_SUCCEEDED

        return BatchInvestigationResult(status=overall, outcomes=outcomes)

    def _process(
        self, tenant_id: EntityId, item: InvestigationEvaluationInput, now: datetime
    ) -> InvestigationOutcome:
        try:
            schema_version = SchemaVersion.parse(item.schema_version_raw)
        except _VALIDATION_ERRORS as exc:
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED,
                failures=(_to_failure("schema_version_parse", exc),),
            )

        try:
            evaluator = self._registry.resolve(item.investigation_rule_id, schema_version)
        except EvaluatorSelectionError as exc:
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.UNSUPPORTED_EVALUATOR,
                failures=(_to_failure("evaluator_selection", exc),),
            )

        try:
            evaluation = evaluator.evaluate(item.alert)
        except Exception as exc:
            # An untrusted evaluator's execution failure must never
            # crash the pipeline (same discipline as M44A/M44B/M44C) —
            # caught broadly and deliberately.
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.FAILED,
                failures=(_to_failure("execution", exc),),
            )

        if not evaluation.should_investigate:
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED, decision_reason=evaluation.reason
            )

        return self._attach(
            tenant_id,
            evaluation.scope_type,
            evaluation.scope_ref,
            item.alert,
            evaluation.summary,
            now,
            decision_reason=evaluation.reason,
        )

    def _attach(
        self,
        tenant_id: EntityId,
        scope_type: TimelineScopeType,
        scope_ref: str,
        alert: Alert,
        summary: str,
        now: datetime,
        decision_reason: str | None = None,
    ) -> InvestigationOutcome:
        timeline = self._provider.find_open_timeline(tenant_id, scope_type, scope_ref)
        opened = timeline is None

        try:
            if timeline is None:
                timeline = InvestigationTimeline.create(
                    timeline_id=InvestigationTimelineId.generate(),
                    tenant_id=tenant_id,
                    scope_type=scope_type,
                    scope_ref=scope_ref,
                )
            entry = TimelineEntry(
                event_id=str(alert.alert_id),
                occurred_at=alert.raised_at,
                category=f"alert:{alert.source_kind.value}",
                summary=summary,
            )
            timeline.add_entry(tenant_id, entry)
        except _VALIDATION_ERRORS as exc:
            return InvestigationOutcome(
                status=InvestigationOutcomeStatus.REJECTED,
                failures=(_to_failure("timeline_attachment", exc),),
                decision_reason=decision_reason,
            )

        self._writer.write(timeline)
        status = (
            InvestigationOutcomeStatus.OPENED if opened else InvestigationOutcomeStatus.UPDATED
        )
        return InvestigationOutcome(
            status=status,
            timeline_id=str(timeline.timeline_id),
            scope_ref=timeline.scope_ref,
            entry_count=len(timeline.entries),
            decision_reason=decision_reason,
        )
