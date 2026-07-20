"""Execution + Finding application service — Phase 3 use cases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from detection.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from detection.application.dtos.execution_finding_dtos import (
    DetectionExecutionDTO,
    DetectionFindingDTO,
    ExecutionPageDTO,
    FindingPageDTO,
)
from detection.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.domain.aggregates.detection_execution import DetectionExecution
from detection.domain.exceptions.domain_exceptions import (
    ExecutionLifecycleBlocked,
    FindingLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from detection.domain.services.finding_dedup import FindingDeduplicator
from detection.domain.value_objects.enums import (
    ExecutionState,
    ExecutionTrigger,
    FindingConfidence,
    FindingSeverity,
)
from detection.domain.value_objects.execution_finding import (
    AnalystNote,
    AssetRef,
    DedupWindow,
    DetectionExecutionRef,
    DetectionRuleRef,
    EscalationRef,
    ExecutionError,
    ExecutionStats,
    ExecutionWindow,
    FindingKey,
    MitreAttackRef,
    TelemetryFingerprint,
    TelemetrySignalRef,
)
from detection.domain.value_objects.identifiers import (
    DetectionExecutionId,
    DetectionFindingId,
    DetectionRuleId,
    TenantId,
)
from detection.domain.value_objects.keys import TelemetrySourceRef
from detection.infrastructure.persistence.serialization import (
    analyst_note_to_json,
    correlation_to_json,
    escalation_to_json,
    execution_error_to_json,
    execution_stats_to_json,
    mitre_ref_to_json,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.commands.execution_finding_commands import (
        ConfirmFinding,
        EscalateFindingToInvestigation,
        MarkFindingFalsePositive,
        ProduceFinding,
        RecordExecutionResult,
        ScheduleRuleExecution,
        SuppressFinding,
        TriageFinding,
    )
    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.application.queries.execution_finding_queries import (
        GetExecution,
        GetFinding,
        ListExecutions,
        ListFindings,
    )

logger = logging.getLogger(__name__)


class ExecutionFindingApplicationService:
    """Orchestrates execution lifecycle, finding production, and triage."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def _publish(self, aggregates: list[Any]) -> None:
        events: list[Any] = []
        for aggregate in aggregates:
            events.extend(aggregate.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    def _map_invalid(self, exc: InvalidArgument) -> ApplicationValidationError:
        return ApplicationValidationError(exc.name, exc.message)

    def _parse_dt(self, value: str, field: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ApplicationValidationError(field, str(exc)) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed

    def _execution_dto(self, execution: DetectionExecution) -> DetectionExecutionDTO:
        return DetectionExecutionDTO(
            id=str(execution.execution_id),
            tenant_id=str(execution.tenant_id),
            rule_id=execution.rule_ref.rule_id,
            rule_version=execution.rule_ref.rule_version,
            source_id=execution.source_ref.source_id,
            source_type=execution.source_ref.source_type,
            window_start=execution.window.start_time.isoformat(),
            window_end=execution.window.end_time.isoformat(),
            state=execution.state.value,
            trigger=execution.trigger.value,
            stats=execution_stats_to_json(execution.stats),
            error=execution_error_to_json(execution.error),
            finding_refs=[str(f) for f in execution.finding_refs],
            scheduled_at=execution.scheduled_at.isoformat(),
            started_at=execution.started_at.isoformat() if execution.started_at else None,
            completed_at=(
                execution.completed_at.isoformat() if execution.completed_at else None
            ),
            version=execution.version,
        )

    def _finding_dto(
        self, finding: Any, *, deduplicated: bool = False
    ) -> DetectionFindingDTO:
        return DetectionFindingDTO(
            id=str(finding.finding_id),
            tenant_id=str(finding.tenant_id),
            finding_key=str(finding.finding_key),
            rule_id=finding.rule_ref.rule_id,
            rule_version=finding.rule_ref.rule_version,
            execution_id=finding.execution_ref.execution_id,
            asset_id=finding.asset_ref.asset_id,
            asset_type=finding.asset_ref.asset_type,
            signal_id=finding.telemetry_signal.signal_id,
            telemetry_fingerprint=str(finding.telemetry_fingerprint),
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            state=finding.state.value,
            observed_at=finding.observed_at.isoformat(),
            detected_at=finding.detected_at.isoformat(),
            last_seen_at=finding.last_seen_at.isoformat(),
            mitre=mitre_ref_to_json(finding.mitre_ref),
            correlation=correlation_to_json(finding.correlation),
            analyst_note=analyst_note_to_json(finding.analyst_note),
            escalation=escalation_to_json(finding.escalation_ref),
            reopened_from=(
                str(finding.reopened_from) if finding.reopened_from else None
            ),
            version=finding.version,
            deduplicated=deduplicated,
        )

    async def schedule_rule_execution(
        self, cmd: ScheduleRuleExecution
    ) -> DetectionExecutionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_str(cmd.source_id, "source_id", max_len=64)
        tenant_id = TenantId(cmd.tenant_id)
        rule_id = DetectionRuleId(cmd.rule_id)
        try:
            trigger = ExecutionTrigger(cmd.trigger)
        except ValueError as exc:
            raise ApplicationValidationError("trigger", str(exc)) from exc
        start = self._parse_dt(cmd.window_start, "window_start")
        end = self._parse_dt(cmd.window_end, "window_end")
        try:
            window = ExecutionWindow(start_time=start, end_time=end)
            rule_ref = DetectionRuleRef(
                rule_id=str(rule_id), rule_version=cmd.rule_version
            )
            source_ref = TelemetrySourceRef(
                source_id=cmd.source_id, source_type=cmd.source_type
            )
        except InvalidArgument as exc:
            raise self._map_invalid(exc) from exc

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            rule = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if rule is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            execution = DetectionExecution.schedule(
                tenant_id=tenant_id,
                rule_ref=rule_ref,
                source_ref=source_ref,
                window=window,
                trigger=trigger,
                now=now,
            )
            await uow.detection_executions.save(execution)
            await uow.commit()
            await self._publish([execution])
            return self._execution_dto(execution)

    async def record_execution_result(
        self, cmd: RecordExecutionResult
    ) -> DetectionExecutionDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.execution_id, "execution_id")
        tenant_id = TenantId(cmd.tenant_id)
        execution_id = DetectionExecutionId(cmd.execution_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            execution = await uow.detection_executions.find_by_id(
                execution_id, tenant_id
            )
            if execution is None:
                raise ApplicationNotFoundError("DetectionExecution", str(execution_id))
            try:
                if cmd.timed_out:
                    execution.timeout(
                        tenant_id=tenant_id,
                        duration_ms=cmd.duration_ms,
                        now=now,
                    )
                elif cmd.failed:
                    if not cmd.error_type or not cmd.error_message:
                        raise ApplicationValidationError(
                            "error", "error_type and error_message required on failure"
                        )
                    execution.fail(
                        tenant_id=tenant_id,
                        error=ExecutionError(
                            error_type=cmd.error_type,
                            error_message=cmd.error_message,
                        ),
                        now=now,
                    )
                else:
                    finding_refs = [
                        DetectionFindingId(fid) for fid in (cmd.finding_ids or [])
                    ]
                    execution.record_result(
                        tenant_id=tenant_id,
                        stats=ExecutionStats(
                            telemetry_records_evaluated=cmd.telemetry_records_evaluated,
                            findings_produced=cmd.findings_produced,
                            duration_ms=cmd.duration_ms,
                            cpu_ms=cmd.cpu_ms,
                        ),
                        finding_refs=finding_refs,
                        now=now,
                    )
            except (
                InvalidArgument,
                InvalidStateTransition,
                ExecutionLifecycleBlocked,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise ApplicationValidationError("execution", str(exc)) from exc
            await uow.detection_executions.save(execution)
            await uow.commit()
            await self._publish([execution])
            return self._execution_dto(execution)

    async def produce_finding(self, cmd: ProduceFinding) -> DetectionFindingDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_uuid(cmd.execution_id, "execution_id")
        validate_str(cmd.asset_id, "asset_id", max_len=256)
        validate_str(cmd.signal_id, "signal_id", max_len=256)
        tenant_id = TenantId(cmd.tenant_id)
        rule_id = DetectionRuleId(cmd.rule_id)
        execution_id = DetectionExecutionId(cmd.execution_id)
        observed_at = self._parse_dt(cmd.observed_at, "observed_at")
        try:
            severity = FindingSeverity(cmd.severity)
            confidence = FindingConfidence(cmd.confidence)
        except ValueError as exc:
            raise ApplicationValidationError("severity/confidence", str(exc)) from exc

        now = datetime.now(UTC)
        fingerprint = TelemetryFingerprint.from_fields(dict(cmd.fingerprint_fields))
        finding_key = FindingKey.compute(
            rule_id=str(rule_id),
            asset_ref=cmd.asset_id,
            telemetry_fingerprint=fingerprint,
        )
        deduper = FindingDeduplicator(
            DedupWindow(duration=timedelta(seconds=cmd.dedup_window_seconds))
        )

        async with self._uow_factory() as uow:
            execution = await uow.detection_executions.find_by_id(
                execution_id, tenant_id
            )
            if execution is None:
                raise ApplicationNotFoundError("DetectionExecution", str(execution_id))
            if execution.state in {
                ExecutionState.FAILED,
                ExecutionState.TIMEDOUT,
                ExecutionState.SKIPPED,
            }:
                raise ApplicationValidationError(
                    "execution",
                    f"cannot produce findings for {execution.state.value} execution",
                )

            existing = await uow.detection_findings.find_by_key(finding_key, tenant_id)
            mitre = None
            if cmd.technique_id or cmd.tactic:
                mitre = MitreAttackRef(
                    tactic=cmd.tactic, technique_id=cmd.technique_id
                )
            try:
                decision = deduper.decide(
                    existing=existing,
                    now=now,
                    tenant_id=tenant_id,
                    finding_key=finding_key,
                    rule_ref=DetectionRuleRef(
                        rule_id=str(rule_id), rule_version=cmd.rule_version
                    ),
                    execution_ref=DetectionExecutionRef(
                        execution_id=str(execution_id)
                    ),
                    asset_ref=AssetRef(
                        asset_id=cmd.asset_id, asset_type=cmd.asset_type
                    ),
                    telemetry_signal=TelemetrySignalRef(
                        signal_id=cmd.signal_id, source_id=cmd.signal_source_id
                    ),
                    telemetry_fingerprint=fingerprint,
                    severity=severity,
                    confidence=confidence,
                    observed_at=observed_at,
                    mitre_ref=mitre,
                )
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc

            await uow.detection_findings.save(decision.finding)
            if decision.created:
                execution.add_finding_ref(
                    tenant_id=tenant_id,
                    finding_id=decision.finding.finding_id,
                    now=now,
                )
                await uow.detection_executions.save(execution)
            await uow.commit()
            to_publish: list[Any] = [decision.finding]
            if decision.created:
                to_publish.append(execution)
            await self._publish(to_publish)
            return self._finding_dto(
                decision.finding, deduplicated=decision.deduplicated
            )

    async def triage_finding(self, cmd: TriageFinding) -> DetectionFindingDTO:
        return await self._lifecycle(
            cmd.tenant_id,
            cmd.finding_id,
            lambda f, tid, now: f.triage(
                tenant_id=tid,
                analyst=cmd.analyst,
                note=AnalystNote(text=cmd.note) if cmd.note else None,
                now=now,
            ),
        )

    async def confirm_finding(self, cmd: ConfirmFinding) -> DetectionFindingDTO:
        return await self._lifecycle(
            cmd.tenant_id,
            cmd.finding_id,
            lambda f, tid, now: f.confirm(
                tenant_id=tid, analyst=cmd.analyst, now=now
            ),
        )

    async def mark_finding_false_positive(
        self, cmd: MarkFindingFalsePositive
    ) -> DetectionFindingDTO:
        return await self._lifecycle(
            cmd.tenant_id,
            cmd.finding_id,
            lambda f, tid, now: f.mark_false_positive(
                tenant_id=tid,
                analyst=cmd.analyst,
                justification=cmd.justification,
                now=now,
            ),
        )

    async def suppress_finding(self, cmd: SuppressFinding) -> DetectionFindingDTO:
        return await self._lifecycle(
            cmd.tenant_id,
            cmd.finding_id,
            lambda f, tid, now: f.suppress(
                tenant_id=tid,
                analyst=cmd.analyst,
                justification=cmd.justification,
                now=now,
            ),
        )

    async def escalate_finding_to_investigation(
        self, cmd: EscalateFindingToInvestigation
    ) -> DetectionFindingDTO:
        now = datetime.now(UTC)
        return await self._lifecycle(
            cmd.tenant_id,
            cmd.finding_id,
            lambda f, tid, n: f.escalate(
                tenant_id=tid,
                analyst=cmd.analyst,
                escalation_ref=EscalationRef(
                    investigation_id=cmd.investigation_id, escalated_at=n
                ),
                now=n,
            ),
            now=now,
        )

    async def _lifecycle(
        self,
        tenant_uuid: UUID,
        finding_uuid: UUID,
        mutator: Any,
        now: datetime | None = None,
    ) -> DetectionFindingDTO:
        validate_uuid(tenant_uuid, "tenant_id")
        validate_uuid(finding_uuid, "finding_id")
        tenant_id = TenantId(tenant_uuid)
        finding_id = DetectionFindingId(finding_uuid)
        stamp = now or datetime.now(UTC)
        async with self._uow_factory() as uow:
            finding = await uow.detection_findings.find_by_id(finding_id, tenant_id)
            if finding is None:
                raise ApplicationNotFoundError("DetectionFinding", str(finding_id))
            try:
                mutator(finding, tenant_id, stamp)
            except (
                InvalidArgument,
                InvalidStateTransition,
                FindingLifecycleBlocked,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise ApplicationValidationError("finding", str(exc)) from exc
            await uow.detection_findings.save(finding)
            await uow.commit()
            await self._publish([finding])
            return self._finding_dto(finding)

    async def get_execution(self, query: GetExecution) -> DetectionExecutionDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.execution_id, "execution_id")
        async with self._uow_factory() as uow:
            execution = await uow.detection_executions.find_by_id(
                DetectionExecutionId(query.execution_id),
                TenantId(query.tenant_id),
            )
            if execution is None:
                raise ApplicationNotFoundError(
                    "DetectionExecution", str(query.execution_id)
                )
            return self._execution_dto(execution)

    async def list_executions(self, query: ListExecutions) -> ExecutionPageDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant_id = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            if query.state:
                try:
                    state = ExecutionState(query.state)
                except ValueError as exc:
                    raise ApplicationValidationError("state", str(exc)) from exc
                items = await uow.detection_executions.find_by_state(state, tenant_id)
                page = items[offset : offset + limit]
            else:
                page = await uow.detection_executions.list_by_tenant(
                    tenant_id, limit=limit, offset=offset
                )
            return ExecutionPageDTO(
                items=[self._execution_dto(e) for e in page],
                limit=limit,
                offset=offset,
            )

    async def get_finding(self, query: GetFinding) -> DetectionFindingDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        validate_uuid(query.finding_id, "finding_id")
        async with self._uow_factory() as uow:
            finding = await uow.detection_findings.find_by_id(
                DetectionFindingId(query.finding_id),
                TenantId(query.tenant_id),
            )
            if finding is None:
                raise ApplicationNotFoundError(
                    "DetectionFinding", str(query.finding_id)
                )
            return self._finding_dto(finding)

    async def list_findings(self, query: ListFindings) -> FindingPageDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        tenant_id = TenantId(query.tenant_id)
        async with self._uow_factory() as uow:
            if query.asset_id:
                items = await uow.detection_findings.find_by_asset(
                    query.asset_id, tenant_id, limit=limit, offset=offset
                )
            elif query.open_only:
                items = await uow.detection_findings.find_open_by_tenant(
                    tenant_id, limit=limit, offset=offset
                )
            else:
                items = await uow.detection_findings.list_by_tenant(
                    tenant_id, limit=limit, offset=offset
                )
            return FindingPageDTO(
                items=[self._finding_dto(f) for f in items],
                limit=limit,
                offset=offset,
            )
