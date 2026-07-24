"""IngestionApplicationService — the Event Ingestion Pipeline's single
application-layer entrypoint (M42 Phase 3 / M43C).

Orchestrates, in order: authorization, tenant-scoped admission
(`IIngestionRateLimiter`), `IngestedEventBatch` (M43A) admission
bookkeeping, the validation pipeline (`validation_pipeline.py`), and —
only for events that pass every stage — construction of a
`CanonicalEvent` through `CanonicalEventFactory` (M43B) and hand-off to
`ICanonicalEventReceiver`. Nothing downstream of that hand-off
(normalization, storage, detection, ...) is this service's concern.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_ingestion.application import _auth
from siem_ingestion.application.dtos.acceptance_result import (
    AcceptanceStatus,
    BatchAcceptanceResult,
    EventAcceptanceResult,
    ValidationFailure,
)
from siem_ingestion.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchSubmissionError,
)
from siem_ingestion.application.services import validation_pipeline as stages
from siem_ingestion.domain.aggregates.ingested_event_batch import IngestedEventBatch
from siem_ingestion.domain.exceptions.domain_exceptions import SiemIngestionDomainError
from siem_ingestion.domain.value_objects.enums import IngestionRole, IngestionSourceType
from siem_ingestion.domain.value_objects.identifiers import IngestedEventBatchId
from siem_ingestion.domain.value_objects.source_ref import IngestionSourceRef
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint
from siem_shared.domain.value_objects.event_source import EventSource
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from datetime import datetime

    from siem_ingestion.application.commands.ingestion_commands import (
        SubmitBatchCommand,
        SubmitEventCommand,
    )
    from siem_ingestion.application.ports.i_canonical_event_receiver import (
        ICanonicalEventReceiver,
    )
    from siem_ingestion.application.ports.i_ingestion_rate_limiter import IIngestionRateLimiter

# Errors expected from the validation/construction pipeline — caught and
# translated into a ValidationFailure, never allowed to propagate.
# `ValueError` is included because `IngestionSourceRef` (M43A) raises it
# directly for a malformed source rather than a typed domain exception.
_PIPELINE_ERRORS = (
    ApplicationValidationError,
    SiemSharedDomainError,
    SiemIngestionDomainError,
    ValueError,
)


def _build_source_ref(cmd: SubmitEventCommand) -> IngestionSourceRef:
    """The admission-level source reference (M43A's provisional shape),
    built straight from the raw command — this is the *first* real
    validation stage, since `IngestedEventBatch` needs a valid source
    before it can even be constructed. A malformed source here (e.g. a
    connector-shaped source missing its connector id) fails exactly the
    same way the CEM's own `EventSource` would fail later, just earlier —
    there is no separate, weaker admission-time check."""
    return IngestionSourceRef(
        source_type=IngestionSourceType(cmd.source_type.value),
        vendor=cmd.vendor,
        source_connector_id=cmd.source_connector_id,
    )


def _to_failure(stage: str, exc: Exception) -> ValidationFailure:
    return ValidationFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


_DEFAULT_SUPPORTED_SCHEMA_VERSION = SchemaVersion(1, 0)


class IngestionApplicationService:
    def __init__(
        self,
        rate_limiter: IIngestionRateLimiter,
        receiver: ICanonicalEventReceiver,
        supported_schema_version: SchemaVersion = _DEFAULT_SUPPORTED_SCHEMA_VERSION,
    ) -> None:
        self._rate_limiter = rate_limiter
        self._receiver = receiver
        self._supported_schema_version = supported_schema_version

    def submit_event(self, cmd: SubmitEventCommand) -> EventAcceptanceResult:
        _auth.require_at_least(cmd.actor_roles, IngestionRole.SUBMITTER)
        now = utc_now()

        try:
            source_ref = _build_source_ref(cmd)
        except _PIPELINE_ERRORS as exc:
            return EventAcceptanceResult(
                status=AcceptanceStatus.VALIDATION_FAILED,
                failures=(_to_failure("event_source", exc),),
            )

        batch = IngestedEventBatch.receive(
            batch_id=IngestedEventBatchId.generate(),
            tenant_id=cmd.tenant_id,
            source=source_ref,
            batch_fingerprint=cmd.fingerprint_raw or _default_batch_fingerprint(cmd, now),
            event_count=1,
            now=now,
        )

        if not self._rate_limiter.check_and_consume(cmd.tenant_id, 1):
            batch.throttle(cmd.tenant_id, "tenant quota exceeded", now)
            return EventAcceptanceResult(status=AcceptanceStatus.RATE_LIMITED)

        result = self._process_event(cmd, now)
        if result.status == AcceptanceStatus.ACCEPTED:
            batch.admit(cmd.tenant_id, now)
        else:
            batch.reject(cmd.tenant_id, now)
        return result

    def submit_batch(self, cmd: SubmitBatchCommand) -> BatchAcceptanceResult:
        _auth.require_at_least(cmd.actor_roles, IngestionRole.SUBMITTER)
        if not cmd.events:
            raise EmptyBatchSubmissionError()
        now = utc_now()

        try:
            first_source_ref = _build_source_ref(cmd.events[0])
        except _PIPELINE_ERRORS as exc:
            return BatchAcceptanceResult(
                status=AcceptanceStatus.VALIDATION_FAILED,
                results=(
                    EventAcceptanceResult(
                        status=AcceptanceStatus.VALIDATION_FAILED,
                        failures=(_to_failure("event_source", exc),),
                    ),
                ),
            )

        batch = IngestedEventBatch.receive(
            batch_id=IngestedEventBatchId.generate(),
            tenant_id=cmd.tenant_id,
            source=first_source_ref,
            batch_fingerprint=cmd.batch_fingerprint
            or _default_batch_fingerprint(cmd.events[0], now),
            event_count=len(cmd.events),
            now=now,
        )

        if not self._rate_limiter.check_and_consume(cmd.tenant_id, len(cmd.events)):
            batch.throttle(cmd.tenant_id, "tenant quota exceeded", now)
            return BatchAcceptanceResult(status=AcceptanceStatus.RATE_LIMITED)

        results: list[EventAcceptanceResult] = []
        for event_cmd in cmd.events:
            try:
                stages.validate_batch_tenant_consistency(cmd.tenant_id, event_cmd.tenant_id)
            except _PIPELINE_ERRORS as exc:
                results.append(
                    EventAcceptanceResult(
                        status=AcceptanceStatus.VALIDATION_FAILED,
                        failures=(_to_failure("tenant_context", exc),),
                    )
                )
                continue
            results.append(self._process_event(event_cmd, now))

        accepted = sum(1 for r in results if r.status == AcceptanceStatus.ACCEPTED)
        if accepted == len(results):
            batch.admit(cmd.tenant_id, now)
            overall = AcceptanceStatus.ACCEPTED
        elif accepted == 0:
            batch.reject(cmd.tenant_id, now)
            overall = AcceptanceStatus.VALIDATION_FAILED
        else:
            batch.admit(cmd.tenant_id, now)
            overall = AcceptanceStatus.PARTIALLY_ACCEPTED

        return BatchAcceptanceResult(status=overall, results=tuple(results))

    def _process_event(self, cmd: SubmitEventCommand, now: datetime) -> EventAcceptanceResult:
        try:
            stages.validate_required_fields(cmd)
            stages.validate_timestamp_sanity(cmd.occurred_at, now)
            category = stages.validate_event_category(cmd.category_raw)
            outcome = stages.validate_event_outcome(cmd.outcome_raw)
            severity = stages.validate_event_severity(cmd.severity_raw)
            stages.validate_payload_size(cmd.attributes)
            schema_version = SchemaVersion.parse(cmd.schema_version_raw)
            stages.validate_schema_compatibility(schema_version, self._supported_schema_version)
            source = EventSource(
                source_type=cmd.source_type,
                vendor=cmd.vendor,
                source_connector_id=cmd.source_connector_id,
            )

            canonical_event = build_canonical_event(
                tenant_id=cmd.tenant_id,
                source=source,
                category=category,
                outcome=outcome,
                occurred_at=cmd.occurred_at,
                schema_version=schema_version,
                event_id=cmd.event_id,
                fingerprint=(
                    EventFingerprint(cmd.fingerprint_raw) if cmd.fingerprint_raw else None
                ),
                ingested_at=now,
                severity=severity,
                actor=cmd.actor,
                target=cmd.target,
                attributes=cmd.attributes,
                raw_payload_ref=cmd.raw_payload_ref,
            )
        except _PIPELINE_ERRORS as exc:
            return EventAcceptanceResult(
                status=AcceptanceStatus.VALIDATION_FAILED,
                failures=(_to_failure("construction", exc),),
            )

        self._receiver.receive(canonical_event)
        return EventAcceptanceResult(
            status=AcceptanceStatus.ACCEPTED, canonical_event=canonical_event
        )


def _default_batch_fingerprint(cmd: SubmitEventCommand, now: datetime) -> str:
    return str(
        EventFingerprint.compute(
            cmd.vendor, cmd.source_type.value, str(cmd.tenant_id), now.isoformat()
        )
    )
