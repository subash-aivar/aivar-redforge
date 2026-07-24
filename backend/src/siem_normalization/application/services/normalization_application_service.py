"""NormalizationApplicationService — the Event Normalization Framework's
single application-layer entrypoint (M42 Phase 4 / M43D).

Orchestrates, in order: authorization, pre-lookup request validation,
deterministic normalizer selection (`IEventNormalizerRegistry`),
execution of the selected `IEventNormalizer`, and — only for a mapping
that succeeds — construction of a `CanonicalEvent` through
`CanonicalEventFactory` (M43B) and hand-off to `ICanonicalEventReceiver`.
This service contains no provider-specific logic anywhere: it never
inspects `raw_payload`'s shape itself, only routes it to whatever the
registry resolves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_normalization.application import _auth
from siem_normalization.application.dtos.normalization_result import (
    BatchNormalizationResult,
    NormalizationFailure,
    NormalizationResult,
    NormalizationStatus,
)
from siem_normalization.application.exceptions import (
    AmbiguousNormalizerSelectionError,
    ApplicationValidationError,
    EmptyBatchNormalizationError,
    MissingRequiredFieldError,
    UnsupportedProviderError,
    UnsupportedVersionError,
)
from siem_normalization.domain.services.normalization_outcome_factory import (
    build_events_normalized,
    build_normalization_failed,
)
from siem_normalization.domain.value_objects.enums import (
    NormalizationFailureReason,
    NormalizationRole,
)
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.event_source import EventSource
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from datetime import datetime

    from siem_normalization.application.commands.normalization_commands import (
        NormalizeBatchCommand,
        NormalizeEventCommand,
    )
    from siem_normalization.application.ports.i_canonical_event_receiver import (
        ICanonicalEventReceiver,
    )
    from siem_normalization.application.ports.i_event_normalizer_registry import (
        IEventNormalizerRegistry,
    )

_REQUEST_VALIDATION_ERRORS = (ApplicationValidationError, SiemSharedDomainError, ValueError)


def _to_failure(stage: str, exc: Exception) -> NormalizationFailure:
    return NormalizationFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class NormalizationApplicationService:
    def __init__(
        self,
        registry: IEventNormalizerRegistry,
        receiver: ICanonicalEventReceiver,
    ) -> None:
        self._registry = registry
        self._receiver = receiver

    def normalize_event(self, cmd: NormalizeEventCommand) -> NormalizationResult:
        _auth.require_at_least(cmd.actor_roles, NormalizationRole.EXECUTOR)
        now = utc_now()
        return self._process_event(cmd, now)

    def normalize_batch(self, cmd: NormalizeBatchCommand) -> BatchNormalizationResult:
        _auth.require_at_least(cmd.actor_roles, NormalizationRole.EXECUTOR)
        if not cmd.events:
            raise EmptyBatchNormalizationError()
        now = utc_now()

        results = tuple(self._process_event(event_cmd, now) for event_cmd in cmd.events)
        normalized = sum(1 for r in results if r.status == NormalizationStatus.NORMALIZED)

        if normalized == len(results):
            overall = NormalizationStatus.NORMALIZED
        elif normalized == 0:
            overall = NormalizationStatus.FAILED_NORMALIZATION
        else:
            overall = NormalizationStatus.PARTIALLY_NORMALIZED

        return BatchNormalizationResult(status=overall, results=results)

    def _process_event(self, cmd: NormalizeEventCommand, now: datetime) -> NormalizationResult:
        try:
            requested_version = self._validate_request(cmd)
        except _REQUEST_VALIDATION_ERRORS as exc:
            return NormalizationResult(
                status=NormalizationStatus.REJECTED,
                failures=(_to_failure("request_validation", exc),),
            )

        try:
            normalizer = self._registry.resolve(cmd.provider, requested_version)
        except UnsupportedProviderError as exc:
            return NormalizationResult(
                status=NormalizationStatus.UNSUPPORTED_PROVIDER,
                failures=(_to_failure("registry_selection", exc),),
            )
        except UnsupportedVersionError as exc:
            return NormalizationResult(
                status=NormalizationStatus.UNSUPPORTED_VERSION,
                failures=(_to_failure("registry_selection", exc),),
            )
        except AmbiguousNormalizerSelectionError as exc:
            return NormalizationResult(
                status=NormalizationStatus.AMBIGUOUS_REGISTRATION,
                failures=(_to_failure("registry_selection", exc),),
            )

        try:
            draft = normalizer.normalize(cmd.raw_payload, cmd.tenant_id)
        except Exception as exc:
            # An untrusted normalizer's mapping failure is exactly the
            # "invalid mapping" case this framework must never let crash
            # the pipeline (M37 §2.4) — caught broadly and deliberately.
            failed_event = build_normalization_failed(
                tenant_id=str(cmd.tenant_id),
                batch_fingerprint=f"{cmd.provider}:{cmd.declared_schema_version_raw}",
                source_vendor=cmd.provider,
                reason=NormalizationFailureReason.MAPPING_ERROR,
                detail=str(exc) or type(exc).__name__,
                now=now,
            )
            return NormalizationResult(
                status=NormalizationStatus.FAILED_NORMALIZATION,
                failed_domain_event=failed_event,
                failures=(_to_failure("mapping", exc),),
            )

        try:
            source = EventSource(source_type=normalizer.source_type, vendor=normalizer.provider)
            canonical_event = build_canonical_event(
                tenant_id=cmd.tenant_id,
                source=source,
                category=draft.category,
                outcome=draft.outcome,
                occurred_at=draft.occurred_at,
                schema_version=normalizer.schema_version,
                ingested_at=now,
                severity=draft.severity,
                actor=draft.actor,
                target=draft.target,
                attributes=draft.attributes,
                raw_payload_ref=draft.raw_payload_ref,
            )
        except SiemSharedDomainError as exc:
            failed_event = build_normalization_failed(
                tenant_id=str(cmd.tenant_id),
                batch_fingerprint=f"{cmd.provider}:{cmd.declared_schema_version_raw}",
                source_vendor=cmd.provider,
                reason=NormalizationFailureReason.SCHEMA_MISMATCH,
                detail=str(exc),
                now=now,
            )
            return NormalizationResult(
                status=NormalizationStatus.FAILED_NORMALIZATION,
                failed_domain_event=failed_event,
                failures=(_to_failure("construction", exc),),
            )

        normalized_event = build_events_normalized(
            tenant_id=str(cmd.tenant_id),
            batch_fingerprint=str(canonical_event.identity.fingerprint),
            schema_version=str(normalizer.schema_version),
            normalized_event_count=1,
            now=now,
        )
        self._receiver.receive(canonical_event)
        return NormalizationResult(
            status=NormalizationStatus.NORMALIZED,
            canonical_event=canonical_event,
            normalized_domain_event=normalized_event,
        )

    def _validate_request(self, cmd: NormalizeEventCommand) -> SchemaVersion:
        if not cmd.provider.strip():
            raise MissingRequiredFieldError("provider")
        if not cmd.raw_payload:
            raise MissingRequiredFieldError("raw_payload")
        if not cmd.declared_schema_version_raw.strip():
            raise MissingRequiredFieldError("declared_schema_version_raw")
        return SchemaVersion.parse(cmd.declared_schema_version_raw)
