from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from siem_normalization.application.commands.normalization_commands import NormalizeBatchCommand
from siem_normalization.application.dtos.normalization_result import NormalizationStatus
from siem_normalization.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchNormalizationError,
)
from siem_normalization.application.registry.in_memory_event_normalizer_registry import (
    InMemoryEventNormalizerRegistry,
)
from siem_normalization.application.services.normalization_application_service import (
    NormalizationApplicationService,
)
from siem_normalization.domain.events.normalization_events import (
    EventsNormalized,
    NormalizationFailed,
)
from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import SCHEMA_V1_0, FakeNormalizer, make_draft, normalize_event_command

NOW = datetime.now(UTC)


def _service(receiver, registry=None):
    return NormalizationApplicationService(
        registry=registry or InMemoryEventNormalizerRegistry(), receiver=receiver
    )


# ---------------------------------------------------------------------------
# successful orchestration
# ---------------------------------------------------------------------------


def test_normalize_event_success_uses_canonical_event_factory(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme",
            SCHEMA_V1_0,
            mapper=lambda payload, tenant_id: make_draft(
                category=EventCategory.NETWORK, occurred_at=NOW
            ),
        )
    )
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert result.status == NormalizationStatus.NORMALIZED
    assert isinstance(result.canonical_event, CanonicalEvent)
    assert result.canonical_event.category == EventCategory.NETWORK
    assert receiver.received == [result.canonical_event]


def test_normalize_event_success_emits_events_normalized_domain_event(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme", SCHEMA_V1_0, mapper=lambda payload, tenant_id: make_draft(occurred_at=NOW)
        )
    )
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert isinstance(result.normalized_domain_event, EventsNormalized)
    assert result.failed_domain_event is None


def test_normalize_event_routes_by_declared_schema_version(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme",
            SchemaVersion(2, 0),
            mapper=lambda payload, tenant_id: make_draft(occurred_at=NOW),
        )
    )
    service = _service(receiver, registry)

    result = service.normalize_event(
        normalize_event_command(declared_schema_version_raw="2.0")
    )

    assert result.status == NormalizationStatus.NORMALIZED
    assert result.canonical_event.metadata.schema_version == SchemaVersion(2, 0)


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------


def test_normalize_event_without_executor_role_raises_forbidden(receiver):
    service = _service(receiver)
    cmd = normalize_event_command(actor_roles=())

    with pytest.raises(ApplicationForbiddenError):
        service.normalize_event(cmd)


# ---------------------------------------------------------------------------
# validation failures (pre-lookup) -> REJECTED
# ---------------------------------------------------------------------------


def test_normalize_event_blank_provider_is_rejected(receiver):
    service = _service(receiver)
    result = service.normalize_event(normalize_event_command(provider="   "))

    assert result.status == NormalizationStatus.REJECTED
    assert result.failures[0].error_type == "MissingRequiredFieldError"


def test_normalize_event_empty_raw_payload_is_rejected(receiver):
    service = _service(receiver)
    result = service.normalize_event(normalize_event_command(raw_payload={}))

    assert result.status == NormalizationStatus.REJECTED


def test_normalize_event_malformed_schema_version_is_rejected(receiver):
    service = _service(receiver)
    result = service.normalize_event(
        normalize_event_command(declared_schema_version_raw="garbage")
    )

    assert result.status == NormalizationStatus.REJECTED
    assert result.failures[0].error_type == "InvalidSchemaVersionStringError"


# ---------------------------------------------------------------------------
# registry selection failures
# ---------------------------------------------------------------------------


def test_normalize_event_unsupported_provider(receiver):
    service = _service(receiver)
    result = service.normalize_event(normalize_event_command(provider="nonexistent"))

    assert result.status == NormalizationStatus.UNSUPPORTED_PROVIDER
    assert result.canonical_event is None
    assert receiver.received == []


def test_normalize_event_unsupported_version(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("acme", SCHEMA_V1_0))
    service = _service(receiver, registry)

    result = service.normalize_event(
        normalize_event_command(declared_schema_version_raw="9.0")
    )

    assert result.status == NormalizationStatus.UNSUPPORTED_VERSION


def test_normalize_event_ambiguous_registration(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("acme", SchemaVersion(1, 0)))
    registry.register(FakeNormalizer("acme", SchemaVersion(1, 5)))
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert result.status == NormalizationStatus.AMBIGUOUS_REGISTRATION
    assert receiver.received == []


# ---------------------------------------------------------------------------
# execution failures -> FAILED_NORMALIZATION
# ---------------------------------------------------------------------------


def test_normalize_event_mapping_raises_produces_failed_normalization(receiver):
    def _bad_mapper(payload, tenant_id):
        raise KeyError("missing required field 'eventType'")

    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("acme", SCHEMA_V1_0, mapper=_bad_mapper))
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert result.status == NormalizationStatus.FAILED_NORMALIZATION
    assert isinstance(result.failed_domain_event, NormalizationFailed)
    assert result.canonical_event is None
    assert receiver.received == []


def test_normalize_event_invalid_mapping_never_crashes_the_pipeline(receiver):
    """Failures are first-class, never silent drops AND never a crash
    (M37 §2.4/§3) — a normalizer raising an arbitrary exception must
    still produce a typed result, not propagate."""

    def _explode(payload, tenant_id):
        raise RuntimeError("totally unexpected provider payload shape")

    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("acme", SCHEMA_V1_0, mapper=_explode))
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert result.status == NormalizationStatus.FAILED_NORMALIZATION


def test_normalize_event_construction_failure_produces_failed_normalization(receiver):
    """The mapper succeeds but produces a semantically invalid draft
    (e.g. a naive occurred_at) — CEM construction itself fails."""

    def _naive_timestamp_mapper(payload, tenant_id):
        return make_draft(occurred_at=datetime.now())

    registry = InMemoryEventNormalizerRegistry()
    registry.register(FakeNormalizer("acme", SCHEMA_V1_0, mapper=_naive_timestamp_mapper))
    service = _service(receiver, registry)

    result = service.normalize_event(normalize_event_command())

    assert result.status == NormalizationStatus.FAILED_NORMALIZATION
    assert result.failures[0].stage == "construction"
    assert receiver.received == []


# ---------------------------------------------------------------------------
# batch
# ---------------------------------------------------------------------------


def test_normalize_batch_all_succeed(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme", SCHEMA_V1_0, mapper=lambda payload, tenant_id: make_draft(occurred_at=NOW)
        )
    )
    service = _service(receiver, registry)
    cmd = NormalizeBatchCommand(
        tenant_id=normalize_event_command().tenant_id,
        events=tuple(normalize_event_command() for _ in range(3)),
        actor_roles=("siem_normalization:execute",),
    )

    result = service.normalize_batch(cmd)

    assert result.status == NormalizationStatus.NORMALIZED
    assert result.normalized_count == 3
    assert result.failed_count == 0
    assert len(result.normalized_events) == 3


def test_normalize_batch_partial_success(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme", SCHEMA_V1_0, mapper=lambda payload, tenant_id: make_draft(occurred_at=NOW)
        )
    )
    service = _service(receiver, registry)
    cmd = NormalizeBatchCommand(
        tenant_id=normalize_event_command().tenant_id,
        events=(
            normalize_event_command(),
            normalize_event_command(provider="nonexistent"),
            normalize_event_command(),
        ),
        actor_roles=("siem_normalization:execute",),
    )

    result = service.normalize_batch(cmd)

    assert result.status == NormalizationStatus.PARTIALLY_NORMALIZED
    assert result.normalized_count == 2
    assert result.failed_count == 1


def test_normalize_batch_all_fail(receiver):
    service = _service(receiver)  # empty registry
    cmd = NormalizeBatchCommand(
        tenant_id=normalize_event_command().tenant_id,
        events=(normalize_event_command(), normalize_event_command()),
        actor_roles=("siem_normalization:execute",),
    )

    result = service.normalize_batch(cmd)

    assert result.status == NormalizationStatus.FAILED_NORMALIZATION
    assert result.normalized_count == 0


def test_normalize_batch_empty_raises(receiver):
    service = _service(receiver)
    cmd = NormalizeBatchCommand(
        tenant_id=normalize_event_command().tenant_id,
        events=(),
        actor_roles=("siem_normalization:execute",),
    )

    with pytest.raises(EmptyBatchNormalizationError):
        service.normalize_batch(cmd)


def test_normalize_batch_without_role_raises_forbidden(receiver):
    service = _service(receiver)
    cmd = NormalizeBatchCommand(
        tenant_id=normalize_event_command().tenant_id,
        events=(normalize_event_command(),),
        actor_roles=(),
    )

    with pytest.raises(ApplicationForbiddenError):
        service.normalize_batch(cmd)


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_normalization_result_is_frozen(receiver):
    registry = InMemoryEventNormalizerRegistry()
    registry.register(
        FakeNormalizer(
            "acme", SCHEMA_V1_0, mapper=lambda payload, tenant_id: make_draft(occurred_at=NOW)
        )
    )
    service = _service(receiver, registry)
    result = service.normalize_event(normalize_event_command())

    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = NormalizationStatus.REJECTED  # type: ignore[misc]
