from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_ingestion.application.commands.ingestion_commands import SubmitBatchCommand
from siem_ingestion.application.dtos.acceptance_result import AcceptanceStatus
from siem_ingestion.application.exceptions import (
    ApplicationForbiddenError,
    EmptyBatchSubmissionError,
)
from siem_ingestion.application.services.ingestion_application_service import (
    IngestionApplicationService,
)
from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
from siem_shared.domain.value_objects.event_source import EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import valid_event_command


def _service(receiver, rate_limiter, **overrides):
    return IngestionApplicationService(rate_limiter=rate_limiter, receiver=receiver, **overrides)


# ---------------------------------------------------------------------------
# submit_event — happy path / CanonicalEventFactory usage
# ---------------------------------------------------------------------------


def test_submit_event_accepted_uses_canonical_event_factory(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command()

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.ACCEPTED
    assert isinstance(result.canonical_event, CanonicalEvent)
    assert result.canonical_event.tenant.tenant_id == cmd.tenant_id
    assert result.canonical_event.category.value == "authentication"
    assert receiver.received == [result.canonical_event]


def test_submit_event_consumes_rate_limiter_budget_of_one(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command()

    service.submit_event(cmd)

    assert allow_all_rate_limiter.calls == [(cmd.tenant_id, 1)]


def test_submit_event_with_actor_and_target(receiver, allow_all_rate_limiter):
    from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType

    service = _service(receiver, allow_all_rate_limiter)
    actor = EntityRef(entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe")
    cmd = valid_event_command(actor=actor)

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.ACCEPTED
    assert result.canonical_event.actor == actor


# ---------------------------------------------------------------------------
# submit_event — authorization
# ---------------------------------------------------------------------------


def test_submit_event_without_submitter_role_raises_forbidden(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(actor_roles=())

    with pytest.raises(ApplicationForbiddenError):
        service.submit_event(cmd)

    assert receiver.received == []


def test_submit_event_with_viewer_only_role_raises_forbidden(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(actor_roles=("siem_ingestion:viewer",))

    with pytest.raises(ApplicationForbiddenError):
        service.submit_event(cmd)


# ---------------------------------------------------------------------------
# submit_event — rate limiting
# ---------------------------------------------------------------------------


def test_submit_event_rate_limited_never_reaches_receiver(receiver, deny_all_rate_limiter):
    service = _service(receiver, deny_all_rate_limiter)
    cmd = valid_event_command()

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.RATE_LIMITED
    assert result.canonical_event is None
    assert receiver.received == []


# ---------------------------------------------------------------------------
# submit_event — validation failures
# ---------------------------------------------------------------------------


def test_submit_event_invalid_schema_version_string(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(schema_version_raw="not-a-version")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.canonical_event is None
    assert result.failures[0].error_type == "InvalidSchemaVersionStringError"
    assert receiver.received == []


def test_submit_event_incompatible_schema_major_version(receiver, allow_all_rate_limiter):
    service = _service(
        receiver, allow_all_rate_limiter, supported_schema_version=SchemaVersion(1, 0)
    )
    cmd = valid_event_command(schema_version_raw="2.0")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "SchemaVersionUnsupportedError"


def test_submit_event_schema_minor_bump_is_compatible(receiver, allow_all_rate_limiter):
    service = _service(
        receiver, allow_all_rate_limiter, supported_schema_version=SchemaVersion(1, 0)
    )
    cmd = valid_event_command(schema_version_raw="1.9")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.ACCEPTED


def test_submit_event_invalid_category(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(category_raw="not-a-real-category")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "InvalidEventCategoryError"


def test_submit_event_invalid_outcome(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(outcome_raw="maybe")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "InvalidEventOutcomeError"


def test_submit_event_invalid_severity(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(severity_raw="extremely-bad")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "InvalidEventSeverityError"


def test_submit_event_missing_vendor_fails_at_source_stage(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(vendor="   ")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].stage == "event_source"


def test_submit_event_connector_source_missing_connector_id(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(source_type=EventSourceType.CONNECTOR, vendor="okta")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert receiver.received == []


def test_submit_event_connector_source_with_connector_id_succeeds(
    receiver, allow_all_rate_limiter
):
    service = _service(receiver, allow_all_rate_limiter)
    connector_id = EntityId.generate()
    cmd = valid_event_command(
        source_type=EventSourceType.CONNECTOR,
        vendor="okta",
        source_connector_id=connector_id,
    )

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.ACCEPTED
    assert result.canonical_event.source.source_connector_id == connector_id


def test_submit_event_timestamp_too_old_fails_sanity_check(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(occurred_at=datetime.now(UTC) - timedelta(days=10 * 365 + 30))

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "TimestampOutOfSanityRangeError"


def test_submit_event_naive_timestamp_rejected(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(occurred_at=datetime.now())

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "TimestampOutOfSanityRangeError"


def test_submit_event_far_future_timestamp_fails_construction(receiver, allow_all_rate_limiter):
    """Future-dating isn't a separate sanity threshold — it's caught by
    EventTimestamp's own ingested_at >= occurred_at invariant, since
    ingested_at is always "now" at ingestion time."""
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(occurred_at=datetime.now(UTC) + timedelta(days=1))

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "InvalidTimestampOrderingError"


def test_submit_event_payload_too_large(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(attributes={"blob": "x" * 300_000})

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "PayloadTooLargeError"


def test_submit_event_missing_required_category_field(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = valid_event_command(category_raw="")

    result = service.submit_event(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.failures[0].error_type == "MissingRequiredFieldError"


# ---------------------------------------------------------------------------
# submit_batch
# ---------------------------------------------------------------------------


def test_submit_batch_all_accepted(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    events = tuple(valid_event_command(tenant_id=tenant_id) for _ in range(3))
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    result = service.submit_batch(cmd)

    assert result.status == AcceptanceStatus.ACCEPTED
    assert result.accepted_count == 3
    assert result.rejected_count == 0
    assert len(result.accepted_events) == 3
    assert len(receiver.received) == 3


def test_submit_batch_partially_accepted(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    events = (
        valid_event_command(tenant_id=tenant_id),
        valid_event_command(tenant_id=tenant_id, category_raw="not-real"),
        valid_event_command(tenant_id=tenant_id),
    )
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    result = service.submit_batch(cmd)

    assert result.status == AcceptanceStatus.PARTIALLY_ACCEPTED
    assert result.accepted_count == 2
    assert result.rejected_count == 1


def test_submit_batch_all_rejected_is_validation_failed(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    events = tuple(
        valid_event_command(tenant_id=tenant_id, category_raw="not-real") for _ in range(2)
    )
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    result = service.submit_batch(cmd)

    assert result.status == AcceptanceStatus.VALIDATION_FAILED
    assert result.accepted_count == 0
    assert receiver.received == []


def test_submit_batch_mixed_tenant_events_fail_the_mismatched_item_only(
    receiver, allow_all_rate_limiter
):
    """A batch must never silently mix tenants — the mismatched event
    fails validation, the correctly-scoped ones still succeed."""
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    other_tenant_id = EntityId.generate()
    events = (
        valid_event_command(tenant_id=tenant_id),
        valid_event_command(tenant_id=other_tenant_id),
    )
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    result = service.submit_batch(cmd)

    assert result.status == AcceptanceStatus.PARTIALLY_ACCEPTED
    assert result.results[0].status == AcceptanceStatus.ACCEPTED
    assert result.results[1].status == AcceptanceStatus.VALIDATION_FAILED
    assert result.results[1].failures[0].error_type == "TenantContextMismatchError"
    assert result.results[1].failures[0].stage == "tenant_context"


def test_submit_batch_empty_events_raises(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    cmd = SubmitBatchCommand(
        tenant_id=EntityId.generate(), events=(), actor_roles=("siem_ingestion:submit",)
    )

    with pytest.raises(EmptyBatchSubmissionError):
        service.submit_batch(cmd)


def test_submit_batch_rate_limited_processes_nothing(receiver, deny_all_rate_limiter):
    service = _service(receiver, deny_all_rate_limiter)
    tenant_id = EntityId.generate()
    events = tuple(valid_event_command(tenant_id=tenant_id) for _ in range(5))
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    result = service.submit_batch(cmd)

    assert result.status == AcceptanceStatus.RATE_LIMITED
    assert result.results == ()
    assert receiver.received == []


def test_submit_batch_rate_limiter_consumes_full_event_count(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    events = tuple(valid_event_command(tenant_id=tenant_id) for _ in range(4))
    cmd = SubmitBatchCommand(tenant_id=tenant_id, events=events, actor_roles=("siem_ingestion:submit",))

    service.submit_batch(cmd)

    assert allow_all_rate_limiter.calls == [(tenant_id, 4)]


def test_submit_batch_without_submitter_role_raises_forbidden(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    tenant_id = EntityId.generate()
    cmd = SubmitBatchCommand(
        tenant_id=tenant_id, events=(valid_event_command(tenant_id=tenant_id),), actor_roles=()
    )

    with pytest.raises(ApplicationForbiddenError):
        service.submit_batch(cmd)


# ---------------------------------------------------------------------------
# Immutability of results
# ---------------------------------------------------------------------------


def test_event_acceptance_result_is_frozen(receiver, allow_all_rate_limiter):
    service = _service(receiver, allow_all_rate_limiter)
    result = service.submit_event(valid_event_command())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = AcceptanceStatus.REJECTED  # type: ignore[misc]


def test_batch_acceptance_result_is_frozen(receiver, allow_all_rate_limiter):
    tenant_id = EntityId.generate()
    service = _service(receiver, allow_all_rate_limiter)
    cmd = SubmitBatchCommand(
        tenant_id=tenant_id,
        events=(valid_event_command(tenant_id=tenant_id),),
        actor_roles=("siem_ingestion:submit",),
    )
    result = service.submit_batch(cmd)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = AcceptanceStatus.REJECTED  # type: ignore[misc]
