from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_ingestion.application.exceptions import (
    InvalidEventCategoryError,
    InvalidEventOutcomeError,
    InvalidEventSeverityError,
    MissingRequiredFieldError,
    PayloadTooLargeError,
    SchemaVersionUnsupportedError,
    TenantContextMismatchError,
    TimestampOutOfSanityRangeError,
)
from siem_ingestion.application.services import validation_pipeline as stages
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import valid_event_command

NOW = datetime.now(UTC)


def test_validate_required_fields_passes_for_valid_command() -> None:
    stages.validate_required_fields(valid_event_command())


def test_validate_required_fields_rejects_blank_vendor() -> None:
    with pytest.raises(MissingRequiredFieldError):
        stages.validate_required_fields(valid_event_command(vendor="  "))


def test_validate_required_fields_rejects_blank_category() -> None:
    with pytest.raises(MissingRequiredFieldError):
        stages.validate_required_fields(valid_event_command(category_raw=""))


def test_validate_batch_tenant_consistency_matching() -> None:
    tenant_id = EntityId.generate()
    stages.validate_batch_tenant_consistency(tenant_id, tenant_id)


def test_validate_batch_tenant_consistency_mismatch_raises() -> None:
    with pytest.raises(TenantContextMismatchError):
        stages.validate_batch_tenant_consistency(EntityId.generate(), EntityId.generate())


def test_validate_timestamp_sanity_accepts_recent_timestamp() -> None:
    stages.validate_timestamp_sanity(NOW - timedelta(minutes=1), NOW)


def test_validate_timestamp_sanity_rejects_naive() -> None:
    with pytest.raises(TimestampOutOfSanityRangeError):
        stages.validate_timestamp_sanity(datetime.now(), NOW)


def test_validate_timestamp_sanity_rejects_implausibly_old() -> None:
    with pytest.raises(TimestampOutOfSanityRangeError):
        stages.validate_timestamp_sanity(NOW - timedelta(days=20 * 365), NOW)


def test_validate_event_category_valid() -> None:
    assert stages.validate_event_category("network") == EventCategory.NETWORK


def test_validate_event_category_invalid_raises() -> None:
    with pytest.raises(InvalidEventCategoryError):
        stages.validate_event_category("bogus")


def test_validate_event_outcome_valid() -> None:
    assert stages.validate_event_outcome("failure") == EventOutcome.FAILURE


def test_validate_event_outcome_invalid_raises() -> None:
    with pytest.raises(InvalidEventOutcomeError):
        stages.validate_event_outcome("bogus")


def test_validate_event_severity_none_is_allowed() -> None:
    assert stages.validate_event_severity(None) is None


def test_validate_event_severity_valid() -> None:
    assert stages.validate_event_severity("high") == EventSeverity.HIGH


def test_validate_event_severity_invalid_raises() -> None:
    with pytest.raises(InvalidEventSeverityError):
        stages.validate_event_severity("bogus")


def test_validate_payload_size_within_limit() -> None:
    stages.validate_payload_size({"a": 1}, max_bytes=1000)


def test_validate_payload_size_exceeds_limit_raises() -> None:
    with pytest.raises(PayloadTooLargeError):
        stages.validate_payload_size({"a": "x" * 100}, max_bytes=10)


def test_validate_schema_compatibility_same_major_passes() -> None:
    stages.validate_schema_compatibility(SchemaVersion(1, 5), SchemaVersion(1, 0))


def test_validate_schema_compatibility_different_major_raises() -> None:
    with pytest.raises(SchemaVersionUnsupportedError):
        stages.validate_schema_compatibility(SchemaVersion(2, 0), SchemaVersion(1, 0))
