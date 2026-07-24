from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_shared.domain.exceptions.domain_exceptions import (
    InvalidSchemaVersionStringError,
    NaiveTimestampError,
)
from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint
from siem_shared.domain.value_objects.event_identity import EventIdentity
from siem_shared.domain.value_objects.event_metadata import EventMetadata
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.event_timestamp import EventTimestamp
from siem_shared.domain.value_objects.schema_version import SchemaVersion
from siem_shared.domain.value_objects.tenant_context import TenantContext

OCCURRED_AT = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
INGESTED_AT = datetime(2026, 1, 1, 12, 0, 2, tzinfo=UTC)


def _event(**overrides: object) -> CanonicalEvent:
    defaults: dict[str, object] = {
        "identity": EventIdentity(
            event_id=EntityId.generate(), fingerprint=EventFingerprint("fp-1")
        ),
        "tenant": TenantContext(tenant_id=EntityId.generate()),
        "timestamp": EventTimestamp(occurred_at=OCCURRED_AT, ingested_at=INGESTED_AT),
        "source": EventSource(source_type=EventSourceType.CLOUD, vendor="aws-cloudtrail"),
        "category": EventCategory.CLOUD_API,
        "outcome": EventOutcome.SUCCESS,
        "metadata": EventMetadata(schema_version=SchemaVersion(1, 0), attributes={"region": "us-east-1"}),
    }
    defaults.update(overrides)
    return CanonicalEvent(**defaults)  # type: ignore[arg-type]


def test_construction_minimal() -> None:
    event = _event()
    assert event.category == EventCategory.CLOUD_API
    assert event.severity is None
    assert event.actor is None
    assert event.target is None


def test_construction_with_actor_and_target() -> None:
    actor = EntityRef(entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe")
    target = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="bucket-1")
    event = _event(actor=actor, target=target, severity=EventSeverity.CRITICAL)
    assert event.actor == actor
    assert event.target == target
    assert event.severity == EventSeverity.CRITICAL


def test_two_events_with_same_field_values_are_equal() -> None:
    identity = EventIdentity(event_id=EntityId.generate(), fingerprint=EventFingerprint("fp-x"))
    tenant = TenantContext(tenant_id=EntityId.generate())
    a = _event(identity=identity, tenant=tenant)
    b = _event(identity=identity, tenant=tenant)
    assert a == b


def test_tenant_isolation_events_with_different_tenants_are_never_equal() -> None:
    identity = EventIdentity(event_id=EntityId.generate(), fingerprint=EventFingerprint("fp-x"))
    a = _event(identity=identity, tenant=TenantContext(tenant_id=EntityId.generate()))
    b = _event(identity=identity, tenant=TenantContext(tenant_id=EntityId.generate()))
    assert a != b
    assert a.tenant.tenant_id != b.tenant.tenant_id


def test_to_dict_from_dict_round_trip() -> None:
    actor = EntityRef(
        entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe", entity_id=EntityId.generate()
    )
    event = _event(actor=actor, severity=EventSeverity.LOW)

    serialized = event.to_dict()
    reconstructed = CanonicalEvent.from_dict(serialized)

    assert reconstructed == event


def test_to_dict_produces_plain_json_safe_structures() -> None:
    """Serialization contract: no domain types leak into the dict —
    only str/int/float/bool/None/dict/list."""
    event = _event(
        metadata=EventMetadata(
            schema_version=SchemaVersion(1, 0),
            attributes={"nested": {"a": [1, 2, {"b": True}]}},
        )
    )
    serialized = event.to_dict()

    def _assert_json_safe(value: object) -> None:
        if isinstance(value, dict):
            for v in value.values():
                _assert_json_safe(v)
        elif isinstance(value, list):
            for v in value:
                _assert_json_safe(v)
        else:
            assert isinstance(value, (str, int, float, bool)) or value is None

    _assert_json_safe(serialized)


def test_to_dict_round_trips_actor_and_target_none() -> None:
    event = _event()
    serialized = event.to_dict()
    assert serialized["actor"] is None
    assert serialized["target"] is None
    reconstructed = CanonicalEvent.from_dict(serialized)
    assert reconstructed.actor is None
    assert reconstructed.target is None


def test_from_dict_rejects_invalid_category() -> None:
    event = _event()
    serialized = event.to_dict()
    serialized["category"] = "not-a-real-category"
    with pytest.raises(ValueError, match="not-a-real-category"):
        CanonicalEvent.from_dict(serialized)


def test_from_dict_rejects_malformed_schema_version() -> None:
    event = _event()
    serialized = event.to_dict()
    serialized["schema_version"] = "garbage"
    with pytest.raises(InvalidSchemaVersionStringError, match="garbage"):
        CanonicalEvent.from_dict(serialized)


def test_from_dict_rejects_naive_timestamp_string() -> None:
    """A stripped-timezone ISO string round trips through isoformat but
    reconstructs as naive — from_dict must reject it via EventTimestamp's
    own invariant, the same as direct construction would."""
    event = _event()
    serialized = event.to_dict()
    serialized["occurred_at"] = "2026-01-01T12:00:00"
    with pytest.raises(NaiveTimestampError, match="occurred_at"):
        CanonicalEvent.from_dict(serialized)


def test_from_dict_reconstructs_connector_source() -> None:
    connector_id = EntityId.generate()
    event = _event(
        source=EventSource(
            source_type=EventSourceType.CONNECTOR,
            vendor="okta",
            source_connector_id=connector_id,
        )
    )
    reconstructed = CanonicalEvent.from_dict(event.to_dict())
    assert reconstructed.source.source_connector_id == connector_id


def test_schema_version_backward_compatible_events_share_major() -> None:
    event_v1_0 = _event(metadata=EventMetadata(schema_version=SchemaVersion(1, 0)))
    event_v1_5 = _event(metadata=EventMetadata(schema_version=SchemaVersion(1, 5)))
    assert event_v1_0.metadata.schema_version.is_compatible_with(
        event_v1_5.metadata.schema_version
    )


def test_schema_version_major_bump_is_a_breaking_change() -> None:
    event_v1 = _event(metadata=EventMetadata(schema_version=SchemaVersion(1, 9)))
    event_v2 = _event(metadata=EventMetadata(schema_version=SchemaVersion(2, 0)))
    assert not event_v1.metadata.schema_version.is_compatible_with(
        event_v2.metadata.schema_version
    )
