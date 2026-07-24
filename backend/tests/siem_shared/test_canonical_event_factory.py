from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from redforge.shared.identifiers import EntityId
from siem_shared.domain.exceptions.domain_exceptions import InvalidTimestampOrderingError
from siem_shared.domain.services.canonical_event_factory import build_canonical_event
from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType
from siem_shared.domain.value_objects.event_category import EventCategory
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint
from siem_shared.domain.value_objects.event_outcome import EventOutcome
from siem_shared.domain.value_objects.event_severity import EventSeverity
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType
from siem_shared.domain.value_objects.schema_version import SchemaVersion

OCCURRED_AT = datetime.now(UTC)


def _source() -> EventSource:
    return EventSource(source_type=EventSourceType.IDENTITY, vendor="okta")


def _build(**overrides: object) -> object:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "source": _source(),
        "category": EventCategory.AUTHENTICATION,
        "outcome": EventOutcome.SUCCESS,
        "occurred_at": OCCURRED_AT,
        "schema_version": SchemaVersion(1, 0),
    }
    defaults.update(overrides)
    return build_canonical_event(**defaults)  # type: ignore[arg-type]


def test_build_with_defaults_generates_event_id_and_fingerprint() -> None:
    event = _build()
    assert event.identity.event_id is not None
    assert event.identity.fingerprint is not None


def test_build_defaults_ingested_at_to_now_not_before_occurred_at() -> None:
    event = _build()
    assert event.timestamp.ingested_at >= event.timestamp.occurred_at


def test_build_with_explicit_event_id_and_fingerprint_uses_them() -> None:
    event_id = EntityId.generate()
    fingerprint = EventFingerprint("explicit-fp")
    event = _build(event_id=event_id, fingerprint=fingerprint)
    assert event.identity.event_id == event_id
    assert event.identity.fingerprint == fingerprint


def test_build_default_fingerprint_is_deterministic_for_same_inputs() -> None:
    tenant_id = EntityId.generate()
    source = _source()
    event_a = build_canonical_event(
        tenant_id=tenant_id,
        source=source,
        category=EventCategory.AUTHENTICATION,
        outcome=EventOutcome.SUCCESS,
        occurred_at=OCCURRED_AT,
        schema_version=SchemaVersion(1, 0),
    )
    event_b = build_canonical_event(
        tenant_id=tenant_id,
        source=source,
        category=EventCategory.AUTHENTICATION,
        outcome=EventOutcome.SUCCESS,
        occurred_at=OCCURRED_AT,
        schema_version=SchemaVersion(1, 0),
    )
    assert event_a.identity.fingerprint == event_b.identity.fingerprint


def test_build_with_actor_and_target_entity_refs() -> None:
    actor = EntityRef(entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe")
    target = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="host-1")
    event = _build(actor=actor, target=target)
    assert event.actor is actor
    assert event.target is target


def test_build_with_severity() -> None:
    event = _build(severity=EventSeverity.HIGH)
    assert event.severity == EventSeverity.HIGH


def test_build_with_attributes_and_raw_payload_ref() -> None:
    event = _build(attributes={"mfa": True}, raw_payload_ref="evidence://xyz")
    assert event.metadata.attributes_as_dict() == {"mfa": True}
    assert event.metadata.raw_payload_ref == "evidence://xyz"


def test_build_propagates_invalid_timestamp_ordering() -> None:
    with pytest.raises(InvalidTimestampOrderingError, match="ingested_at"):
        _build(ingested_at=OCCURRED_AT - timedelta(seconds=1))


def test_canonical_event_is_frozen() -> None:
    event = _build()
    with pytest.raises(dataclasses.FrozenInstanceError):
        event.category = EventCategory.NETWORK  # type: ignore[misc]


def test_canonical_event_rebuilt_from_same_identity_and_tenant_is_equal() -> None:
    """Two independently-constructed events with the same identity,
    tenant, and field values are equal by value — proving equality is
    structural, not reference-based, without relying on `copy.deepcopy`
    (which the stdlib `copy` module cannot handle for the frozen
    `MappingProxyType` attribute bag by design)."""
    event_id = EntityId.generate()
    fingerprint = EventFingerprint("fp-1")
    tenant_id = EntityId.generate()
    source = _source()

    first = build_canonical_event(
        tenant_id=tenant_id,
        source=source,
        category=EventCategory.AUTHENTICATION,
        outcome=EventOutcome.SUCCESS,
        occurred_at=OCCURRED_AT,
        schema_version=SchemaVersion(1, 0),
        event_id=event_id,
        fingerprint=fingerprint,
        ingested_at=OCCURRED_AT,
    )
    second = build_canonical_event(
        tenant_id=tenant_id,
        source=source,
        category=EventCategory.AUTHENTICATION,
        outcome=EventOutcome.SUCCESS,
        occurred_at=OCCURRED_AT,
        schema_version=SchemaVersion(1, 0),
        event_id=event_id,
        fingerprint=fingerprint,
        ingested_at=OCCURRED_AT,
    )
    assert first == second
