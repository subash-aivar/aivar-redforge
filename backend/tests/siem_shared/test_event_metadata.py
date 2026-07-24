from __future__ import annotations

from types import MappingProxyType

import pytest

from siem_shared.domain.exceptions.domain_exceptions import (
    EmptyRawPayloadRefError,
    NonSerializableAttributeError,
)
from siem_shared.domain.value_objects.event_metadata import EventMetadata
from siem_shared.domain.value_objects.schema_version import SchemaVersion


def test_default_attributes_is_empty() -> None:
    md = EventMetadata(schema_version=SchemaVersion(1, 0))
    assert md.attributes_as_dict() == {}


def test_nested_attributes_are_frozen() -> None:
    md = EventMetadata(
        schema_version=SchemaVersion(1, 0),
        attributes={"a": {"b": [1, 2, 3]}},
    )
    assert isinstance(md.attributes["a"], MappingProxyType)
    assert isinstance(md.attributes["a"]["b"], tuple)  # type: ignore[index]


def test_top_level_attributes_mapping_is_immutable() -> None:
    md = EventMetadata(schema_version=SchemaVersion(1, 0), attributes={"x": 1})
    with pytest.raises(TypeError):
        md.attributes["x"] = 2  # type: ignore[index]


def test_mutating_source_dict_after_construction_does_not_affect_metadata() -> None:
    source = {"a": [1, 2]}
    md = EventMetadata(schema_version=SchemaVersion(1, 0), attributes=source)
    source["a"].append(3)
    assert md.attributes_as_dict() == {"a": [1, 2]}


def test_attributes_as_dict_round_trips_plain_structures() -> None:
    original = {"count": 3, "tags": ["a", "b"], "nested": {"ok": True, "ratio": 0.5}}
    md = EventMetadata(schema_version=SchemaVersion(1, 0), attributes=original)
    assert md.attributes_as_dict() == original


def test_rejects_non_serializable_attribute_value() -> None:
    with pytest.raises(NonSerializableAttributeError):
        EventMetadata(schema_version=SchemaVersion(1, 0), attributes={"bad": {1, 2, 3}})


def test_rejects_non_serializable_nested_attribute_value() -> None:
    with pytest.raises(NonSerializableAttributeError):
        EventMetadata(
            schema_version=SchemaVersion(1, 0),
            attributes={"outer": {"inner": object()}},
        )


def test_none_is_serializable() -> None:
    md = EventMetadata(schema_version=SchemaVersion(1, 0), attributes={"maybe": None})
    assert md.attributes_as_dict() == {"maybe": None}


def test_raw_payload_ref_none_is_allowed() -> None:
    md = EventMetadata(schema_version=SchemaVersion(1, 0), raw_payload_ref=None)
    assert md.raw_payload_ref is None


def test_raw_payload_ref_rejects_blank_string() -> None:
    with pytest.raises(EmptyRawPayloadRefError):
        EventMetadata(schema_version=SchemaVersion(1, 0), raw_payload_ref="   ")


def test_raw_payload_ref_accepts_non_empty_string() -> None:
    md = EventMetadata(schema_version=SchemaVersion(1, 0), raw_payload_ref="evidence://abc123")
    assert md.raw_payload_ref == "evidence://abc123"
