from __future__ import annotations

import pytest

from redforge.shared.identifiers import EntityId
from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType


def test_entity_ref_construction_unresolved() -> None:
    ref = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="10.0.0.5")
    assert ref.entity_type == EntityRefType.ASSET
    assert ref.raw_identifier == "10.0.0.5"
    assert ref.entity_id is None
    assert ref.is_resolved is False


def test_entity_ref_construction_resolved() -> None:
    entity_id = EntityId.generate()
    ref = EntityRef(
        entity_type=EntityRefType.IDENTITY,
        raw_identifier="jdoe",
        entity_id=entity_id,
    )
    assert ref.is_resolved is True
    assert ref.entity_id == entity_id


def test_entity_ref_resolved_to_returns_new_instance() -> None:
    entity_id = EntityId.generate()
    unresolved = EntityRef(entity_type=EntityRefType.CONNECTOR, raw_identifier="conn-1")
    resolved = unresolved.resolved_to(entity_id)

    assert unresolved.is_resolved is False
    assert resolved.is_resolved is True
    assert resolved.entity_id == entity_id
    assert resolved.entity_type == unresolved.entity_type
    assert resolved.raw_identifier == unresolved.raw_identifier


def test_entity_ref_rejects_empty_raw_identifier() -> None:
    with pytest.raises(ValueError, match="raw_identifier"):
        EntityRef(entity_type=EntityRefType.AI_SYSTEM, raw_identifier="")


def test_entity_ref_rejects_whitespace_only_raw_identifier() -> None:
    with pytest.raises(ValueError, match="raw_identifier"):
        EntityRef(entity_type=EntityRefType.UNKNOWN, raw_identifier="   ")


def test_entity_ref_is_immutable() -> None:
    ref = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="10.0.0.5")
    with pytest.raises(AttributeError):
        ref.raw_identifier = "10.0.0.6"  # type: ignore[misc]


def test_entity_ref_equality_by_value() -> None:
    entity_id = EntityId.generate()
    a = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="x", entity_id=entity_id)
    b = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="x", entity_id=entity_id)
    assert a == b
