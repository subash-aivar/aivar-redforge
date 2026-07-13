"""Unit tests for EntityId."""

import pytest

from redforge.shared.identifiers import EntityId


def test_generate_creates_unique_ids() -> None:
    id1 = EntityId.generate()
    id2 = EntityId.generate()
    assert id1 != id2


def test_from_string_roundtrip() -> None:
    original = EntityId.generate()
    restored = EntityId.from_string(str(original))
    assert original == restored


def test_from_string_invalid_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Invalid EntityId"):
        EntityId.from_string("not-a-valid-ulid")


def test_from_string_empty_raises_value_error() -> None:
    with pytest.raises(ValueError, match="Invalid EntityId"):
        EntityId.from_string("")


def test_equality_based_on_ulid_value() -> None:
    id1 = EntityId.generate()
    id2 = EntityId.from_string(str(id1))
    assert id1 == id2
    assert hash(id1) == hash(id2)


def test_inequality_with_different_ulids() -> None:
    id1 = EntityId.generate()
    id2 = EntityId.generate()
    assert id1 != id2


def test_not_equal_to_other_types() -> None:
    id1 = EntityId.generate()
    assert id1 != "some-string"
    assert id1 != 42


def test_sortable() -> None:
    ids = [EntityId.generate() for _ in range(5)]
    sorted_ids = sorted(ids)
    # ULIDs are monotonically increasing, so sorted order matches creation order
    assert sorted_ids == ids


def test_hashable_in_sets() -> None:
    id1 = EntityId.generate()
    id2 = EntityId.from_string(str(id1))
    id3 = EntityId.generate()
    id_set = {id1, id2, id3}
    assert len(id_set) == 2


def test_repr_contains_ulid() -> None:
    entity_id = EntityId.generate()
    assert "EntityId(" in repr(entity_id)
    assert str(entity_id.value) in repr(entity_id)


def test_str_returns_ulid_string() -> None:
    entity_id = EntityId.generate()
    ulid_str = str(entity_id)
    assert len(ulid_str) == 26  # ULID string length
