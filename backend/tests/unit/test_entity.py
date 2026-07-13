"""Unit tests for BaseEntity."""

from redforge.shared.entity import BaseEntity
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _make_entity(entity_id: EntityId | None = None) -> BaseEntity:
    """Helper to create a BaseEntity for testing."""
    return BaseEntity(
        id=entity_id or EntityId.generate(),
        timestamps=AuditTimestamps.create(),
    )


def test_entity_exposes_id_and_timestamps() -> None:
    entity_id = EntityId.generate()
    timestamps = AuditTimestamps.create()
    entity = BaseEntity(id=entity_id, timestamps=timestamps)

    assert entity.id == entity_id
    assert entity.timestamps == timestamps


def test_equality_by_identity() -> None:
    entity_id = EntityId.generate()
    entity1 = BaseEntity(id=entity_id, timestamps=AuditTimestamps.create())
    entity2 = BaseEntity(id=entity_id, timestamps=AuditTimestamps.create())

    assert entity1 == entity2


def test_inequality_with_different_ids() -> None:
    entity1 = _make_entity()
    entity2 = _make_entity()

    assert entity1 != entity2


def test_not_equal_to_non_entity() -> None:
    entity = _make_entity()
    assert entity != "not-an-entity"
    assert entity != 42


def test_hashable_by_id() -> None:
    entity_id = EntityId.generate()
    entity1 = BaseEntity(id=entity_id, timestamps=AuditTimestamps.create())
    entity2 = BaseEntity(id=entity_id, timestamps=AuditTimestamps.create())

    entity_set = {entity1, entity2}
    assert len(entity_set) == 1


def test_repr_includes_class_name_and_id() -> None:
    entity = _make_entity()
    repr_str = repr(entity)
    assert "BaseEntity(" in repr_str
    assert str(entity.id) in repr_str
