from __future__ import annotations

from integration_hub.domain.value_objects.discovery import RelationshipType
from siem_shared.domain.value_objects.entity_ref import EntityRef, EntityRefType
from siem_shared.domain.value_objects.entity_relationship_ref import EntityRelationshipRef


def test_reuses_integration_hub_relationship_type_verbatim() -> None:
    """ADR-G6: RelationshipType is Integration Hub's original enum,
    reused verbatim — this asserts the actual imported class identity,
    not merely a same-named lookalike."""
    from siem_shared.domain.value_objects import entity_relationship_ref as module

    assert module.RelationshipType is RelationshipType


def test_construction() -> None:
    subject = EntityRef(entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe")
    obj = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="host-1")
    edge = EntityRelationshipRef(
        subject=subject,
        relationship=RelationshipType.AUTHENTICATES_WITH,
        object=obj,
    )

    assert edge.subject is subject
    assert edge.object is obj
    assert edge.relationship == RelationshipType.AUTHENTICATES_WITH


def test_equality_by_value() -> None:
    subject = EntityRef(entity_type=EntityRefType.IDENTITY, raw_identifier="jdoe")
    obj = EntityRef(entity_type=EntityRefType.ASSET, raw_identifier="host-1")
    a = EntityRelationshipRef(subject=subject, relationship=RelationshipType.OWNS, object=obj)
    b = EntityRelationshipRef(subject=subject, relationship=RelationshipType.OWNS, object=obj)
    assert a == b
