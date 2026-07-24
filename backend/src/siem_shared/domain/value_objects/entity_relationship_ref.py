"""EntityRelationshipRef — an `EntityRef`-to-`EntityRef` edge, typed by
Integration Hub's existing `RelationshipType` enum.

Per M41 ADR-G6, `RelationshipType` is reused **verbatim** — imported
directly from `integration_hub`, never redefined here or anywhere else.
This value object exists so `siem_investigation`'s future Knowledge
Graph extension (M37 §7, M42 Phase 9) has a ready-made, correctly-typed
edge shape to build on, consistent with `EntityRef` already being part
of this shared kernel (M43A).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from integration_hub.domain.value_objects.discovery import RelationshipType

if TYPE_CHECKING:
    from siem_shared.domain.value_objects.entity_ref import EntityRef

__all__ = ["EntityRelationshipRef", "RelationshipType"]


@dataclass(frozen=True, slots=True)
class EntityRelationshipRef:
    subject: EntityRef
    relationship: RelationshipType
    object: EntityRef
