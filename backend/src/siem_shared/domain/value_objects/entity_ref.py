"""EntityRef — the platform-wide typed reference value object.

Defined here per M37 §2.1 and elevated to a platform-wide contract by
M41 ADR-G4: every bounded context's cross-aggregate pointer to an asset,
identity, connector, or AI system uses this type rather than a bare
`EntityId` or a parallel typed-reference concept.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from redforge.shared.identifiers import EntityId


class EntityRefType(StrEnum):
    """The kinds of thing an `EntityRef` can point to."""

    ASSET = "asset"
    IDENTITY = "identity"
    AI_SYSTEM = "ai_system"
    CONNECTOR = "connector"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EntityRef:
    """A typed, source-agnostic reference to another domain entity.

    `entity_id` is populated only once entity resolution has run;
    `raw_identifier` preserves what the source actually said (an IP,
    a username, an ARN) so correlation can work before/without
    resolution, per M37 §2.1.
    """

    entity_type: EntityRefType
    raw_identifier: str
    entity_id: EntityId | None = None

    def __post_init__(self) -> None:
        if not self.raw_identifier.strip():
            raise ValueError("EntityRef.raw_identifier must be a non-empty string")

    @property
    def is_resolved(self) -> bool:
        """Whether this reference has been bound to a concrete `EntityId`."""
        return self.entity_id is not None

    def resolved_to(self, entity_id: EntityId) -> EntityRef:
        """Return a new, resolved `EntityRef` bound to `entity_id`.

        `EntityRef` is immutable — resolution produces a new instance
        rather than mutating this one.
        """
        return EntityRef(
            entity_type=self.entity_type,
            raw_identifier=self.raw_identifier,
            entity_id=entity_id,
        )
