"""EntityRef — an opaque reference to one endpoint of a relationship.

`entity_id` is deliberately an opaque, unparsed string: this bounded
context never owns, mirrors, or format-validates another context's
identity. For the three RedForge-native endpoint kinds (IOC,
THREAT_ACTOR, ATTACK_PATTERN) existence is verified by the application
layer via the corresponding read-only ACL port BEFORE an
`IntelligenceRelationship` is constructed; for the other five kinds no
owning module exists and the string is accepted as-is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from intelligence_relationships.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from intelligence_relationships.domain.value_objects.enums import EntityType


@dataclass(frozen=True, slots=True)
class EntityRef:
    entity_type: EntityType
    entity_id: str

    def __post_init__(self) -> None:
        if not self.entity_id.strip():
            raise EmptyIdentifierError("entity_id")

    @property
    def key(self) -> str:
        """Canonical, comparable identity string for this endpoint."""
        return f"{self.entity_type.value}:{self.entity_id}"

    def __str__(self) -> str:
        return self.key
