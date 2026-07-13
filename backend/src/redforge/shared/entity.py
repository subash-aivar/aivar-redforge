"""Base domain entity.

Provides the foundation that all domain entities inherit from.
Encapsulates identity and audit timestamps — the two properties
that every persistent entity in RedForge carries.

Usage:
    from redforge.shared import BaseEntity, EntityId, AuditTimestamps

    class Organization(BaseEntity):
        def __init__(self, id: EntityId, timestamps: AuditTimestamps, name: str):
            super().__init__(id=id, timestamps=timestamps)
            self._name = name
"""

from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


class BaseEntity:
    """Base class for all domain entities.

    Provides identity (EntityId) and audit timestamps (AuditTimestamps).
    Two entities are equal if and only if they have the same id —
    this follows the DDD Entity pattern where identity, not attribute
    equality, determines equivalence.

    Subclasses should NOT override __eq__ or __hash__.
    """

    __slots__ = ("_id", "_timestamps")

    def __init__(self, id: EntityId, timestamps: AuditTimestamps) -> None:
        self._id = id
        self._timestamps = timestamps

    @property
    def id(self) -> EntityId:
        """The entity's unique identifier."""
        return self._id

    @property
    def timestamps(self) -> AuditTimestamps:
        """The entity's audit timestamps."""
        return self._timestamps

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseEntity):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(id={self._id})"
