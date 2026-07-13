"""Domain identifier primitives.

Provides a ULID-based EntityId that serves as the standard identifier
for all domain entities across every bounded context.

ULIDs are preferred over UUIDv4 because they are:
- Lexicographically sortable (timestamp-prefixed)
- Better for B-tree index locality in PostgreSQL
- Compatible with UUID column types (128-bit)
- Human-readable when serialized as string

Usage:
    from redforge.shared import EntityId

    entity_id = EntityId.generate()
    entity_id = EntityId.from_string("01HGW2N7HF0ABCDEF1234567")
"""

from __future__ import annotations

from functools import total_ordering
from typing import Self

from ulid import ULID


@total_ordering
class EntityId:
    """Immutable domain identifier backed by a ULID.

    EntityId is a value object — two EntityIds with the same underlying
    ULID are considered equal regardless of which entity they identify.
    """

    __slots__ = ("_ulid",)

    def __init__(self, value: ULID) -> None:
        self._ulid = value

    @classmethod
    def generate(cls) -> Self:
        """Generate a new unique EntityId."""
        return cls(ULID())

    @classmethod
    def from_string(cls, value: str) -> Self:
        """Parse an EntityId from its string representation.

        Args:
            value: A 26-character ULID string.

        Raises:
            ValueError: If the string is not a valid ULID.
        """
        try:
            return cls(ULID.from_str(value))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid EntityId: '{value}'") from exc

    @property
    def value(self) -> ULID:
        """The underlying ULID value."""
        return self._ulid

    def __str__(self) -> str:
        return str(self._ulid)

    def __repr__(self) -> str:
        return f"EntityId({self._ulid})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EntityId):
            return NotImplemented
        return self._ulid == other._ulid

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, EntityId):
            return NotImplemented
        return self._ulid < other._ulid

    def __hash__(self) -> int:
        return hash(self._ulid)
