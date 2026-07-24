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
from typing import TYPE_CHECKING, Self

from ulid import ULID

if TYPE_CHECKING:
    from uuid import UUID


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

    @classmethod
    def from_uuid(cls, value: UUID) -> Self:
        """Build an EntityId from a raw `uuid.UUID` (e.g. a value read back
        from a `postgresql.UUID(as_uuid=True)` column).

        `EntityId.__init__` expects a `ULID`, not a `uuid.UUID` — passing a
        raw UUID directly (`EntityId(row.tenant_id)`) silently constructs an
        object whose `__str__`/`.value`/`__eq__` do not behave like one
        built via `.generate()`/`.from_string()`, because the underlying
        `ULID` was never actually parsed from the 128-bit value. This is the
        single sanctioned way to bridge a raw UUID column value into an
        EntityId; it uses `ULID.from_uuid`, the same 128-bit-compatible
        conversion used when a `ULID.value` is written into a UUID column,
        so the result is always `==` to an EntityId built directly from the
        same underlying value.
        """
        return cls(ULID.from_uuid(value))

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
