"""SqlAlchemyAttackPatternIdentityAdapter — the real infrastructure
adapter for `IAttackPatternIdentityPort` (M51.4 Phase C1).

Reads read-only against the `attack_pattern_intel_patterns` table
owned by the `attack_pattern_intel` bounded context, using a
lightweight SQLAlchemy Core table description declared locally. It
deliberately does NOT import `attack_pattern_intel`'s ORM models or
(far less) its domain classes — see `SqlAlchemyIocIdentityAdapter`'s
docstring for the identical rationale and constraints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import column, select, table
from sqlalchemy.dialects.postgresql import UUID as PgUUID

from intelligence_relationships.application.ports.i_attack_pattern_identity_port import (
    IAttackPatternIdentityPort,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# A local, read-only Core description of another context's table —
# never that context's ORM model class, and never registered against
# this application's declarative metadata.
_ATTACK_PATTERN_TABLE = table(
    "attack_pattern_intel_patterns",
    column("id", PgUUID(as_uuid=True)),
)


class SqlAlchemyAttackPatternIdentityAdapter(IAttackPatternIdentityPort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def exists(self, attack_pattern_id: str) -> bool:
        try:
            key = UUID(attack_pattern_id)
        except ValueError:
            # A syntactically impossible id can never identify a row;
            # "unknown" is the honest answer, not a 500.
            return False
        result = await self._session.execute(
            select(_ATTACK_PATTERN_TABLE.c.id).where(_ATTACK_PATTERN_TABLE.c.id == key).limit(1)
        )
        return result.scalar_one_or_none() is not None
