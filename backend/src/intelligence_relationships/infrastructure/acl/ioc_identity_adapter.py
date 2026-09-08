"""SqlAlchemyIocIdentityAdapter — the real infrastructure adapter for
`IIocIdentityPort` (M51.4 Phase C1).

Reads read-only against the `ioc_intelligence_iocs` table owned by the
`ioc_intelligence` bounded context, using a lightweight SQLAlchemy
Core table description declared locally. It deliberately does NOT
import `ioc_intelligence`'s ORM models or (far less) its domain
classes: the only thing this seam is permitted to know is that a row
with a given primary key exists. No write path, no column beyond `id`,
no join.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import column, select, table
from sqlalchemy.dialects.postgresql import UUID as PgUUID

from intelligence_relationships.application.ports.i_ioc_identity_port import IIocIdentityPort

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

# A local, read-only Core description of another context's table —
# never that context's ORM model class, and never registered against
# this application's declarative metadata.
_IOC_TABLE = table(
    "ioc_intelligence_iocs",
    column("id", PgUUID(as_uuid=True)),
)


class SqlAlchemyIocIdentityAdapter(IIocIdentityPort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def exists(self, ioc_id: str) -> bool:
        try:
            key = UUID(ioc_id)
        except ValueError:
            # A syntactically impossible id can never identify a row;
            # "unknown" is the honest answer, not a 500.
            return False
        result = await self._session.execute(
            select(_IOC_TABLE.c.id).where(_IOC_TABLE.c.id == key).limit(1)
        )
        return result.scalar_one_or_none() is not None
