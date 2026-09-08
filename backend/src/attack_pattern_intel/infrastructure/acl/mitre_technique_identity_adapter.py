"""SqlAlchemyMitreTechniqueIdentityAdapter — the real infrastructure
adapter for `IMitreTechniqueIdentityPort` (M51.3 Phase B1).

Reads read-only against the existing `attack_techniques` table (owned
by `redforge.domain.threat_intel`, M22, DO-NOT-MODIFY) via its
infra-level SQLAlchemy ORM model, `redforge.infrastructure.database.
models.threat_intel_reference_data.AttackTechniqueModel` — never that
context's domain aggregate classes (`AttackTechnique`,
`AttackTactic`), and never a second write path into that table. This
is the one legitimate seam between the two bounded contexts, per the
M51.3 ACL-over-legacy-identity architecture decision."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from attack_pattern_intel.application.ports.i_mitre_technique_identity_port import (
    IMitreTechniqueIdentityPort,
    MitreTechniqueSnapshot,
)
from redforge.infrastructure.database.models.threat_intel_reference_data import (
    AttackTechniqueModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyMitreTechniqueIdentityAdapter(IMitreTechniqueIdentityPort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def exists(self, technique_id: str) -> bool:
        result = await self._session.execute(
            select(AttackTechniqueModel.id).where(AttackTechniqueModel.technique_id == technique_id)
        )
        return result.scalar_one_or_none() is not None

    async def get_snapshot(self, technique_id: str) -> MitreTechniqueSnapshot | None:
        result = await self._session.execute(
            select(AttackTechniqueModel).where(AttackTechniqueModel.technique_id == technique_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return MitreTechniqueSnapshot(
            technique_id=row.technique_id,
            name=row.name,
            tactic_ids=tuple(row.tactic_ids or []),
            platforms=tuple(row.platforms or []),
            is_sub_technique=row.is_sub_technique,
            is_deprecated=row.is_deprecated,
            is_revoked=row.is_revoked,
        )
