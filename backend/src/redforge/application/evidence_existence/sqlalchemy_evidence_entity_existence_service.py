"""SqlAlchemyEvidenceEntityExistenceService — concrete, real
implementation of `IEvidenceEntityExistencePort` (M51.1 Phase 4.5).

Supports exactly two entity types today, matching the two real,
tenant-scoped, not-found-on-mismatch repository methods `redforge`
already owns:

- "SecurityCondition" -> `SecurityConditionRepository.get_by_id_for_org`
- "InvestigationCase" -> `SqlAlchemyInvestigationRepository.get`

Any other `entity_type` is rejected (returns `False`) — fail-closed,
never a silent "maybe". Both underlying repository methods already
return `None` on a cross-tenant row (never raise, never leak
existence-but-forbidden), so tenant isolation here is inherited
directly from already-audited repository behavior, not reimplemented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.application.evidence_existence.i_evidence_entity_existence_port import (
    IEvidenceEntityExistencePort,
)
from redforge.infrastructure.database.repositories.investigations.case_repository import (
    SqlAlchemyInvestigationRepository,
)
from redforge.infrastructure.database.repositories.security_condition_repository import (
    SecurityConditionRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

SUPPORTED_ENTITY_TYPES = frozenset({"SecurityCondition", "InvestigationCase"})


class SqlAlchemyEvidenceEntityExistenceService(IEvidenceEntityExistencePort):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def exists(self, entity_type: str, entity_id: str, organization_id: str) -> bool:
        if entity_type == "SecurityCondition":
            condition = await SecurityConditionRepository(self._session).get_by_id_for_org(
                entity_id, organization_id
            )
            return condition is not None
        if entity_type == "InvestigationCase":
            case = await SqlAlchemyInvestigationRepository(self._session).get(
                organization_id, entity_id
            )
            return case is not None
        return False
