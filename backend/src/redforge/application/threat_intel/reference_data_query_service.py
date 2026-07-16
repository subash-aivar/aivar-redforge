"""Reference Data query service — M22 Phase 1.

Read-only CRUD-level queries over the global ATT&CK / CVE catalog and
the ingestion log, for the internal administration API (verifying what
has been loaded). No orchestration, no cross-aggregate joins beyond
what the repositories already expose.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.threat_intel.attack_technique_entity import (
    AttackTactic,
    AttackTechnique,
    AttackTechniqueRelationship,
)
from redforge.domain.threat_intel.reference_data_ingestion import ReferenceDataIngestionRecord
from redforge.domain.threat_intel.reference_data_value_objects import (
    AttackRelationshipType,
    ReferenceDataSource,
)
from redforge.domain.threat_intel.vulnerability_entity import Vulnerability
from redforge.infrastructure.database.repositories.threat_intel_reference_data_repository import (
    SqlAlchemyAttackTacticRepository,
    SqlAlchemyAttackTechniqueRepository,
    SqlAlchemyReferenceDataIngestionRepository,
    SqlAlchemyVulnerabilityRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class ReferenceDataQueryService:
    """Queries: read-only access to the loaded global reference catalog."""

    def __init__(self, session: AsyncSession) -> None:
        self._tactics = SqlAlchemyAttackTacticRepository(session)
        self._techniques = SqlAlchemyAttackTechniqueRepository(session)
        self._vulnerabilities = SqlAlchemyVulnerabilityRepository(session)
        self._ingestion = SqlAlchemyReferenceDataIngestionRepository(session)

    # ── Tactics ──────────────────────────────────────────────────────────

    async def get_tactic(self, tactic_id: str) -> AttackTactic | None:
        return await self._tactics.get_by_id(tactic_id)

    async def list_tactics(self, *, limit: int = 200, offset: int = 0) -> list[AttackTactic]:
        return await self._tactics.list_all(limit=limit, offset=offset)

    async def count_tactics(self) -> int:
        return await self._tactics.count()

    # ── Techniques ───────────────────────────────────────────────────────

    async def get_technique(self, technique_id: str) -> AttackTechnique | None:
        return await self._techniques.get_by_id(technique_id)

    async def list_techniques_by_tactic(
        self, tactic_id: str, *, limit: int = 200, offset: int = 0
    ) -> list[AttackTechnique]:
        return await self._techniques.list_by_tactic(tactic_id, limit=limit, offset=offset)

    async def list_sub_techniques(self, parent_technique_id: str) -> list[AttackTechnique]:
        return await self._techniques.list_sub_techniques(parent_technique_id)

    async def search_techniques(
        self, query: str, *, limit: int = 50, offset: int = 0
    ) -> list[AttackTechnique]:
        return await self._techniques.search_by_name(query, limit=limit, offset=offset)

    async def count_techniques(self) -> int:
        return await self._techniques.count()

    async def list_technique_relationships(
        self,
        technique_id: str,
        *,
        relationship_type: AttackRelationshipType | None = None,
    ) -> list[AttackTechniqueRelationship]:
        return await self._techniques.list_relationships_for_technique(
            technique_id, relationship_type=relationship_type
        )

    # ── Vulnerabilities ──────────────────────────────────────────────────

    async def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        return await self._vulnerabilities.get_by_cve_id(cve_id)

    async def list_kev_vulnerabilities(
        self, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        return await self._vulnerabilities.list_by_kev_flag(True, limit=limit, offset=offset)

    async def list_high_epss_vulnerabilities(
        self, min_probability: float, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        return await self._vulnerabilities.list_by_epss_threshold(
            min_probability, limit=limit, offset=offset
        )

    async def count_vulnerabilities(self) -> int:
        return await self._vulnerabilities.count()

    # ── Ingestion log (verification) ────────────────────────────────────

    async def list_recent_ingestions(
        self,
        *,
        source_system: ReferenceDataSource | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ReferenceDataIngestionRecord]:
        return await self._ingestion.list_recent(
            source_system=source_system, limit=limit, offset=offset
        )

    async def count_ingestions_by_source(self, source_system: ReferenceDataSource) -> int:
        return await self._ingestion.count_by_source(source_system)
