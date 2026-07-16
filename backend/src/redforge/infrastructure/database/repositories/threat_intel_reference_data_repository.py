"""SQLAlchemy repositories for the Threat Intelligence Reference Data
sub-context — M22 Phase 1.

Same conventions as `threat_intel_repository.py` (M18) and
`investigations/case_repository.py` (M21): SAVEPOINT (`begin_nested`) +
refetch-and-converge for concurrent upserts. Every repository here
fronts a GLOBAL table (no `organization_id` filter anywhere) except
`SqlAlchemyReferenceDataIngestionRepository`, which fronts
`stix_ingestion_log`.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError

from redforge.domain.threat_intel.attack_technique_entity import (
    AttackTactic,
    AttackTechnique,
    AttackTechniqueRelationship,
)
from redforge.domain.threat_intel.reference_data_ingestion import ReferenceDataIngestionRecord
from redforge.domain.threat_intel.reference_data_value_objects import (
    AttackRelationshipType,
    CveId,
    CvssScore,
    EpssScore,
    IngestionScope,
    ReferenceDataSource,
    TacticId,
    TechniqueId,
)
from redforge.domain.threat_intel.vulnerability_entity import Vulnerability
from redforge.infrastructure.database.models.threat_intel_reference_data import (
    AttackTacticModel,
    AttackTechniqueModel,
    AttackTechniqueRelationshipModel,
    StixIngestionLogModel,
    VulnerabilityModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


# ─── Mappers: ORM <-> domain entity ──────────────────────────────────────────


def _tactic_to_domain(model: AttackTacticModel) -> AttackTactic:
    return AttackTactic(
        tactic_id=TacticId(model.tactic_id),
        name=model.name,
        shortname=model.shortname,
        description=model.description,
        stix_id=model.stix_id,
        url=model.url,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _tactic_from_domain(tactic: AttackTactic, *, id: str, now: datetime) -> AttackTacticModel:
    return AttackTacticModel(
        id=id,
        tactic_id=tactic.tactic_id.value,
        name=tactic.name,
        shortname=tactic.shortname,
        description=tactic.description,
        stix_id=tactic.stix_id,
        url=tactic.url,
        created_at=tactic.created_at or now,
        updated_at=now,
    )


def _technique_to_domain(model: AttackTechniqueModel) -> AttackTechnique:
    return AttackTechnique(
        technique_id=TechniqueId(model.technique_id),
        name=model.name,
        description=model.description,
        stix_id=model.stix_id,
        is_sub_technique=model.is_sub_technique,
        parent_technique_id=(
            TechniqueId(model.parent_technique_id) if model.parent_technique_id else None
        ),
        tactic_ids=tuple(TacticId(t) for t in model.tactic_ids),
        platforms=tuple(model.platforms),
        data_sources=tuple(model.data_sources),
        is_deprecated=model.is_deprecated,
        is_revoked=model.is_revoked,
        framework_version=model.framework_version,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _technique_from_domain(
    technique: AttackTechnique, *, id: str, now: datetime
) -> AttackTechniqueModel:
    return AttackTechniqueModel(
        id=id,
        technique_id=technique.technique_id.value,
        name=technique.name,
        description=technique.description,
        stix_id=technique.stix_id,
        is_sub_technique=technique.is_sub_technique,
        parent_technique_id=(
            technique.parent_technique_id.value if technique.parent_technique_id else None
        ),
        tactic_ids=[t.value for t in technique.tactic_ids],
        platforms=list(technique.platforms),
        data_sources=list(technique.data_sources),
        is_deprecated=technique.is_deprecated,
        is_revoked=technique.is_revoked,
        framework_version=technique.framework_version,
        created_at=technique.created_at or now,
        updated_at=now,
    )


def _relationship_to_domain(
    model: AttackTechniqueRelationshipModel,
) -> AttackTechniqueRelationship:
    return AttackTechniqueRelationship(
        stix_id=model.stix_id,
        relationship_type=AttackRelationshipType(model.relationship_type),
        source_ref=model.source_ref,
        target_ref=model.target_ref,
        source_technique_id=(
            TechniqueId(model.source_technique_id) if model.source_technique_id else None
        ),
        target_technique_id=(
            TechniqueId(model.target_technique_id) if model.target_technique_id else None
        ),
        description=model.description,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _relationship_from_domain(
    relationship: AttackTechniqueRelationship, *, id: str, now: datetime
) -> AttackTechniqueRelationshipModel:
    return AttackTechniqueRelationshipModel(
        id=id,
        stix_id=relationship.stix_id,
        relationship_type=relationship.relationship_type.value,
        source_ref=relationship.source_ref,
        target_ref=relationship.target_ref,
        source_technique_id=(
            relationship.source_technique_id.value if relationship.source_technique_id else None
        ),
        target_technique_id=(
            relationship.target_technique_id.value if relationship.target_technique_id else None
        ),
        description=relationship.description,
        created_at=relationship.created_at or now,
        updated_at=now,
    )


def _vulnerability_to_domain(model: VulnerabilityModel) -> Vulnerability:
    cvss_v3 = None
    if model.cvss_v3_score is not None and model.cvss_v3_vector and model.cvss_v3_version:
        cvss_v3 = CvssScore(
            version=model.cvss_v3_version,
            base_score=model.cvss_v3_score,
            vector=model.cvss_v3_vector,
        )
    epss = None
    if model.epss_probability is not None and model.epss_percentile is not None:
        epss = EpssScore(
            probability=model.epss_probability,
            percentile=model.epss_percentile,
            model_date=(
                model.epss_model_date.date() if model.epss_model_date else datetime.now(UTC).date()
            ),
        )
    return Vulnerability(
        cve_id=CveId(model.cve_id),
        description=model.description,
        cvss_v3=cvss_v3,
        cvss_v2_score=model.cvss_v2_score,
        epss=epss,
        is_kev=model.is_kev,
        kev_date_added=model.kev_date_added,
        kev_due_date=model.kev_due_date,
        kev_vulnerability_name=model.kev_vulnerability_name,
        kev_short_description=model.kev_short_description,
        kev_required_action=model.kev_required_action,
        kev_known_ransomware_use=model.kev_known_ransomware_use,
        published_at=model.published_at,
        last_modified_at=model.last_modified_at,
        source_last_synced_at=model.source_last_synced_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _vulnerability_from_domain(
    vulnerability: Vulnerability, *, id: str, now: datetime
) -> VulnerabilityModel:
    epss_model_date = None
    if vulnerability.epss is not None:
        epss_model_date = datetime(
            vulnerability.epss.model_date.year,
            vulnerability.epss.model_date.month,
            vulnerability.epss.model_date.day,
            tzinfo=UTC,
        )
    return VulnerabilityModel(
        id=id,
        cve_id=vulnerability.cve_id.value,
        description=vulnerability.description,
        cvss_v3_score=vulnerability.cvss_v3.base_score if vulnerability.cvss_v3 else None,
        cvss_v3_vector=vulnerability.cvss_v3.vector if vulnerability.cvss_v3 else None,
        cvss_v3_version=vulnerability.cvss_v3.version if vulnerability.cvss_v3 else None,
        cvss_v2_score=vulnerability.cvss_v2_score,
        epss_probability=vulnerability.epss.probability if vulnerability.epss else None,
        epss_percentile=vulnerability.epss.percentile if vulnerability.epss else None,
        epss_model_date=epss_model_date,
        is_kev=vulnerability.is_kev,
        kev_date_added=vulnerability.kev_date_added,
        kev_due_date=vulnerability.kev_due_date,
        kev_vulnerability_name=vulnerability.kev_vulnerability_name,
        kev_short_description=vulnerability.kev_short_description,
        kev_required_action=vulnerability.kev_required_action,
        kev_known_ransomware_use=vulnerability.kev_known_ransomware_use,
        published_at=vulnerability.published_at,
        last_modified_at=vulnerability.last_modified_at,
        source_last_synced_at=vulnerability.source_last_synced_at,
        created_at=vulnerability.created_at or now,
        updated_at=now,
    )


def _ingestion_record_to_domain(model: StixIngestionLogModel) -> ReferenceDataIngestionRecord:
    return ReferenceDataIngestionRecord(
        id=model.id,
        source_system=ReferenceDataSource(model.source_system),
        scope=IngestionScope(model.scope),
        organization_id=model.organization_id,
        object_type=model.object_type,
        external_id=model.external_id,
        content_hash=model.content_hash,
        ingested_at=model.ingested_at,
        batch_id=model.batch_id,
    )


# ─── Repositories ─────────────────────────────────────────────────────────────


class SqlAlchemyAttackTacticRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, tactic: AttackTactic) -> AttackTactic:
        existing_stmt = select(AttackTacticModel).where(
            AttackTacticModel.tactic_id == tactic.tactic_id.value
        )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        model = _tactic_from_domain(
            tactic, id=existing.id if existing else _new_id(), now=now
        )
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one_or_none()
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.name = model.name
            winner.shortname = model.shortname
            winner.description = model.description
            winner.stix_id = model.stix_id
            winner.url = model.url
            winner.updated_at = now
            await self._session.flush()
            model = winner
        return _tactic_to_domain(model)

    async def get_by_id(self, tactic_id: str) -> AttackTactic | None:
        stmt = select(AttackTacticModel).where(AttackTacticModel.tactic_id == tactic_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _tactic_to_domain(model) if model else None

    async def list_all(self, *, limit: int = 200, offset: int = 0) -> list[AttackTactic]:
        stmt = (
            select(AttackTacticModel)
            .order_by(AttackTacticModel.tactic_id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_tactic_to_domain(m) for m in result.scalars().all()]

    async def count(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(AttackTacticModel))
        return int(result.scalar_one())

    async def list_all_ids(self) -> set[str]:
        """All currently-stored `tactic_id` values. Used by the admin
        loading service to validate an `AttackTechnique`'s `tactic_ids`
        against real, already-ingested tactics before persisting the
        technique — never a fabricated tactic reference."""
        result = await self._session.execute(select(AttackTacticModel.tactic_id))
        return set(result.scalars().all())


class SqlAlchemyAttackTechniqueRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, technique: AttackTechnique) -> AttackTechnique:
        existing_stmt = select(AttackTechniqueModel).where(
            AttackTechniqueModel.technique_id == technique.technique_id.value
        )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        model = _technique_from_domain(
            technique, id=existing.id if existing else _new_id(), now=now
        )
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one_or_none()
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.name = model.name
            winner.description = model.description
            winner.stix_id = model.stix_id
            winner.is_sub_technique = model.is_sub_technique
            winner.parent_technique_id = model.parent_technique_id
            winner.tactic_ids = model.tactic_ids
            winner.platforms = model.platforms
            winner.data_sources = model.data_sources
            winner.is_deprecated = model.is_deprecated
            winner.is_revoked = model.is_revoked
            winner.framework_version = model.framework_version
            winner.updated_at = now
            await self._session.flush()
            model = winner
        return _technique_to_domain(model)

    async def get_by_id(self, technique_id: str) -> AttackTechnique | None:
        stmt = select(AttackTechniqueModel).where(
            AttackTechniqueModel.technique_id == technique_id
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _technique_to_domain(model) if model else None

    async def list_by_tactic(
        self, tactic_id: str, *, limit: int = 200, offset: int = 0
    ) -> list[AttackTechnique]:
        # tactic_ids is a JSON array column; containment check via the
        # portable `@>` JSON-array operator is unavailable on plain JSON
        # (only JSONB), so this filters in Python after a bounded page
        # fetch — acceptable at Phase 1 catalog scale (~700 techniques).
        stmt = select(AttackTechniqueModel).order_by(AttackTechniqueModel.technique_id)
        result = await self._session.execute(stmt)
        matches = [
            m for m in result.scalars().all() if tactic_id in (m.tactic_ids or [])
        ]
        return [_technique_to_domain(m) for m in matches[offset : offset + limit]]

    async def list_sub_techniques(self, parent_technique_id: str) -> list[AttackTechnique]:
        stmt = (
            select(AttackTechniqueModel)
            .where(AttackTechniqueModel.parent_technique_id == parent_technique_id)
            .order_by(AttackTechniqueModel.technique_id)
        )
        result = await self._session.execute(stmt)
        return [_technique_to_domain(m) for m in result.scalars().all()]

    async def search_by_name(
        self, query: str, *, limit: int = 50, offset: int = 0
    ) -> list[AttackTechnique]:
        """Full-text search backed by the GIN index created in migration
        0035 (`ix_atk_name_fts`)."""
        tsquery = _to_tsquery_prefix(query)
        if not tsquery:
            return []
        stmt = (
            select(AttackTechniqueModel)
            .where(
                text("to_tsvector('english', name) @@ to_tsquery('english', :q)")
            )
            .params(q=tsquery)
            .order_by(AttackTechniqueModel.technique_id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_technique_to_domain(m) for m in result.scalars().all()]

    async def count(self) -> int:
        result = await self._session.execute(
            select(func.count()).select_from(AttackTechniqueModel)
        )
        return int(result.scalar_one())

    async def list_all_ids(self) -> set[str]:
        """All currently-stored `technique_id` values. Used by the
        admin loading service to pre-validate `parent_technique_id` and
        relationship technique references against real, resolvable
        techniques *before* attempting to persist — so a dangling
        reference is reported as an isolated per-item validation error
        rather than surfacing as an unhandled `IntegrityError` when the
        deferred self-referencing FK is finally checked at COMMIT,
        which would otherwise abort the entire batch."""
        result = await self._session.execute(select(AttackTechniqueModel.technique_id))
        return set(result.scalars().all())

    async def upsert_relationship(
        self, relationship: AttackTechniqueRelationship
    ) -> AttackTechniqueRelationship:
        existing_stmt = select(AttackTechniqueRelationshipModel).where(
            AttackTechniqueRelationshipModel.stix_id == relationship.stix_id
        )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        model = _relationship_from_domain(
            relationship, id=existing.id if existing else _new_id(), now=now
        )
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one_or_none()
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.relationship_type = model.relationship_type
            winner.source_ref = model.source_ref
            winner.target_ref = model.target_ref
            winner.source_technique_id = model.source_technique_id
            winner.target_technique_id = model.target_technique_id
            winner.description = model.description
            winner.updated_at = now
            await self._session.flush()
            model = winner
        return _relationship_to_domain(model)

    async def list_relationships_for_technique(
        self,
        technique_id: str,
        *,
        relationship_type: AttackRelationshipType | None = None,
    ) -> list[AttackTechniqueRelationship]:
        stmt = select(AttackTechniqueRelationshipModel).where(
            or_(
                AttackTechniqueRelationshipModel.source_technique_id == technique_id,
                AttackTechniqueRelationshipModel.target_technique_id == technique_id,
            )
        )
        if relationship_type is not None:
            stmt = stmt.where(
                AttackTechniqueRelationshipModel.relationship_type == relationship_type.value
            )
        result = await self._session.execute(stmt)
        return [_relationship_to_domain(m) for m in result.scalars().all()]


class SqlAlchemyVulnerabilityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, vulnerability: Vulnerability) -> Vulnerability:
        existing_stmt = select(VulnerabilityModel).where(
            VulnerabilityModel.cve_id == vulnerability.cve_id.value
        )
        result = await self._session.execute(existing_stmt)
        existing = result.scalar_one_or_none()
        now = datetime.now(UTC)
        model = _vulnerability_from_domain(
            vulnerability, id=existing.id if existing else _new_id(), now=now
        )
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one_or_none()
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.description = model.description
            winner.cvss_v3_score = model.cvss_v3_score
            winner.cvss_v3_vector = model.cvss_v3_vector
            winner.cvss_v3_version = model.cvss_v3_version
            winner.cvss_v2_score = model.cvss_v2_score
            winner.epss_probability = model.epss_probability
            winner.epss_percentile = model.epss_percentile
            winner.epss_model_date = model.epss_model_date
            winner.is_kev = model.is_kev
            winner.kev_date_added = model.kev_date_added
            winner.kev_due_date = model.kev_due_date
            winner.kev_vulnerability_name = model.kev_vulnerability_name
            winner.kev_short_description = model.kev_short_description
            winner.kev_required_action = model.kev_required_action
            winner.kev_known_ransomware_use = model.kev_known_ransomware_use
            winner.published_at = model.published_at
            winner.last_modified_at = model.last_modified_at
            winner.source_last_synced_at = model.source_last_synced_at
            winner.updated_at = now
            await self._session.flush()
            model = winner
        return _vulnerability_to_domain(model)

    async def get_by_cve_id(self, cve_id: str) -> Vulnerability | None:
        stmt = select(VulnerabilityModel).where(VulnerabilityModel.cve_id == cve_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _vulnerability_to_domain(model) if model else None

    async def list_by_kev_flag(
        self, is_kev: bool = True, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        stmt = (
            select(VulnerabilityModel)
            .where(VulnerabilityModel.is_kev.is_(is_kev))
            .order_by(VulnerabilityModel.kev_date_added.desc().nullslast())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_vulnerability_to_domain(m) for m in result.scalars().all()]

    async def list_by_epss_threshold(
        self, min_probability: float, *, limit: int = 200, offset: int = 0
    ) -> list[Vulnerability]:
        stmt = (
            select(VulnerabilityModel)
            .where(VulnerabilityModel.epss_probability >= min_probability)
            .order_by(VulnerabilityModel.epss_probability.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_vulnerability_to_domain(m) for m in result.scalars().all()]

    async def count(self) -> int:
        result = await self._session.execute(
            select(func.count()).select_from(VulnerabilityModel)
        )
        return int(result.scalar_one())


class SqlAlchemyReferenceDataIngestionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_record(
        self, record: ReferenceDataIngestionRecord
    ) -> tuple[ReferenceDataIngestionRecord, bool]:
        model = StixIngestionLogModel(
            id=record.id,
            source_system=record.source_system.value,
            scope=record.scope.value,
            organization_id=record.organization_id,
            object_type=record.object_type,
            external_id=record.external_id,
            content_hash=record.content_hash,
            batch_id=record.batch_id,
            ingested_at=record.ingested_at,
        )
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return _ingestion_record_to_domain(model), True
        except IntegrityError:
            existing = await self.find(
                record.source_system,
                record.external_id,
                scope=record.scope,
                organization_id=record.organization_id,
            )
            if existing is None:  # pragma: no cover - should be unreachable
                raise
            existing_stmt = select(StixIngestionLogModel).where(
                StixIngestionLogModel.id == existing.id
            )
            result = await self._session.execute(existing_stmt)
            winner = result.scalar_one()
            winner.object_type = model.object_type
            winner.content_hash = model.content_hash
            winner.batch_id = model.batch_id
            winner.ingested_at = model.ingested_at
            await self._session.flush()
            return _ingestion_record_to_domain(winner), False

    async def find(
        self,
        source_system: ReferenceDataSource,
        external_id: str,
        *,
        scope: IngestionScope,
        organization_id: str | None = None,
    ) -> ReferenceDataIngestionRecord | None:
        stmt = select(StixIngestionLogModel).where(
            StixIngestionLogModel.source_system == source_system.value,
            StixIngestionLogModel.external_id == external_id,
            StixIngestionLogModel.scope == scope.value,
        )
        if scope is IngestionScope.GLOBAL:
            stmt = stmt.where(StixIngestionLogModel.organization_id.is_(None))
        else:
            stmt = stmt.where(StixIngestionLogModel.organization_id == organization_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _ingestion_record_to_domain(model) if model else None

    async def list_recent(
        self,
        *,
        source_system: ReferenceDataSource | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ReferenceDataIngestionRecord]:
        stmt = select(StixIngestionLogModel).order_by(StixIngestionLogModel.ingested_at.desc())
        if source_system is not None:
            stmt = stmt.where(StixIngestionLogModel.source_system == source_system.value)
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_ingestion_record_to_domain(m) for m in result.scalars().all()]

    async def count_by_source(self, source_system: ReferenceDataSource) -> int:
        result = await self._session.execute(
            select(func.count())
            .select_from(StixIngestionLogModel)
            .where(StixIngestionLogModel.source_system == source_system.value)
        )
        return int(result.scalar_one())


def _new_id() -> str:
    from redforge.shared.identifiers import EntityId

    return str(EntityId.generate())


_TSQUERY_UNSAFE_RE = re.compile(r"[^\w]")


def _to_tsquery_prefix(query: str) -> str:
    """Turn free-text search input into a safe `to_tsquery` argument:
    each whitespace-separated term is stripped of any character with
    special meaning to `to_tsquery` and becomes a prefix-match lexeme
    joined with AND. Never interpolates the raw query string into SQL —
    the result is still always passed as a bound parameter, this
    sanitization only prevents a malformed/attacker-controlled query
    string from producing a `to_tsquery` syntax error."""
    terms = [_TSQUERY_UNSAFE_RE.sub("", t) for t in query.split()]
    terms = [t for t in terms if t]
    if not terms:
        return ""
    return " & ".join(f"{t}:*" for t in terms)
