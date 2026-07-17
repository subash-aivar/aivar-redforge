"""SQLAlchemy implementation of ControlCatalogRepository."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select, update

from redforge.domain.compliance.entity import (
    ControlCatalog,
    ControlMapping,
    ControlRequirement,
    FrameworkDefinition,
)
from redforge.domain.compliance.value_objects import (
    ControlDomain,
    ControlMappingVersion,
    ControlSeverity,
    FrameworkKey,
    FrameworkMetadata,
    FrameworkStatus,
    MappingConfidenceHint,
    PolicyThreshold,
)
from redforge.infrastructure.database.models.compliance import (
    ComplianceFrameworkModel,
    ComplianceMappingModel,
    ComplianceRequirementModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyControlCatalogRepository:
    """Async SQLAlchemy repository for the compliance control catalog."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ── Framework operations ─────────────────────────────────────────────

    async def get_framework(self, key: FrameworkKey) -> FrameworkDefinition | None:
        row = await self._session.scalar(
            select(ComplianceFrameworkModel).where(ComplianceFrameworkModel.key == key.value)
        )
        if row is None:
            return None
        requirements = await self._load_requirements_for_framework(key)
        return self._framework_from_row(row, requirements)

    async def list_frameworks(
        self,
        *,
        status: FrameworkStatus | None = None,
    ) -> list[FrameworkDefinition]:
        stmt = select(ComplianceFrameworkModel)
        if status is not None:
            stmt = stmt.where(ComplianceFrameworkModel.status == status.value)
        rows = (await self._session.scalars(stmt)).all()
        results = []
        for row in rows:
            requirements = await self._load_requirements_for_framework(
                FrameworkKey(row.key)
            )
            results.append(self._framework_from_row(row, requirements))
        return results

    async def save_framework(self, framework: FrameworkDefinition) -> None:
        existing = await self._session.scalar(
            select(ComplianceFrameworkModel).where(
                ComplianceFrameworkModel.id == str(framework.id)
            )
        )
        now = datetime.now(UTC)
        if existing is None:
            self._session.add(
                ComplianceFrameworkModel(
                    id=str(framework.id),
                    key=framework.key.value,
                    status=framework.status.value,
                    metadata_={
                        "name": framework.metadata.name,
                        "version": framework.metadata.version,
                        "issuing_body": framework.metadata.issuing_body,
                        "description": framework.metadata.description,
                        "effective_date": framework.metadata.effective_date,
                        "tags": list(framework.metadata.tags),
                        "external_url": framework.metadata.external_url,
                    },
                    created_at=framework.created_at,
                    updated_at=now,
                )
            )
        else:
            await self._session.execute(
                update(ComplianceFrameworkModel)
                .where(ComplianceFrameworkModel.id == str(framework.id))
                .values(
                    status=framework.status.value,
                    metadata_={
                        "name": framework.metadata.name,
                        "version": framework.metadata.version,
                        "issuing_body": framework.metadata.issuing_body,
                        "description": framework.metadata.description,
                        "effective_date": framework.metadata.effective_date,
                        "tags": list(framework.metadata.tags),
                        "external_url": framework.metadata.external_url,
                    },
                    updated_at=now,
                )
            )
        # Upsert requirements
        for req in framework.requirements.values():
            await self.save_requirement(req)

    # ── Requirement operations ────────────────────────────────────────────

    async def get_requirement(
        self, requirement_id: EntityId
    ) -> ControlRequirement | None:
        row = await self._session.scalar(
            select(ComplianceRequirementModel).where(
                ComplianceRequirementModel.id == str(requirement_id)
            )
        )
        return self._requirement_from_row(row) if row else None

    async def save_requirement(self, requirement: ControlRequirement) -> None:
        existing = await self._session.scalar(
            select(ComplianceRequirementModel).where(
                ComplianceRequirementModel.id == str(requirement.id)
            )
        )
        now = datetime.now(UTC)
        if existing is None:
            self._session.add(
                ComplianceRequirementModel(
                    id=str(requirement.id),
                    framework_key=requirement.framework_key.value,
                    requirement_ref=requirement.requirement_ref,
                    title=requirement.title,
                    description=requirement.description,
                    domain=requirement.domain.value,
                    severity=requirement.severity.value,
                    guidance=requirement.guidance,
                    policy_threshold=requirement.policy_threshold.value,
                    tags=list(requirement.tags),
                    external_ref=requirement.external_ref,
                    created_at=requirement.created_at,
                    updated_at=now,
                )
            )
        else:
            await self._session.execute(
                update(ComplianceRequirementModel)
                .where(ComplianceRequirementModel.id == str(requirement.id))
                .values(
                    title=requirement.title,
                    description=requirement.description,
                    domain=requirement.domain.value,
                    severity=requirement.severity.value,
                    guidance=requirement.guidance,
                    policy_threshold=requirement.policy_threshold.value,
                    tags=list(requirement.tags),
                    external_ref=requirement.external_ref,
                    updated_at=now,
                )
            )

    async def list_requirements(
        self,
        framework_key: FrameworkKey,
        *,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[ControlRequirement], int]:
        base = select(ComplianceRequirementModel).where(
            ComplianceRequirementModel.framework_key == framework_key.value
        )
        if search:
            pattern = f"%{search}%"
            base = base.where(
                ComplianceRequirementModel.title.ilike(pattern)
                | ComplianceRequirementModel.requirement_ref.ilike(pattern)
            )

        count_stmt = select(func.count()).select_from(base.subquery())
        total = (await self._session.scalar(count_stmt)) or 0

        rows = (
            await self._session.scalars(
                base.order_by(ComplianceRequirementModel.requirement_ref)
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return [self._requirement_from_row(r) for r in rows], total

    # ── Mapping operations ────────────────────────────────────────────────

    async def get_mapping(self, mapping_id: EntityId) -> ControlMapping | None:
        row = await self._session.scalar(
            select(ComplianceMappingModel).where(
                ComplianceMappingModel.id == str(mapping_id)
            )
        )
        return self._mapping_from_row(row) if row else None

    async def save_mapping(self, mapping: ControlMapping) -> None:
        existing = await self._session.scalar(
            select(ComplianceMappingModel).where(
                ComplianceMappingModel.id == str(mapping.id)
            )
        )
        now = datetime.now(UTC)
        if existing is None:
            self._session.add(
                ComplianceMappingModel(
                    id=str(mapping.id),
                    source_requirement_id=str(mapping.source_requirement_id),
                    target_requirement_id=str(mapping.target_requirement_id),
                    source_framework_key=mapping.source_framework_key.value,
                    target_framework_key=mapping.target_framework_key.value,
                    confidence=mapping.confidence.value,
                    rationale=mapping.rationale,
                    version=str(mapping.version),
                    is_active=mapping.is_active,
                    created_at=mapping.created_at,
                    updated_at=now,
                )
            )
        else:
            await self._session.execute(
                update(ComplianceMappingModel)
                .where(ComplianceMappingModel.id == str(mapping.id))
                .values(
                    confidence=mapping.confidence.value,
                    rationale=mapping.rationale,
                    version=str(mapping.version),
                    is_active=mapping.is_active,
                    updated_at=now,
                )
            )

    async def list_mappings(
        self,
        *,
        source_framework_key: FrameworkKey | None = None,
        target_framework_key: FrameworkKey | None = None,
        active_only: bool = True,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[ControlMapping], int]:
        base = select(ComplianceMappingModel)
        if active_only:
            base = base.where(ComplianceMappingModel.is_active.is_(True))
        if source_framework_key:
            base = base.where(
                ComplianceMappingModel.source_framework_key == source_framework_key.value
            )
        if target_framework_key:
            base = base.where(
                ComplianceMappingModel.target_framework_key == target_framework_key.value
            )

        count_stmt = select(func.count()).select_from(base.subquery())
        total = (await self._session.scalar(count_stmt)) or 0

        rows = (
            await self._session.scalars(
                base.order_by(ComplianceMappingModel.created_at).limit(limit).offset(offset)
            )
        ).all()
        return [self._mapping_from_row(r) for r in rows], total

    # ── Catalog (aggregate root loader) ──────────────────────────────────

    async def get_catalog(self) -> ControlCatalog:
        """Load a catalog shell for in-memory aggregate operations.

        Phase 1 does not persist a catalog root row; mutations are made
        directly to framework/requirement/mapping rows.  The catalog ID
        is ephemeral per-request and is only used for in-memory aggregate
        identity — it is never compared to or stored in the database.
        """
        frameworks = await self.list_frameworks()
        mappings_list, _ = await self.list_mappings(active_only=False, limit=5000)
        return ControlCatalog.reconstitute(
            id_=EntityId.generate(),
            frameworks=frameworks,
            mappings=mappings_list,
        )

    # ── Private helpers ───────────────────────────────────────────────────

    async def _load_requirements_for_framework(
        self, key: FrameworkKey
    ) -> list[ControlRequirement]:
        rows = (
            await self._session.scalars(
                select(ComplianceRequirementModel).where(
                    ComplianceRequirementModel.framework_key == key.value
                )
            )
        ).all()
        return [self._requirement_from_row(r) for r in rows]

    @staticmethod
    def _framework_from_row(
        row: ComplianceFrameworkModel,
        requirements: list[ControlRequirement],
    ) -> FrameworkDefinition:
        meta_dict = dict(row.metadata_)
        return FrameworkDefinition(
            id=EntityId.from_string(row.id),
            key=FrameworkKey(row.key),
            metadata=FrameworkMetadata.from_dict(meta_dict),
            status=FrameworkStatus(row.status),
            requirements={r.id: r for r in requirements},
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _requirement_from_row(row: ComplianceRequirementModel) -> ControlRequirement:
        return ControlRequirement(
            id=EntityId.from_string(row.id),
            framework_key=FrameworkKey(row.framework_key),
            requirement_ref=row.requirement_ref,
            title=row.title,
            description=row.description,
            domain=ControlDomain(row.domain),
            severity=ControlSeverity(row.severity),
            guidance=row.guidance,
            policy_threshold=PolicyThreshold(row.policy_threshold),
            tags=tuple(row.tags or []),
            external_ref=row.external_ref,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def _mapping_from_row(row: ComplianceMappingModel) -> ControlMapping:
        ver_parts = (row.version or "1.0").split(".")
        return ControlMapping(
            id=EntityId.from_string(row.id),
            source_requirement_id=EntityId.from_string(row.source_requirement_id),
            target_requirement_id=EntityId.from_string(row.target_requirement_id),
            source_framework_key=FrameworkKey(row.source_framework_key),
            target_framework_key=FrameworkKey(row.target_framework_key),
            confidence=MappingConfidenceHint(row.confidence),
            rationale=row.rationale,
            version=ControlMappingVersion(
                major=int(ver_parts[0]), minor=int(ver_parts[1])
            ),
            is_active=row.is_active,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )
