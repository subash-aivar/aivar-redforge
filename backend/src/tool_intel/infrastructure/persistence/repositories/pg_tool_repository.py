"""PgToolRepository — SQLAlchemy implementation of `IToolRepository`,
mirroring `campaign_intel.infrastructure.persistence.repositories.
pg_campaign_repository.PgCampaignRepository`'s translation shape (no
business logic, no authorization) plus its real optimistic-concurrency
compare-and-swap pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (aliases, platforms, capabilities, evidence
citations, source attributions) are wholesale-replaced on every
`save()` — the aggregate itself is the sole authority on their
contents. Version history is append-only: only rows whose `version` is
not already persisted are inserted, matching the aggregate's own
append-only invariant."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from tool_intel.application.ports.i_tool_repository import IToolRepository
from tool_intel.domain.aggregates.tool import Tool
from tool_intel.domain.value_objects.enums import (
    ToolCapability,
    ToolCategory,
    ToolConfidence,
    ToolLifecycleStatus,
    ToolPlatform,
)
from tool_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from tool_intel.domain.value_objects.identifiers import TenantId, ToolId
from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily
from tool_intel.domain.value_objects.version_record import VersionRecord
from tool_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
    ToolIntelIntegrityError,
)
from tool_intel.infrastructure.persistence.models.tool_models import (
    ToolAliasModel,
    ToolCapabilityModel,
    ToolEvidenceCitationModel,
    ToolModel,
    ToolPlatformModel,
    ToolSourceAttributionModel,
    ToolVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return ToolModel.tenant_id.is_(None)
    return ToolModel.tenant_id == tenant_uuid


def _row_to_tool(row: ToolModel) -> Tool:
    return Tool(
        tool_id=ToolId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        canonical_name=row.canonical_name,
        lifecycle_status=ToolLifecycleStatus(row.lifecycle_status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        category=ToolCategory(row.category),
        family=ToolFamily(family_name=row.family_name) if row.family_name else None,
        aliases=tuple(ToolAlias(a.value) for a in row.aliases),
        platforms=tuple(ToolPlatform(p.platform) for p in row.platforms),
        capabilities=tuple(ToolCapability(c.capability) for c in row.capabilities),
        confidence=ToolConfidence(row.confidence),
        evidence_citations=tuple(EvidenceCitation(e.value) for e in row.evidence_citations),
        source_attributions=tuple(
            SourceAttribution(
                source_system=s.source_system,
                reference=s.reference,
                observed_at=s.observed_at,
                confidence=ToolConfidence(s.confidence),
                notes=s.notes,
            )
            for s in row.source_attributions
        ),
        version_history=tuple(
            VersionRecord(
                version=v.version,
                changed_at=v.changed_at,
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in sorted(row.version_history, key=lambda v: v.version)
        ),
        superseded_by=ToolId(row.superseded_by) if row.superseded_by else None,
        row_version=row.row_version,
    )


class PgToolRepository(IToolRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, tool: Tool) -> None:
        try:
            await self._save(tool)
        except IntegrityError as exc:
            raise ToolIntelIntegrityError("save Tool", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise ToolIntelIntegrityError("save Tool", str(exc)) from exc

    async def _save(self, tool: Tool) -> None:
        tool_uuid = tool.tool_id.value
        tenant_uuid = _tenant_uuid(tool.tenant_id)
        superseded_by_uuid = tool.superseded_by.value if tool.superseded_by is not None else None
        family_name = tool.family.family_name if tool.family is not None else None

        row = await self._session.get(ToolModel, tool_uuid)
        if row is None:
            row = ToolModel(
                id=tool_uuid,
                tenant_id=tenant_uuid,
                canonical_name=tool.canonical_name,
                category=tool.category.value,
                lifecycle_status=tool.lifecycle_status.value,
                family_name=family_name,
                confidence=tool.confidence.value,
                superseded_by=superseded_by_uuid,
                created_at=tool.created_at,
                updated_at=tool.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(tool, tool_uuid)
            await self._session.flush()
            tool.row_version = 1
            return

        expected = tool.row_version
        result = await self._session.execute(
            update(ToolModel)
            .where(
                ToolModel.id == tool_uuid,
                ToolModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                category=tool.category.value,
                lifecycle_status=tool.lifecycle_status.value,
                family_name=family_name,
                confidence=tool.confidence.value,
                superseded_by=superseded_by_uuid,
                updated_at=tool.updated_at,
                row_version=expected + 1,
            )
            .returning(ToolModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(ToolModel, tool_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(tool.tool_id), expected, actual)

        await self._replace_children(tool, tool_uuid)
        await self._session.flush()
        tool.row_version = int(new_version)

    async def _replace_children(self, tool: Tool, tool_uuid: UUID) -> None:
        await self._session.execute(
            delete(ToolAliasModel).where(ToolAliasModel.tool_id == tool_uuid)
        )
        for alias in tool.aliases:
            self._session.add(ToolAliasModel(id=uuid4(), tool_id=tool_uuid, value=alias.value))

        await self._session.execute(
            delete(ToolPlatformModel).where(ToolPlatformModel.tool_id == tool_uuid)
        )
        for platform in tool.platforms:
            self._session.add(
                ToolPlatformModel(id=uuid4(), tool_id=tool_uuid, platform=platform.value)
            )

        await self._session.execute(
            delete(ToolCapabilityModel).where(ToolCapabilityModel.tool_id == tool_uuid)
        )
        for capability in tool.capabilities:
            self._session.add(
                ToolCapabilityModel(id=uuid4(), tool_id=tool_uuid, capability=capability.value)
            )

        await self._session.execute(
            delete(ToolEvidenceCitationModel).where(ToolEvidenceCitationModel.tool_id == tool_uuid)
        )
        for citation in tool.evidence_citations:
            self._session.add(
                ToolEvidenceCitationModel(id=uuid4(), tool_id=tool_uuid, value=citation.value)
            )

        await self._session.execute(
            delete(ToolSourceAttributionModel).where(
                ToolSourceAttributionModel.tool_id == tool_uuid
            )
        )
        for attribution in tool.source_attributions:
            self._session.add(
                ToolSourceAttributionModel(
                    id=uuid4(),
                    tool_id=tool_uuid,
                    source_system=attribution.source_system,
                    reference=attribution.reference,
                    observed_at=attribution.observed_at,
                    confidence=attribution.confidence.value,
                    notes=attribution.notes,
                )
            )

        # Version history is append-only: only insert versions not
        # already persisted (never delete/replace, matching the
        # aggregate's own append-only invariant).
        result = await self._session.execute(
            select(ToolVersionModel.version).where(ToolVersionModel.tool_id == tool_uuid)
        )
        existing_versions = {r[0] for r in result.all()}
        for record in tool.version_history:
            if record.version not in existing_versions:
                self._session.add(
                    ToolVersionModel(
                        id=uuid4(),
                        tool_id=tool_uuid,
                        version=record.version,
                        changed_at=record.changed_at,
                        change_summary=record.change_summary,
                        source=record.source,
                    )
                )

    async def get(self, tenant_id: TenantId | None, tool_id: ToolId) -> Tool | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ToolModel).where(ToolModel.id == tool_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_tool(row)

    async def get_any(self, tool_id: ToolId) -> Tool | None:
        row = await self._session.get(ToolModel, tool_id.value)
        if row is None:
            return None
        return _row_to_tool(row)

    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Tool | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ToolModel).where(ToolModel.canonical_name == canonical_name)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_tool(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: ToolLifecycleStatus | None = None,
        category: ToolCategory | None = None,
        platform: ToolPlatform | None = None,
        capability: ToolCapability | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Tool]:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(ToolModel).where(_tenant_filter(tenant_uuid))
        if lifecycle_status is not None:
            stmt = stmt.where(ToolModel.lifecycle_status == lifecycle_status.value)
        if category is not None:
            stmt = stmt.where(ToolModel.category == category.value)
        if platform is not None:
            stmt = stmt.where(
                ToolModel.id.in_(
                    select(ToolPlatformModel.tool_id).where(
                        ToolPlatformModel.platform == platform.value
                    )
                )
            )
        if capability is not None:
            stmt = stmt.where(
                ToolModel.id.in_(
                    select(ToolCapabilityModel.tool_id).where(
                        ToolCapabilityModel.capability == capability.value
                    )
                )
            )
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(ToolModel.created_at.desc(), ToolModel.id.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_tool(row) for row in rows]
