"""PgInfrastructureRepository — SQLAlchemy implementation of
`IInfrastructureRepository`, mirroring `tool_intel.infrastructure.
persistence.repositories.pg_tool_repository.PgToolRepository`'s
translation shape (no business logic, no authorization) plus its real
optimistic-concurrency compare-and-swap pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (regions, evidence citations, source attributions)
are wholesale-replaced on every `save()` — the aggregate itself is the
sole authority on their contents. Version history is append-only: only
rows whose `version` is not already persisted are inserted, matching
the aggregate's own append-only invariant."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from infrastructure_intel.application.ports.i_infrastructure_repository import (
    IInfrastructureRepository,
)
from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureConfidence,
    InfrastructureLifecycleStatus,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from infrastructure_intel.domain.value_objects.hosting import (
    CloudProviderRef,
    HostingProviderRef,
    NetworkOwnership,
    Region,
)
from infrastructure_intel.domain.value_objects.identifiers import (
    InfrastructureId,
    TenantId,
)
from infrastructure_intel.domain.value_objects.version_record import VersionRecord
from infrastructure_intel.infrastructure.persistence.exceptions import (
    InfrastructureIntelIntegrityError,
    OptimisticLockConflictError,
)
from infrastructure_intel.infrastructure.persistence.models.infrastructure_models import (
    InfrastructureEvidenceCitationModel,
    InfrastructureModel,
    InfrastructureRegionModel,
    InfrastructureSourceAttributionModel,
    InfrastructureVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return InfrastructureModel.tenant_id.is_(None)
    return InfrastructureModel.tenant_id == tenant_uuid


def _row_to_infrastructure(row: InfrastructureModel) -> Infrastructure:
    return Infrastructure(
        infrastructure_id=InfrastructureId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        infrastructure_type=InfrastructureType(row.infrastructure_type),
        normalized_identifier=row.normalized_identifier,
        lifecycle_status=InfrastructureLifecycleStatus(row.lifecycle_status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        hosting_provider=(
            HostingProviderRef(provider_name=row.hosting_provider_name)
            if row.hosting_provider_name
            else None
        ),
        cloud_provider=(
            CloudProviderRef(provider=CloudProvider(row.cloud_provider))
            if row.cloud_provider
            else None
        ),
        regions=tuple(
            Region(region_code=r.region_code)
            for r in sorted(row.regions, key=lambda r: r.region_code)
        ),
        network_ownership=(
            NetworkOwnership(
                registrant_organization=row.registrant_organization,
                abuse_contact=row.abuse_contact,
                notes=row.ownership_notes,
            )
            if row.registrant_organization
            else None
        ),
        confidence=InfrastructureConfidence(row.confidence),
        evidence_citations=tuple(EvidenceCitation(e.value) for e in row.evidence_citations),
        source_attributions=tuple(
            SourceAttribution(
                source_system=s.source_system,
                reference=s.reference,
                observed_at=s.observed_at,
                confidence=InfrastructureConfidence(s.confidence),
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
        superseded_by=InfrastructureId(row.superseded_by) if row.superseded_by else None,
        row_version=row.row_version,
    )


class PgInfrastructureRepository(IInfrastructureRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, record: Infrastructure) -> None:
        try:
            await self._save(record)
        except IntegrityError as exc:
            raise InfrastructureIntelIntegrityError("save Infrastructure", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise InfrastructureIntelIntegrityError("save Infrastructure", str(exc)) from exc

    async def _save(self, record: Infrastructure) -> None:
        record_uuid = record.infrastructure_id.value
        tenant_uuid = _tenant_uuid(record.tenant_id)
        superseded_by_uuid = (
            record.superseded_by.value if record.superseded_by is not None else None
        )
        hosting_provider_name = (
            record.hosting_provider.provider_name if record.hosting_provider is not None else None
        )
        cloud_provider = (
            record.cloud_provider.provider.value if record.cloud_provider is not None else None
        )
        ownership = record.network_ownership

        row = await self._session.get(InfrastructureModel, record_uuid)
        if row is None:
            row = InfrastructureModel(
                id=record_uuid,
                tenant_id=tenant_uuid,
                infrastructure_type=record.infrastructure_type.value,
                normalized_identifier=record.normalized_identifier,
                lifecycle_status=record.lifecycle_status.value,
                hosting_provider_name=hosting_provider_name,
                cloud_provider=cloud_provider,
                registrant_organization=(
                    ownership.registrant_organization if ownership is not None else None
                ),
                abuse_contact=ownership.abuse_contact if ownership is not None else "",
                ownership_notes=ownership.notes if ownership is not None else "",
                confidence=record.confidence.value,
                superseded_by=superseded_by_uuid,
                created_at=record.created_at,
                updated_at=record.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(record, record_uuid)
            await self._session.flush()
            record.row_version = 1
            return

        expected = record.row_version
        result = await self._session.execute(
            update(InfrastructureModel)
            .where(
                InfrastructureModel.id == record_uuid,
                InfrastructureModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                lifecycle_status=record.lifecycle_status.value,
                hosting_provider_name=hosting_provider_name,
                cloud_provider=cloud_provider,
                registrant_organization=(
                    ownership.registrant_organization if ownership is not None else None
                ),
                abuse_contact=ownership.abuse_contact if ownership is not None else "",
                ownership_notes=ownership.notes if ownership is not None else "",
                confidence=record.confidence.value,
                superseded_by=superseded_by_uuid,
                updated_at=record.updated_at,
                row_version=expected + 1,
            )
            .returning(InfrastructureModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(InfrastructureModel, record_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(record.infrastructure_id), expected, actual)

        await self._replace_children(record, record_uuid)
        await self._session.flush()
        record.row_version = int(new_version)

    async def _replace_children(self, record: Infrastructure, record_uuid: UUID) -> None:
        await self._session.execute(
            delete(InfrastructureRegionModel).where(
                InfrastructureRegionModel.infrastructure_id == record_uuid
            )
        )
        for region in record.regions:
            self._session.add(
                InfrastructureRegionModel(
                    id=uuid4(), infrastructure_id=record_uuid, region_code=region.region_code
                )
            )

        await self._session.execute(
            delete(InfrastructureEvidenceCitationModel).where(
                InfrastructureEvidenceCitationModel.infrastructure_id == record_uuid
            )
        )
        for citation in record.evidence_citations:
            self._session.add(
                InfrastructureEvidenceCitationModel(
                    id=uuid4(), infrastructure_id=record_uuid, value=citation.value
                )
            )

        await self._session.execute(
            delete(InfrastructureSourceAttributionModel).where(
                InfrastructureSourceAttributionModel.infrastructure_id == record_uuid
            )
        )
        for attribution in record.source_attributions:
            self._session.add(
                InfrastructureSourceAttributionModel(
                    id=uuid4(),
                    infrastructure_id=record_uuid,
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
            select(InfrastructureVersionModel.version).where(
                InfrastructureVersionModel.infrastructure_id == record_uuid
            )
        )
        existing_versions = {r[0] for r in result.all()}
        for entry in record.version_history:
            if entry.version not in existing_versions:
                self._session.add(
                    InfrastructureVersionModel(
                        id=uuid4(),
                        infrastructure_id=record_uuid,
                        version=entry.version,
                        changed_at=entry.changed_at,
                        change_summary=entry.change_summary,
                        source=entry.source,
                    )
                )

    async def get(
        self, tenant_id: TenantId | None, infrastructure_id: InfrastructureId
    ) -> Infrastructure | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(InfrastructureModel).where(InfrastructureModel.id == infrastructure_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_infrastructure(row)

    async def get_any(self, infrastructure_id: InfrastructureId) -> Infrastructure | None:
        row = await self._session.get(InfrastructureModel, infrastructure_id.value)
        if row is None:
            return None
        return _row_to_infrastructure(row)

    async def get_by_identity(
        self,
        tenant_id: TenantId | None,
        infrastructure_type: InfrastructureType,
        normalized_identifier: str,
    ) -> Infrastructure | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(InfrastructureModel).where(
            InfrastructureModel.infrastructure_type == infrastructure_type.value,
            InfrastructureModel.normalized_identifier == normalized_identifier,
        )
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_infrastructure(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: InfrastructureLifecycleStatus | None = None,
        infrastructure_type: InfrastructureType | None = None,
        cloud_provider: CloudProvider | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Infrastructure]:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(InfrastructureModel).where(_tenant_filter(tenant_uuid))
        if lifecycle_status is not None:
            stmt = stmt.where(InfrastructureModel.lifecycle_status == lifecycle_status.value)
        if infrastructure_type is not None:
            stmt = stmt.where(InfrastructureModel.infrastructure_type == infrastructure_type.value)
        if cloud_provider is not None:
            stmt = stmt.where(InfrastructureModel.cloud_provider == cloud_provider.value)
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(InfrastructureModel.created_at.desc(), InfrastructureModel.id.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_infrastructure(row) for row in rows]
