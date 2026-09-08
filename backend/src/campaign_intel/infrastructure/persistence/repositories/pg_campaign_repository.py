"""PgCampaignRepository — SQLAlchemy implementation of
`ICampaignRepository`, mirroring `malware_intel.infrastructure.
persistence.repositories.pg_malware_repository.PgMalwareRepository`'s
translation shape (no business logic, no authorization) plus its real
optimistic-concurrency compare-and-swap pattern.

Tenant scoping is query-enforced everywhere: every read filters by
`tenant_id == scope` (`scope=None` meaning "global rows only"), so a
row belonging to a different scope is indistinguishable from "does not
exist".

Child collections (aliases, objectives, regions, target sectors,
evidence citations, source attributions) are wholesale-replaced on every
`save()` — the aggregate itself is the sole authority on their
contents. Version history is append-only: only rows whose `version` is
not already persisted are inserted, matching the aggregate's own
append-only invariant."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from campaign_intel.application.ports.i_campaign_repository import ICampaignRepository
from campaign_intel.domain.aggregates.campaign import Campaign
from campaign_intel.domain.value_objects.enums import (
    CampaignConfidence,
    CampaignLifecycleStatus,
    CampaignMotivation,
    CampaignObjectiveType,
    CampaignStatus,
    CampaignTargetSector,
)
from campaign_intel.domain.value_objects.evidence import EvidenceCitation, SourceAttribution
from campaign_intel.domain.value_objects.identifiers import CampaignId, TenantId
from campaign_intel.domain.value_objects.taxonomy import CampaignAlias, CampaignObjective
from campaign_intel.domain.value_objects.timeline import CampaignTimeline
from campaign_intel.domain.value_objects.version_record import VersionRecord
from campaign_intel.infrastructure.persistence.exceptions import (
    CampaignIntelIntegrityError,
    OptimisticLockConflictError,
)
from campaign_intel.infrastructure.persistence.models.campaign_models import (
    CampaignAliasModel,
    CampaignEvidenceCitationModel,
    CampaignModel,
    CampaignObjectiveModel,
    CampaignRegionModel,
    CampaignSourceAttributionModel,
    CampaignTargetSectorModel,
    CampaignVersionModel,
)

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.sql.elements import ColumnElement


def _tenant_uuid(tenant_id: TenantId | None) -> UUID | None:
    return None if tenant_id is None else tenant_id.value.to_uuid()


def _tenant_filter(tenant_uuid: UUID | None) -> ColumnElement[bool]:
    if tenant_uuid is None:
        return CampaignModel.tenant_id.is_(None)
    return CampaignModel.tenant_id == tenant_uuid


def _row_to_timeline(row: CampaignModel) -> CampaignTimeline | None:
    if row.timeline_first_observed is None:
        return None
    return CampaignTimeline(
        first_observed=row.timeline_first_observed,
        last_observed=row.timeline_last_observed,
        ongoing=row.timeline_ongoing,
    )


def _row_to_campaign(row: CampaignModel) -> Campaign:
    return Campaign(
        campaign_id=CampaignId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id) if row.tenant_id is not None else None,
        canonical_name=row.canonical_name,
        lifecycle_status=CampaignLifecycleStatus(row.lifecycle_status),
        created_at=row.created_at,
        updated_at=row.updated_at,
        status=CampaignStatus(row.status),
        motivation=CampaignMotivation(row.motivation),
        timeline=_row_to_timeline(row),
        aliases=tuple(CampaignAlias(a.value) for a in row.aliases),
        objectives=tuple(
            CampaignObjective(
                objective_type=CampaignObjectiveType(o.objective_type),
                description=o.description,
            )
            for o in row.objectives
        ),
        regions=tuple(r.region for r in row.regions),
        target_sectors=tuple(CampaignTargetSector(s.target_sector) for s in row.target_sectors),
        confidence=CampaignConfidence(row.confidence),
        evidence_citations=tuple(EvidenceCitation(e.value) for e in row.evidence_citations),
        source_attributions=tuple(
            SourceAttribution(
                source_system=s.source_system,
                reference=s.reference,
                observed_at=s.observed_at,
                confidence=CampaignConfidence(s.confidence),
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
        superseded_by=CampaignId(row.superseded_by) if row.superseded_by else None,
        row_version=row.row_version,
    )


class PgCampaignRepository(ICampaignRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, campaign: Campaign) -> None:
        try:
            await self._save(campaign)
        except IntegrityError as exc:
            raise CampaignIntelIntegrityError("save Campaign", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            raise CampaignIntelIntegrityError("save Campaign", str(exc)) from exc

    async def _save(self, campaign: Campaign) -> None:
        campaign_uuid = campaign.campaign_id.value
        tenant_uuid = _tenant_uuid(campaign.tenant_id)
        superseded_by_uuid = (
            campaign.superseded_by.value if campaign.superseded_by is not None else None
        )
        timeline = campaign.timeline

        row = await self._session.get(CampaignModel, campaign_uuid)
        if row is None:
            row = CampaignModel(
                id=campaign_uuid,
                tenant_id=tenant_uuid,
                canonical_name=campaign.canonical_name,
                status=campaign.status.value,
                lifecycle_status=campaign.lifecycle_status.value,
                motivation=campaign.motivation.value,
                confidence=campaign.confidence.value,
                timeline_first_observed=timeline.first_observed if timeline else None,
                timeline_last_observed=timeline.last_observed if timeline else None,
                timeline_ongoing=timeline.ongoing if timeline else False,
                superseded_by=superseded_by_uuid,
                created_at=campaign.created_at,
                updated_at=campaign.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._replace_children(campaign, campaign_uuid)
            await self._session.flush()
            campaign.row_version = 1
            return

        expected = campaign.row_version
        result = await self._session.execute(
            update(CampaignModel)
            .where(
                CampaignModel.id == campaign_uuid,
                CampaignModel.row_version == expected,
            )
            .values(
                tenant_id=tenant_uuid,
                status=campaign.status.value,
                lifecycle_status=campaign.lifecycle_status.value,
                motivation=campaign.motivation.value,
                confidence=campaign.confidence.value,
                timeline_first_observed=timeline.first_observed if timeline else None,
                timeline_last_observed=timeline.last_observed if timeline else None,
                timeline_ongoing=timeline.ongoing if timeline else False,
                superseded_by=superseded_by_uuid,
                updated_at=campaign.updated_at,
                row_version=expected + 1,
            )
            .returning(CampaignModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            actual_row = await self._session.get(CampaignModel, campaign_uuid)
            actual = actual_row.row_version if actual_row is not None else -1
            raise OptimisticLockConflictError(str(campaign.campaign_id), expected, actual)

        await self._replace_children(campaign, campaign_uuid)
        await self._session.flush()
        campaign.row_version = int(new_version)

    async def _replace_children(self, campaign: Campaign, campaign_uuid: UUID) -> None:
        await self._session.execute(
            delete(CampaignAliasModel).where(CampaignAliasModel.campaign_id == campaign_uuid)
        )
        for alias in campaign.aliases:
            self._session.add(
                CampaignAliasModel(id=uuid4(), campaign_id=campaign_uuid, value=alias.value)
            )

        await self._session.execute(
            delete(CampaignObjectiveModel).where(
                CampaignObjectiveModel.campaign_id == campaign_uuid
            )
        )
        for objective in campaign.objectives:
            self._session.add(
                CampaignObjectiveModel(
                    id=uuid4(),
                    campaign_id=campaign_uuid,
                    objective_type=objective.objective_type.value,
                    description=objective.description,
                )
            )

        await self._session.execute(
            delete(CampaignRegionModel).where(CampaignRegionModel.campaign_id == campaign_uuid)
        )
        for region in campaign.regions:
            self._session.add(
                CampaignRegionModel(id=uuid4(), campaign_id=campaign_uuid, region=region)
            )

        await self._session.execute(
            delete(CampaignTargetSectorModel).where(
                CampaignTargetSectorModel.campaign_id == campaign_uuid
            )
        )
        for sector in campaign.target_sectors:
            self._session.add(
                CampaignTargetSectorModel(
                    id=uuid4(), campaign_id=campaign_uuid, target_sector=sector.value
                )
            )

        await self._session.execute(
            delete(CampaignEvidenceCitationModel).where(
                CampaignEvidenceCitationModel.campaign_id == campaign_uuid
            )
        )
        for citation in campaign.evidence_citations:
            self._session.add(
                CampaignEvidenceCitationModel(
                    id=uuid4(), campaign_id=campaign_uuid, value=citation.value
                )
            )

        await self._session.execute(
            delete(CampaignSourceAttributionModel).where(
                CampaignSourceAttributionModel.campaign_id == campaign_uuid
            )
        )
        for attribution in campaign.source_attributions:
            self._session.add(
                CampaignSourceAttributionModel(
                    id=uuid4(),
                    campaign_id=campaign_uuid,
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
            select(CampaignVersionModel.version).where(
                CampaignVersionModel.campaign_id == campaign_uuid
            )
        )
        existing_versions = {r[0] for r in result.all()}
        for record in campaign.version_history:
            if record.version not in existing_versions:
                self._session.add(
                    CampaignVersionModel(
                        id=uuid4(),
                        campaign_id=campaign_uuid,
                        version=record.version,
                        changed_at=record.changed_at,
                        change_summary=record.change_summary,
                        source=record.source,
                    )
                )

    async def get(self, tenant_id: TenantId | None, campaign_id: CampaignId) -> Campaign | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(CampaignModel).where(CampaignModel.id == campaign_id.value)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_campaign(row)

    async def get_any(self, campaign_id: CampaignId) -> Campaign | None:
        row = await self._session.get(CampaignModel, campaign_id.value)
        if row is None:
            return None
        return _row_to_campaign(row)

    async def get_by_canonical_name(
        self, tenant_id: TenantId | None, canonical_name: str
    ) -> Campaign | None:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(CampaignModel).where(CampaignModel.canonical_name == canonical_name)
        stmt = stmt.where(_tenant_filter(tenant_uuid))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _row_to_campaign(row)

    async def list(
        self,
        tenant_id: TenantId | None,
        lifecycle_status: CampaignLifecycleStatus | None = None,
        status: CampaignStatus | None = None,
        motivation: CampaignMotivation | None = None,
        target_sector: CampaignTargetSector | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Campaign]:
        tenant_uuid = _tenant_uuid(tenant_id)
        stmt = select(CampaignModel).where(_tenant_filter(tenant_uuid))
        if lifecycle_status is not None:
            stmt = stmt.where(CampaignModel.lifecycle_status == lifecycle_status.value)
        if status is not None:
            stmt = stmt.where(CampaignModel.status == status.value)
        if motivation is not None:
            stmt = stmt.where(CampaignModel.motivation == motivation.value)
        if target_sector is not None:
            stmt = stmt.where(
                CampaignModel.id.in_(
                    select(CampaignTargetSectorModel.campaign_id).where(
                        CampaignTargetSectorModel.target_sector == target_sector.value
                    )
                )
            )
        # Stable ordering (created_at, then id as a tiebreaker) is
        # required for pagination to be well-defined across pages.
        stmt = stmt.order_by(CampaignModel.created_at.desc(), CampaignModel.id.desc())
        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_campaign(row) for row in rows]
