"""Aggregate -> DTO mappers for campaign_intel."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign_intel.application.dtos.campaign_dtos import (
    CampaignDetailDTO,
    CampaignSummaryDTO,
    ObjectiveDTO,
    SourceAttributionDTO,
    TimelineDTO,
    VersionRecordDTO,
)

if TYPE_CHECKING:
    from campaign_intel.domain.aggregates.campaign import Campaign
    from campaign_intel.domain.value_objects.evidence import SourceAttribution
    from campaign_intel.domain.value_objects.timeline import CampaignTimeline


def _attribution_dto(attribution: SourceAttribution) -> SourceAttributionDTO:
    return SourceAttributionDTO(
        source_system=attribution.source_system,
        reference=attribution.reference,
        observed_at=attribution.observed_at.isoformat(),
        confidence=attribution.confidence.value,
        notes=attribution.notes,
    )


def _timeline_dto(timeline: CampaignTimeline | None) -> TimelineDTO | None:
    if timeline is None:
        return None
    return TimelineDTO(
        first_observed=timeline.first_observed.isoformat(),
        last_observed=(
            timeline.last_observed.isoformat() if timeline.last_observed is not None else None
        ),
        ongoing=timeline.ongoing,
    )


def to_summary_dto(campaign: Campaign) -> CampaignSummaryDTO:
    return CampaignSummaryDTO(
        campaign_id=str(campaign.campaign_id),
        tenant_id=str(campaign.tenant_id) if campaign.tenant_id is not None else None,
        canonical_name=campaign.canonical_name,
        status=campaign.status.value,
        lifecycle_status=campaign.lifecycle_status.value,
        motivation=campaign.motivation.value,
        confidence=campaign.confidence.value,
        created_at=campaign.created_at.isoformat(),
        updated_at=campaign.updated_at.isoformat(),
        alias_count=len(campaign.aliases),
        objective_count=len(campaign.objectives),
        region_count=len(campaign.regions),
        target_sector_count=len(campaign.target_sectors),
    )


def to_detail_dto(campaign: Campaign) -> CampaignDetailDTO:
    return CampaignDetailDTO(
        campaign_id=str(campaign.campaign_id),
        tenant_id=str(campaign.tenant_id) if campaign.tenant_id is not None else None,
        canonical_name=campaign.canonical_name,
        status=campaign.status.value,
        lifecycle_status=campaign.lifecycle_status.value,
        motivation=campaign.motivation.value,
        confidence=campaign.confidence.value,
        superseded_by=str(campaign.superseded_by) if campaign.superseded_by is not None else None,
        created_at=campaign.created_at.isoformat(),
        updated_at=campaign.updated_at.isoformat(),
        timeline=_timeline_dto(campaign.timeline),
        aliases=tuple(a.value for a in campaign.aliases),
        objectives=tuple(
            ObjectiveDTO(objective_type=o.objective_type.value, description=o.description)
            for o in campaign.objectives
        ),
        regions=tuple(campaign.regions),
        target_sectors=tuple(s.value for s in campaign.target_sectors),
        evidence_citations=tuple(e.value for e in campaign.evidence_citations),
        source_attributions=tuple(_attribution_dto(a) for a in campaign.source_attributions),
        version_history=tuple(
            VersionRecordDTO(
                version=v.version,
                changed_at=v.changed_at.isoformat(),
                change_summary=v.change_summary,
                source=v.source,
            )
            for v in campaign.version_history
        ),
    )
