"""Application DTOs for campaign_intel. Frozen, primitive-typed
dataclasses only — no domain value objects or aggregate references ever
cross this boundary, mirroring
`malware_intel.application.dtos.malware_dtos`'s convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SourceAttributionDTO:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ObjectiveDTO:
    objective_type: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class TimelineDTO:
    first_observed: str
    last_observed: str | None = None
    ongoing: bool = False


@dataclass(frozen=True, slots=True)
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class CampaignSummaryDTO:
    campaign_id: str
    tenant_id: str | None
    canonical_name: str
    status: str
    lifecycle_status: str
    motivation: str
    confidence: str
    created_at: str
    updated_at: str
    alias_count: int = 0
    objective_count: int = 0
    region_count: int = 0
    target_sector_count: int = 0


@dataclass(frozen=True, slots=True)
class CampaignDetailDTO:
    campaign_id: str
    tenant_id: str | None
    canonical_name: str
    status: str
    lifecycle_status: str
    motivation: str
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    timeline: TimelineDTO | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)
    objectives: tuple[ObjectiveDTO, ...] = field(default_factory=tuple)
    regions: tuple[str, ...] = field(default_factory=tuple)
    target_sectors: tuple[str, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
