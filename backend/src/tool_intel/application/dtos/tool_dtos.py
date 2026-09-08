"""Application DTOs for tool_intel. Frozen, primitive-typed dataclasses
only — no domain value objects or aggregate references ever cross this
boundary, mirroring `campaign_intel.application.dtos.campaign_dtos`'s
convention."""

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
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class ToolSummaryDTO:
    tool_id: str
    tenant_id: str | None
    canonical_name: str
    category: str
    lifecycle_status: str
    family: str | None
    confidence: str
    created_at: str
    updated_at: str
    alias_count: int = 0
    platform_count: int = 0
    capability_count: int = 0


@dataclass(frozen=True, slots=True)
class ToolDetailDTO:
    tool_id: str
    tenant_id: str | None
    canonical_name: str
    category: str
    lifecycle_status: str
    family: str | None
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    aliases: tuple[str, ...] = field(default_factory=tuple)
    platforms: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
