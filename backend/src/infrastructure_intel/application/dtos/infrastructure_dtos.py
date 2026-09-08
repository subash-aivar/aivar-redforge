"""Application DTOs for infrastructure_intel. Frozen, primitive-typed
dataclasses only — no domain value objects or aggregate references ever
cross this boundary, mirroring `tool_intel.application.dtos.tool_dtos`'s
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
class NetworkOwnershipDTO:
    registrant_organization: str
    abuse_contact: str = ""
    notes: str = ""


@dataclass(frozen=True, slots=True)
class VersionRecordDTO:
    version: int
    changed_at: str
    change_summary: str
    source: str


@dataclass(frozen=True, slots=True)
class InfrastructureSummaryDTO:
    infrastructure_id: str
    tenant_id: str | None
    infrastructure_type: str
    normalized_identifier: str
    lifecycle_status: str
    hosting_provider: str | None
    cloud_provider: str | None
    confidence: str
    created_at: str
    updated_at: str
    region_count: int = 0
    evidence_citation_count: int = 0
    source_attribution_count: int = 0


@dataclass(frozen=True, slots=True)
class InfrastructureDetailDTO:
    infrastructure_id: str
    tenant_id: str | None
    infrastructure_type: str
    normalized_identifier: str
    lifecycle_status: str
    hosting_provider: str | None
    cloud_provider: str | None
    network_ownership: NetworkOwnershipDTO | None
    confidence: str
    superseded_by: str | None
    created_at: str
    updated_at: str
    regions: tuple[str, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    version_history: tuple[VersionRecordDTO, ...] = field(default_factory=tuple)
