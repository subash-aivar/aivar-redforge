"""Application DTOs for ioc_intelligence (M51.2 Phase A2). Frozen,
primitive-typed dataclasses only — no domain value objects or
aggregate references ever cross this boundary, mirroring
`threat_actor_intel.application.dtos.threat_actor_dtos`'s convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class LifecycleStateDTO:
    value: str


@dataclass(frozen=True, slots=True)
class EpistemicStateDTO:
    value: str


@dataclass(frozen=True, slots=True)
class SourceAttributionDTO:
    source_system: str
    external_id: str
    content_hash: str | None
    observed_at: str
    weight_applied: float
    confidence: str


@dataclass(frozen=True, slots=True)
class EvidenceCitationDTO:
    value: str


@dataclass(frozen=True, slots=True)
class IocSummaryDTO:
    ioc_id: str
    tenant_id: str | None
    ioc_type: str
    canonical_key: str
    lifecycle: LifecycleStateDTO
    epistemic_state: EpistemicStateDTO
    created_at: str
    updated_at: str
    valid_until: str | None
    # M51.2 Phase A6: real counts of the aggregate's own already-loaded
    # collections — `list()` already returns full `IOC` aggregates, so
    # this is a zero-cost mapper addition, never a fabricated total.
    source_count: int = 0
    evidence_count: int = 0


@dataclass(frozen=True, slots=True)
class IocDetailDTO:
    ioc_id: str
    tenant_id: str | None
    ioc_type: str
    canonical_key: str
    lifecycle: LifecycleStateDTO
    epistemic_state: EpistemicStateDTO
    valid_from: str
    valid_until: str | None
    created_at: str
    updated_at: str
    source_attributions: tuple[SourceAttributionDTO, ...] = field(default_factory=tuple)
    evidence_citations: tuple[EvidenceCitationDTO, ...] = field(default_factory=tuple)
