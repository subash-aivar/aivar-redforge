"""Application DTOs for threat_actor_intel (M51.1 Phase 2). Frozen,
primitive-typed dataclasses only — no domain value objects or
aggregate references ever cross this boundary, mirroring
`exposure.application.dtos.exposure_dtos`'s convention."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ThreatActorSummaryDTO:
    threat_actor_id: str
    tenant_id: str | None
    name: str
    origin: str
    status: str
    attribution_confidence: str


@dataclass(frozen=True, slots=True)
class ThreatActorDetailDTO:
    threat_actor_id: str
    tenant_id: str | None
    name: str
    origin: str
    status: str
    attribution_confidence: str
    sophistication: str
    motivations: tuple[str, ...] = field(default_factory=tuple)
    aliases: tuple[str, ...] = field(default_factory=tuple)
    technique_refs: tuple[str, ...] = field(default_factory=tuple)
    indicator_refs: tuple[str, ...] = field(default_factory=tuple)
    created_at: str = ""
    updated_at: str = ""


@dataclass(frozen=True, slots=True)
class ThreatActorAssociationDTO:
    association_id: str
    tenant_id: str
    threat_actor_id: str
    referenced_entity_type: str
    referenced_entity_id: str
    evidence_citation: str
    state: str
    created_at: str
    retracted_at: str | None = None
