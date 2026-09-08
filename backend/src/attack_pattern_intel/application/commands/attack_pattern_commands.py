"""Application commands for attack_pattern_intel (M51.3 Phase B1). No
HTTP/FastAPI types, no ORM types — pure application-layer contracts,
constructed by an already-authorized caller (the API layer). Unlike
`ioc_intelligence`'s Phase A2 commands, these carry no `actor_roles`
field: per the M51.3 architecture decision, tenant/global permission
checks happen exclusively in the API layer via `require_permission`/
`require_platform_permission` — the application service trusts the
`tenant_id` it is given and does not re-implement authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from attack_pattern_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    notes: str = ""


@dataclass(frozen=True, slots=True)
class TacticMappingInput:
    tactic_id: str
    tactic_shortname: str
    priority: int = 0
    notes: str = ""


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveAttackPatternCommand:
    tenant_id: TenantId | None
    technique_id: str
    sub_technique_id: str | None = None
    tactic_mappings: tuple[TacticMappingInput, ...] = field(default_factory=tuple)
    platforms: tuple[str, ...] = field(default_factory=tuple)


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddDetectionGuidanceCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    content: str
    attribution: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class AddMitigationReferenceCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    mitigation_id: str
    name: str
    description: str
    attribution: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class AddProcedureExampleCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    description: str
    attribution: SourceAttributionInput
    actor_ref: str | None = None


@dataclass(frozen=True, slots=True)
class AddRelationshipCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    relationship_type: str
    target_attack_pattern_id: str
    attribution: SourceAttributionInput


# ── Lifecycle ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeprecateAttackPatternCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeAttackPatternCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeAttackPatternCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateAttackPatternCommand:
    tenant_id: TenantId | None
    attack_pattern_id: str
    evidence: SourceAttributionInput
