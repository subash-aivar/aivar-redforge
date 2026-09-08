"""Application commands for intelligence_relationships (M51.4 Phase
C1). No HTTP/FastAPI types, no ORM types — pure application-layer
contracts, constructed by an already-authorized caller (the API
layer). They carry no `actor_roles` field: tenant/global permission
checks happen exclusively in the API layer via `require_permission`/
`require_platform_permission` — the application service trusts the
`tenant_id` it is given and does not re-implement authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from intelligence_relationships.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class EntityRefInput:
    entity_type: str
    entity_id: str


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveRelationshipCommand:
    tenant_id: TenantId | None
    relationship_type: str
    source_entity: EntityRefInput
    target_entity: EntityRefInput
    direction: str = "unidirectional"
    confidence: str = "medium"
    epistemic_state: str = "observation"
    valid_from: str | None = None
    valid_until: str | None = None
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    source_attributions: tuple[SourceAttributionInput, ...] = field(default_factory=tuple)


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    relationship_id: str
    value: str


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    relationship_id: str
    attribution: SourceAttributionInput


# ── Epistemic axis ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TransitionEpistemicStateCommand:
    tenant_id: TenantId | None
    relationship_id: str
    target_state: str
    evidence: SourceAttributionInput


# ── Lifecycle axis ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeprecateRelationshipCommand:
    tenant_id: TenantId | None
    relationship_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeRelationshipCommand:
    tenant_id: TenantId | None
    relationship_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeRelationshipCommand:
    tenant_id: TenantId | None
    relationship_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateRelationshipCommand:
    tenant_id: TenantId | None
    relationship_id: str
    evidence: SourceAttributionInput
