"""Application commands for threat_actor_intel (M51.1 Phase 2). No
HTTP/FastAPI types, no ORM types — pure application-layer contracts,
constructed by a trusted caller (the future API layer, Phase 4) from
an already-authenticated context. `tenant_id` fields on association
commands represent that already-resolved trusted tenant context —
never an arbitrary field lifted verbatim from a request body."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.value_objects.identifiers import TenantId

# ── Global ThreatActor operations ───────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RegisterThreatActorCommand:
    name: str
    origin: str
    motivations: tuple[str, ...]
    sophistication: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AddAliasCommand:
    threat_actor_id: str
    alias: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssociateTechniqueCommand:
    threat_actor_id: str
    technique_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AssociateIndicatorCommand:
    threat_actor_id: str
    indicator_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpdateMotivationsCommand:
    threat_actor_id: str
    motivations: tuple[str, ...]
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpdateSophisticationCommand:
    threat_actor_id: str
    sophistication: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TransitionActivityStatusCommand:
    threat_actor_id: str
    target_status: str
    actor_roles: tuple[str, ...] = ()


# ── Tenant association operations ───────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CreateThreatActorAssociationCommand:
    tenant_id: TenantId
    threat_actor_id: str
    referenced_entity_type: str
    referenced_entity_id: str
    evidence_citation: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RetractThreatActorAssociationCommand:
    tenant_id: TenantId
    association_id: str
    actor_roles: tuple[str, ...] = ()
