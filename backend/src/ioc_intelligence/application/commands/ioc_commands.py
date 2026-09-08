"""Application commands for ioc_intelligence (M51.2 Phase A2). No
HTTP/FastAPI types, no ORM types — pure application-layer contracts,
constructed by a trusted caller (a future API layer) from an
already-authenticated context. `tenant_id` fields represent that
already-resolved trusted tenant context — never an arbitrary field
lifted verbatim from a request body, and `tenant_id=None` always means
"acting on global intelligence," never a stand-in for an unresolved
caller."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ioc_intelligence.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    external_id: str
    observed_at: str
    weight_applied: float
    confidence: str
    content_hash: str | None = None


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveGlobalIocCommand:
    ioc_type: str
    raw_value: str
    source_attributions: tuple[SourceAttributionInput, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ObserveTenantIocCommand:
    tenant_id: TenantId
    ioc_type: str
    raw_value: str
    source_attributions: tuple[SourceAttributionInput, ...] = field(default_factory=tuple)
    evidence_citations: tuple[str, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()


# ── Provenance ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    ioc_id: str
    attribution: SourceAttributionInput
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    ioc_id: str
    evidence_citation: str
    actor_roles: tuple[str, ...] = ()


# ── Lifecycle ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TransitionLifecycleCommand:
    tenant_id: TenantId | None
    ioc_id: str
    target_lifecycle: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RefreshValidityCommand:
    tenant_id: TenantId | None
    ioc_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SupersedeIocCommand:
    tenant_id: TenantId | None
    ioc_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RevokeIocCommand:
    tenant_id: TenantId | None
    ioc_id: str
    actor_roles: tuple[str, ...] = ()


# ── Epistemic state ──────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class TransitionEpistemicStateCommand:
    tenant_id: TenantId | None
    ioc_id: str
    target_state: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MarkDisputedCommand:
    tenant_id: TenantId | None
    ioc_id: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RefuteIocCommand:
    tenant_id: TenantId | None
    ioc_id: str
    reason: str
    actor_roles: tuple[str, ...] = ()
