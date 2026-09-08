"""Application commands for tool_intel. No HTTP/FastAPI types, no ORM
types — pure application-layer contracts, constructed by an
already-authorized caller (the API layer). These carry no `actor_roles`
field: tenant/global permission checks happen exclusively in the API
layer via `require_permission`/`require_platform_permission` — the
application service trusts the `tenant_id` it is given and does not
re-implement authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tool_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveToolCommand:
    tenant_id: TenantId | None
    canonical_name: str
    category: str = "other"
    family: str | None = None
    confidence: str = "medium"
    aliases: tuple[str, ...] = field(default_factory=tuple)
    platforms: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[str, ...] = field(default_factory=tuple)


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddAliasCommand:
    tenant_id: TenantId | None
    tool_id: str
    alias: str


@dataclass(frozen=True, slots=True)
class AddPlatformCommand:
    tenant_id: TenantId | None
    tool_id: str
    platform: str


@dataclass(frozen=True, slots=True)
class AddCapabilityCommand:
    tenant_id: TenantId | None
    tool_id: str
    capability: str


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    tool_id: str
    citation: str


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    tool_id: str
    attribution: SourceAttributionInput


# ── Record lifecycle ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeprecateToolCommand:
    tenant_id: TenantId | None
    tool_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeToolCommand:
    tenant_id: TenantId | None
    tool_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeToolCommand:
    tenant_id: TenantId | None
    tool_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateToolCommand:
    tenant_id: TenantId | None
    tool_id: str
    evidence: SourceAttributionInput
