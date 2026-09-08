"""Application commands for campaign_intel. No HTTP/FastAPI types, no
ORM types — pure application-layer contracts, constructed by an
already-authorized caller (the API layer). These carry no `actor_roles`
field: tenant/global permission checks happen exclusively in the API
layer via `require_permission`/`require_platform_permission` — the
application service trusts the `tenant_id` it is given and does not
re-implement authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaign_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ObjectiveInput:
    objective_type: str
    description: str = ""


@dataclass(frozen=True, slots=True)
class TimelineInput:
    first_observed: str
    last_observed: str | None = None
    ongoing: bool = False


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveCampaignCommand:
    tenant_id: TenantId | None
    canonical_name: str
    status: str = "unknown"
    motivation: str = "unknown"
    confidence: str = "medium"
    timeline: TimelineInput | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)
    objectives: tuple[ObjectiveInput, ...] = field(default_factory=tuple)
    regions: tuple[str, ...] = field(default_factory=tuple)
    target_sectors: tuple[str, ...] = field(default_factory=tuple)


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddAliasCommand:
    tenant_id: TenantId | None
    campaign_id: str
    alias: str


@dataclass(frozen=True, slots=True)
class AddObjectiveCommand:
    tenant_id: TenantId | None
    campaign_id: str
    objective: ObjectiveInput


@dataclass(frozen=True, slots=True)
class AddRegionCommand:
    tenant_id: TenantId | None
    campaign_id: str
    region: str


@dataclass(frozen=True, slots=True)
class AddTargetSectorCommand:
    tenant_id: TenantId | None
    campaign_id: str
    target_sector: str


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    campaign_id: str
    citation: str


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    campaign_id: str
    attribution: SourceAttributionInput


# ── Real-world campaign status (independent of record lifecycle) ─────────


@dataclass(frozen=True, slots=True)
class TransitionCampaignStatusCommand:
    tenant_id: TenantId | None
    campaign_id: str
    target_status: str
    evidence: SourceAttributionInput


# ── Record lifecycle (independent of real-world status) ──────────────────


@dataclass(frozen=True, slots=True)
class DeprecateCampaignCommand:
    tenant_id: TenantId | None
    campaign_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeCampaignCommand:
    tenant_id: TenantId | None
    campaign_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeCampaignCommand:
    tenant_id: TenantId | None
    campaign_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateCampaignCommand:
    tenant_id: TenantId | None
    campaign_id: str
    evidence: SourceAttributionInput
