"""Application commands for infrastructure_intel. No HTTP/FastAPI types,
no ORM types — pure application-layer contracts, constructed by an
already-authorized caller (the API layer). These carry no `actor_roles`
field: tenant/global permission checks happen exclusively in the API
layer via `require_permission`/`require_platform_permission` — the
application service trusts the `tenant_id` it is given and does not
re-implement authorization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infrastructure_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class NetworkOwnershipInput:
    registrant_organization: str
    abuse_contact: str = ""
    notes: str = ""


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveInfrastructureCommand:
    tenant_id: TenantId | None
    infrastructure_type: str
    normalized_identifier: str
    confidence: str = "medium"
    hosting_provider: str | None = None
    cloud_provider: str | None = None
    regions: tuple[str, ...] = field(default_factory=tuple)
    network_ownership: NetworkOwnershipInput | None = None


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SetHostingProviderCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    provider_name: str


@dataclass(frozen=True, slots=True)
class SetCloudProviderCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    provider: str


@dataclass(frozen=True, slots=True)
class AddRegionCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    region_code: str


@dataclass(frozen=True, slots=True)
class SetNetworkOwnershipCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    ownership: NetworkOwnershipInput


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    citation: str


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    attribution: SourceAttributionInput


# ── Record lifecycle ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeprecateInfrastructureCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeInfrastructureCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeInfrastructureCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateInfrastructureCommand:
    tenant_id: TenantId | None
    infrastructure_id: str
    evidence: SourceAttributionInput
