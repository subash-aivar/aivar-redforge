"""Application commands for threat_report_intel. No HTTP/FastAPI types,
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
    from threat_report_intel.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class SourceAttributionInput:
    source_system: str
    reference: str
    observed_at: str
    confidence: str = "medium"
    notes: str = ""


@dataclass(frozen=True, slots=True)
class PublisherInput:
    organization_name: str
    contact: str = ""


@dataclass(frozen=True, slots=True)
class ReportMetadataInput:
    report_type: str
    tlp_marking: str
    external_report_id: str = ""


@dataclass(frozen=True, slots=True)
class ThreatReportReferenceInput:
    url_or_citation: str
    description: str = ""


# ── Observation ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ObserveThreatReportCommand:
    tenant_id: TenantId | None
    title: str
    publisher: PublisherInput
    publication_date: str
    report_metadata: ReportMetadataInput
    executive_summary: str
    technical_summary: str
    severity: str = "medium"
    confidence: str = "medium"
    references: tuple[ThreatReportReferenceInput, ...] = field(default_factory=tuple)


# ── Enrichment ───────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AddReferenceCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    reference: ThreatReportReferenceInput


@dataclass(frozen=True, slots=True)
class AddEvidenceCitationCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    citation: str


@dataclass(frozen=True, slots=True)
class AddSourceAttributionCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    attribution: SourceAttributionInput


# ── Record lifecycle ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeprecateThreatReportCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class RevokeThreatReportCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class SupersedeThreatReportCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    superseded_by: str
    evidence: SourceAttributionInput


@dataclass(frozen=True, slots=True)
class ReactivateThreatReportCommand:
    tenant_id: TenantId | None
    threat_report_id: str
    evidence: SourceAttributionInput
