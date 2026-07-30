"""Read-only, JSON-friendly DTOs for attack_surface_management's
application layer (M49B). Never expose a domain object — every field is
a str/int/float/bool/ISO-timestamp/tuple-of-primitives, rebuilt fresh
from the aggregate each time, mirroring `risk_engine`'s
`EnterpriseRiskProfileDTO` convention exactly."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class OpenPortDTO:
    port_id: str
    port_number: int
    protocol: str
    state: str
    detected_at: datetime
    is_high_risk: bool
    service_name: str | None = None
    service_version: str | None = None


@dataclass(frozen=True, slots=True)
class CertificateDTO:
    certificate_id: str
    common_name: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    status: str


@dataclass(frozen=True, slots=True)
class DnsRecordDTO:
    record_id: str
    record_type: str
    name: str
    value: str
    ttl_seconds: int
    detected_at: datetime


@dataclass(frozen=True, slots=True)
class TechnologyFingerprintDTO:
    name: str
    version: str | None
    confidence: float


@dataclass(frozen=True, slots=True)
class AssetOwnershipDTO:
    owning_team: str
    contact: str | None = None


@dataclass(frozen=True, slots=True)
class AssetDTO:
    asset_id: str
    tenant_id: str
    asset_type: str
    primary_identifier: str
    discovery_source: str
    classification: str
    criticality: str
    exposure_state: str
    lifecycle_state: str
    created_at: datetime
    updated_at: datetime
    domain_name: str | None = None
    subdomain: str | None = None
    ip_address: str | None = None
    ownership: AssetOwnershipDTO | None = None
    ports: tuple[OpenPortDTO, ...] = field(default_factory=tuple)
    certificates: tuple[CertificateDTO, ...] = field(default_factory=tuple)
    dns_records: tuple[DnsRecordDTO, ...] = field(default_factory=tuple)
    fingerprints: tuple[TechnologyFingerprintDTO, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class CriticalityScoreDTO:
    """The flattened result of `CriticalityScoringService.score` for a
    given asset, at the moment it was computed — a pure read/derived
    view, not a persisted field of `Asset` itself."""

    asset_id: str
    tenant_id: str
    score: int
    computed_at: datetime


@dataclass(frozen=True, slots=True)
class NetworkRangeDTO:
    range_id: str
    tenant_id: str
    cidr: str
    discovery_source: str
    lifecycle_state: str
    asset_count: int
    created_at: datetime
    updated_at: datetime
