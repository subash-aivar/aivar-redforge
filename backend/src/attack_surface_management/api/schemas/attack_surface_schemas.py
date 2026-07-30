"""Pydantic request/response schemas for attack_surface_management's
API boundary (M49D). Deliberately separate from the application-layer
DTOs in `attack_surface_management.application.dtos` — mirrors
`risk_engine.api.schemas.risk_schemas`' convention of a plain
`BaseModel`, `model_validate(asdict(dto))`-friendly response shape."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class OpenPortResponse(BaseModel):
    port_id: str
    port_number: int
    protocol: str
    state: str
    detected_at: datetime
    is_high_risk: bool
    service_name: str | None = None
    service_version: str | None = None


class CertificateResponse(BaseModel):
    certificate_id: str
    common_name: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    status: str


class DnsRecordResponse(BaseModel):
    record_id: str
    record_type: str
    name: str
    value: str
    ttl_seconds: int
    detected_at: datetime


class TechnologyFingerprintResponse(BaseModel):
    name: str
    version: str | None = None
    confidence: float


class AssetOwnershipResponse(BaseModel):
    owning_team: str
    contact: str | None = None


class AssetResponse(BaseModel):
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
    ownership: AssetOwnershipResponse | None = None
    ports: list[OpenPortResponse] = Field(default_factory=list)
    certificates: list[CertificateResponse] = Field(default_factory=list)
    dns_records: list[DnsRecordResponse] = Field(default_factory=list)
    fingerprints: list[TechnologyFingerprintResponse] = Field(default_factory=list)


class ListAssetsResponse(BaseModel):
    items: list[AssetResponse]
    count: int


class RegisterAssetRequest(BaseModel):
    asset_type: str
    domain_name: str | None = None
    subdomain: str | None = None
    ip_address: str | None = None
    discovery_source: str | None = None
    asset_id: str | None = None


class ServiceBannerRequest(BaseModel):
    name: str = Field(min_length=1)
    version: str | None = None
    banner: str | None = None


class RecordOpenPortRequest(BaseModel):
    port_number: int = Field(ge=0, le=65535)
    protocol: str
    service: ServiceBannerRequest | None = None
    port_id: str | None = None


class AttachCertificateRequest(BaseModel):
    common_name: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    serial_number: str = Field(min_length=1)
    not_before: datetime
    not_after: datetime
    status: str
    certificate_id: str | None = None


class AddDnsRecordRequest(BaseModel):
    record_type: str
    name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    ttl_seconds: int = Field(ge=0)
    record_id: str | None = None


class AddTechnologyFingerprintRequest(BaseModel):
    name: str = Field(min_length=1)
    version: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)


class SetCriticalityRequest(BaseModel):
    criticality: str


class ReclassifyAssetRequest(BaseModel):
    classification: str


class UpdateOwnershipRequest(BaseModel):
    owning_team: str = Field(min_length=1)
    contact: str | None = None


class TransitionAssetLifecycleRequest(BaseModel):
    new_state: str


class CriticalityScoreResponse(BaseModel):
    asset_id: str
    tenant_id: str
    score: int
    computed_at: datetime


class NetworkRangeResponse(BaseModel):
    range_id: str
    tenant_id: str
    cidr: str
    discovery_source: str
    lifecycle_state: str
    asset_count: int
    created_at: datetime
    updated_at: datetime


class ListNetworkRangesResponse(BaseModel):
    items: list[NetworkRangeResponse]
    count: int


class FormNetworkRangeRequest(BaseModel):
    cidr: str = Field(min_length=1)
    discovery_source: str | None = None
    range_id: str | None = None


class RecordNetworkRangeAssetCountRequest(BaseModel):
    count: int = Field(ge=0)
