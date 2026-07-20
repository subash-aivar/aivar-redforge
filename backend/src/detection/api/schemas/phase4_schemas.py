"""Pydantic schemas for Phase 4 APIs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CreatePackRequest(BaseModel):
    pack_key: str
    title: str
    category: str
    maintainer: str
    rule_ids: list[str] = Field(default_factory=list)
    description: str = ""
    compliance_framework_id: str | None = None
    tags: list[str] = Field(default_factory=list)


class SubscribePackRequest(BaseModel):
    subscriber_tenant_id: str


class DetectionPackResponse(BaseModel):
    pack_id: str
    pack_key: str
    title: str
    category: str
    lifecycle_state: str
    semver: str
    rule_ids: list[str]
    subscribed_tenants: list[str]
    compliance_framework_id: str | None = None
    coverage: dict[str, Any] = Field(default_factory=dict)


class ListPacksResponse(BaseModel):
    items: list[DetectionPackResponse]
    total: int
    limit: int
    offset: int


class RequestExceptionRequest(BaseModel):
    exception_type: str
    scope_kind: str
    justification: str
    requester: str
    valid_until: str
    affected_rule_ids: list[str]
    finding_id: str | None = None
    rule_id: str | None = None
    classification: str = "operational"
    compliance_mapped: bool = False
    compliance_impact_acknowledged: bool = False
    asset_ids: list[str] = Field(default_factory=list)


class ApproveExceptionRequest(BaseModel):
    approver: str


class RejectExceptionRequest(BaseModel):
    rejector: str
    reason: str


class RenewExceptionRequest(BaseModel):
    renewer: str
    new_valid_until: str


class RevokeExceptionRequest(BaseModel):
    revoker: str
    reason: str


class DetectionExceptionResponse(BaseModel):
    exception_id: str
    exception_type: str
    state: str
    requester: str
    valid_until: str
    affected_rule_ids: list[str]
    compliance_impact_acknowledged: bool
    approver: str | None = None
    justification: str = ""


class ListExceptionsResponse(BaseModel):
    items: list[DetectionExceptionResponse]
    total: int
    limit: int
    offset: int


class SubmitEvidenceRequest(BaseModel):
    evidence_type: str
    payload_b64: str
    collected_by: str
    finding_id: str | None = None
    exception_id: str | None = None
    simulation_id: str | None = None
    storage_uri: str | None = None


class DetectionEvidenceResponse(BaseModel):
    evidence_id: str
    evidence_type: str
    payload_hash: str
    storage_ref: str
    integrity_status: str
    collected_by: str
    finding_id: str | None = None
    exception_id: str | None = None
    simulation_id: str | None = None


class CorrelateFindingRequest(BaseModel):
    refresh: bool = False


class CorrelateFindingResponse(BaseModel):
    finding_id: str
    status: str
    sources_succeeded: int = 0
    sources_failed: int = 0
    skipped: bool = False
    correlation_id: str | None = None
    errors: list[str] = Field(default_factory=list)
    error: str | None = None


class CoverageTechniqueResponse(BaseModel):
    technique_id: str
    rule_count: int
    rule_ids: list[str]
    covered: bool


class DetectionCoverageResponse(BaseModel):
    tenant_id: str
    techniques: list[CoverageTechniqueResponse]
    covered_count: int
    gap_count: int
    gaps: list[str]
    total_in_scope: int
