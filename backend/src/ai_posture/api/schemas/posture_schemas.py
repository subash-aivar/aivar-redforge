"""Pydantic schemas for ai_posture API."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field


class RegisterAssetRequest(BaseModel):
    asset_ref_id: UUID
    discovery_source: str = "ManualRegistration"
    data_sensitivity: str = "Internal"
    as_shadow: bool = False


class ClassifyAssetRequest(BaseModel):
    ai_system_kind: str


class AssignOwnerRequest(BaseModel):
    owner_id: str
    owner_display_name: str = ""


class RaiseAlertRequest(BaseModel):
    cloud_account: str
    resource_identifier: str
    service_type: str
    region: str
    discovery_source: str = "ManualRegistration"


class TriageAlertRequest(BaseModel):
    triaged_by: str
    notes: str = ""


class BulkTriageRequest(BaseModel):
    triaged_by: str
    discovery_source: str | None = None
    cloud_account: str | None = None
    service_type: str | None = None
    notes: str = ""


class BulkResolveRequest(BaseModel):
    alert_ids: list[UUID]
    resolution_action: str
    confirm_as: str
    false_positive_reason: str = ""


class SetDiscoveryOnlyModeRequest(BaseModel):
    enabled: bool


class AssessThreatRequest(BaseModel):
    evidence_refs: list[str] = Field(default_factory=list)
