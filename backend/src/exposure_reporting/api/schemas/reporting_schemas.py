from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class GenerateReportRequest(BaseModel):
    report_type: str
    generated_by: str = Field(min_length=1)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None


class DeliverReportRequest(BaseModel):
    delivery_channel: str = "api"


class CreateBusinessImpactMappingRequest(BaseModel):
    asset_ref_id: UUID
    criticality: str
    impact_domain: str
    authored_by: str = Field(min_length=1)
    business_process_ref: str | None = None
    business_unit_ref: str | None = None
    financial_impact_estimate: float | None = None
    regulatory_scope: list[str] = Field(default_factory=list)


class UpdateBusinessImpactMappingRequest(BaseModel):
    criticality: str
    impact_domain: str
    authored_by: str = Field(min_length=1)
    business_process_ref: str | None = None
    business_unit_ref: str | None = None
    financial_impact_estimate: float | None = None
    regulatory_scope: list[str] | None = None
