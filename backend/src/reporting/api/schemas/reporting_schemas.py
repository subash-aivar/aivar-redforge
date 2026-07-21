from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class CreateScheduledReportRequest(BaseModel):
    template_id: UUID
    schedule: str = "0 * * * *"
    parameters: dict[str, Any] = Field(default_factory=dict)
    recipients: list[str] = Field(default_factory=list)
    cadence_minutes: int = Field(default=60, ge=1)
    created_by: str = "system"


class GenerateReportOnDemandRequest(BaseModel):
    template_id: UUID
    parameters: dict[str, Any] = Field(default_factory=dict)
    generated_by: str = "system"


class ExportReportRequest(BaseModel):
    format: str = "CSV"


class BIExportRequestBody(BaseModel):
    dataset_ref: str
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=100, ge=1, le=1000)
    actor: str = "bi"
