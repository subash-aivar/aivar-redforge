from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RegisterDataSetRequest(BaseModel):
    domain: str
    schema_version: str = "1"


class DefineKPIRequest(BaseModel):
    kpi_type: str
    computation_schedule: str = "0 2 * * *"


class CreateBaselineRequest(BaseModel):
    signal_type: str
    method: str
    window_days: int = Field(default=30, ge=7, le=365)


class IngestEventRequest(BaseModel):
    domain: str
    event_id: str
    event_type: str
    event_ts: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class TriggerKPIRequest(BaseModel):
    kpi_type: str


class EvaluateAnomalyRequest(BaseModel):
    signal_type: str
    observed: float


class CreateQueryRequest(BaseModel):
    name: str
    template: str
    domain: str
    parameters: list[str] = Field(default_factory=list)
    created_by: str = "system"


class ExecuteQueryRequest(BaseModel):
    parameters: dict[str, Any] = Field(default_factory=dict)
    executed_by: str = "system"


class RebuildRequest(BaseModel):
    domain: str | None = None
