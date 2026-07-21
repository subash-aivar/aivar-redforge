from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScheduleTrainingRequest(BaseModel):
    model_type: str
    dataset_id: str | None = None
    training_rows: list[dict[str, Any]] = Field(default_factory=list)


class PromoteRequest(BaseModel):
    deployed_by: str = "admin"


class DeprecateRequest(BaseModel):
    deprecated_by: str = "admin"


class InferenceRequest(BaseModel):
    model_type: str
    assets: list[dict[str, Any]]


class DriftRequest(BaseModel):
    actual: list[float]
