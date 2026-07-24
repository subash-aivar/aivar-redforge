"""AiDeploymentDTO — the read-only projection of an `AiDeployment`
returned by the application layer (M47A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class AiDeploymentDTO:
    deployment_id: str
    tenant_id: str
    target_id: str
    model_family: str
    model_version: str
    provider_id: str
    endpoint_url: str
    status: str
    created_at: datetime
    updated_at: datetime
