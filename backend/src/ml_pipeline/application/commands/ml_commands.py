from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ml_pipeline.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class ScheduleMLModelTrainingCommand:
    tenant_id: TenantId
    model_type: str
    dataset_id: str | None = None
    actor_roles: tuple[str, ...] = ()
    training_rows: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class PromoteMLModelCommand:
    tenant_id: TenantId
    model_id: UUID
    deployed_by: str = "admin"
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeprecateMLModelCommand:
    tenant_id: TenantId
    model_id: UUID
    deprecated_by: str = "admin"
    actor_roles: tuple[str, ...] = ()
