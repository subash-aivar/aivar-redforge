from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class ScheduleMLModelTrainingCommand:
    tenant_id: UUID
    model_type: str
    dataset_id: str | None = None
    actor_roles: tuple[str, ...] = ()
    training_rows: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True, slots=True)
class PromoteMLModelCommand:
    tenant_id: UUID
    model_id: UUID
    deployed_by: str = "admin"
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeprecateMLModelCommand:
    tenant_id: UUID
    model_id: UUID
    deprecated_by: str = "admin"
    actor_roles: tuple[str, ...] = ()
