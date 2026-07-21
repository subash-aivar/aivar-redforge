from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterAnalyticsDataSetCommand:
    tenant_id: UUID
    domain: str
    schema_version: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DefineSecurityKPICommand:
    tenant_id: UUID
    kpi_type: str
    computation_schedule: str = "0 2 * * *"
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateAnomalyBaselineCommand:
    tenant_id: UUID
    signal_type: str
    method: str
    window_days: int = 30
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TriggerProjectionRebuildCommand:
    tenant_id: UUID
    domain: str | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TriggerKPIComputationCommand:
    tenant_id: UUID
    kpi_type: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class IngestAnalyticsEventCommand:
    tenant_id: UUID
    domain: str
    event_id: str
    event_type: str
    event_ts: datetime
    payload: dict[str, object]
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateAnalyticsQueryCommand:
    tenant_id: UUID
    name: str
    template: str
    domain: str
    parameters: tuple[str, ...] = ()
    created_by: str = ""
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExecuteAnalyticsQueryCommand:
    tenant_id: UUID
    query_id: UUID
    parameters: dict[str, object]
    executed_by: str
    actor_roles: tuple[str, ...] = ()
