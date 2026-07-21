"""Commands for exposure_reporting Phase 5."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class GenerateExposureReportCommand:
    tenant_id: UUID
    report_type: str
    generated_by: str
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeliverExposureReportCommand:
    tenant_id: UUID
    report_id: UUID
    delivery_channel: str = "api"
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CreateBusinessImpactMappingCommand:
    tenant_id: UUID
    asset_ref_id: UUID
    criticality: str
    impact_domain: str
    authored_by: str
    business_process_ref: str | None = None
    business_unit_ref: str | None = None
    financial_impact_estimate: float | None = None
    regulatory_scope: tuple[str, ...] = ()
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class UpdateBusinessImpactMappingCommand:
    tenant_id: UUID
    asset_ref_id: UUID
    criticality: str
    impact_domain: str
    authored_by: str
    business_process_ref: str | None = None
    business_unit_ref: str | None = None
    financial_impact_estimate: float | None = None
    regulatory_scope: tuple[str, ...] | None = None
    actor_roles: tuple[str, ...] = ()
