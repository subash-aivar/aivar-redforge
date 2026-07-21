"""DTOs for exposure_reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ExposureReportDTO:
    report_id: str
    tenant_id: str
    report_type: str
    status: str
    template_id: str
    narrative: str
    content: dict[str, Any]
    generated_by: str
    generated_at: str
    time_range_start: str | None
    time_range_end: str | None
    delivered_at: str | None
    data_freshness_warning: bool = False


@dataclass(slots=True)
class BusinessImpactMappingDTO:
    mapping_id: str
    tenant_id: str
    asset_ref_id: str
    criticality: str
    impact_domain: str
    authored_by: str
    created_at: str
    updated_at: str
    business_process_ref: str | None = None
    business_unit_ref: str | None = None
    financial_impact_estimate: float | None = None
    regulatory_scope: list[str] = field(default_factory=list)
    financial_impact_label: str = "Tenant-provided estimate, not platform-computed"


@dataclass(slots=True)
class DashboardDTO:
    tenant_id: str
    tenant_exposure_score: float
    asset_count: int
    mapped_asset_count: int
    unmapped_asset_count: int
    dominant_amplifier: str | None
    kpi: dict[str, Any]
    top_assets: list[dict[str, Any]]
    business_impact_mapped: bool
    data_freshness_warning: bool
    generated_at: str


@dataclass(slots=True)
class TrendPointDTO:
    computed_at: str
    tenant_exposure_score: float
    asset_count: int


@dataclass(slots=True)
class TrendDTO:
    tenant_id: str
    points: list[TrendPointDTO]
    score_input_version: str
