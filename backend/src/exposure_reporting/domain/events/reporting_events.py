"""Domain events for exposure_reporting Phase 5."""

from __future__ import annotations

from dataclasses import dataclass

from exposure_reporting.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ExposureReportGenerated(BaseDomainEvent):
    report_type: str = ""
    template_id: str = ""


@dataclass(frozen=True, slots=True)
class ExposureReportDelivered(BaseDomainEvent):
    delivery_channel: str = ""


@dataclass(frozen=True, slots=True)
class BusinessImpactMappingCreated(BaseDomainEvent):
    asset_ref_id: str = ""
    criticality: str = ""


@dataclass(frozen=True, slots=True)
class BusinessImpactMappingUpdated(BaseDomainEvent):
    asset_ref_id: str = ""
    criticality: str = ""


@dataclass(frozen=True, slots=True)
class ExposureGraphNodeUpserted(BaseDomainEvent):
    node_type: str = ""
    node_key: str = ""


@dataclass(frozen=True, slots=True)
class ExposureGraphEdgeUpserted(BaseDomainEvent):
    edge_type: str = ""
    from_key: str = ""
    to_key: str = ""
