"""Six M31 Phase 5 read models + audit view."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

PROJECTION_VERSION = 1


@dataclass
class AIAssetInventoryDashboard:
    tenant_id: str
    assets: list[dict[str, Any]] = field(default_factory=list)
    last_scan_at: datetime | None = None
    configured_discovery_sources: list[str] = field(default_factory=list)
    coverage_scope: str = "unknown"
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class AIRiskRegister:
    tenant_id: str
    entries: list[dict[str, Any]] = field(default_factory=list)
    trend: list[dict[str, Any]] = field(default_factory=list)
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class ShadowAIDiscoveryReport:
    tenant_id: str
    scope_of_report: dict[str, Any] = field(default_factory=dict)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    partial_scans: list[dict[str, Any]] = field(default_factory=list)
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class AICompliancePostureReport:
    tenant_id: str
    framework_id: str
    controls: list[dict[str, Any]] = field(default_factory=list)
    gap_count: int = 0
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class AISupplyChainIntegrityReport:
    tenant_id: str
    models: list[dict[str, Any]] = field(default_factory=list)
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class AIAgentDeviationReport:
    tenant_id: str
    deviations: list[dict[str, Any]] = field(default_factory=list)
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION


@dataclass
class EnvelopeHumanApprovalAudit:
    tenant_id: str
    envelope_id: str
    history: list[dict[str, Any]] = field(default_factory=list)
    last_event_id: str = ""
    projection_version: int = PROJECTION_VERSION
