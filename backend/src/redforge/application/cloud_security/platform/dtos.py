"""DTOs / commands for M26 Phase 8 platform integration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class OrchestratePlatformCommand:
    organization_id: str
    cloud_account_id: UUID | None = None
    organization_wide: bool = False
    fail_fast: bool = False
    include_k8s: bool = False
    include_runtime: bool = False
    runtime_events: list[dict[str, Any]] = field(default_factory=list)
    correlation_id: str = ""
    request_id: str = ""
    cloud_asset_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class RegisterProviderLifecycleCommand:
    organization_id: str
    provider_type: str
    display_name: str
    polling_interval_seconds: int = 3600
    region_filter: tuple[str, ...] = ()
    service_filter: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RegisterAccountLifecycleCommand:
    organization_id: str
    cloud_provider_id: str
    external_id: str
    display_name: str
    account_type: str
    credential_reference_id: str
    tags: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class StepResultDTO:
    step_name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: float | None
    message: str
    error: str | None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class OrchestrationRunDTO:
    run_id: str
    organization_id: str
    scope: str
    target_id: str
    status: str
    steps: list[StepResultDTO]
    diagnostics: dict[str, Any]
    operation_id: str
    correlation_id: str
    request_id: str
    started_at: datetime
    completed_at: datetime | None
    row_version: int


@dataclass(frozen=True, slots=True)
class OrchestrationRunPageDTO:
    items: list[OrchestrationRunDTO]
    page: int
    size: int
    total: int


@dataclass(frozen=True, slots=True)
class ValidationCheckDTO:
    name: str
    passed: bool
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ValidationReportDTO:
    organization_id: str
    overall_passed: bool
    checks: list[ValidationCheckDTO]
    created_at: datetime
    operation_id: str = ""


@dataclass(frozen=True, slots=True)
class PackageHealthDTO:
    package: str
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PlatformHealthDTO:
    overall: str
    packages: list[PackageHealthDTO]
    checked_at: datetime
    operation_id: str = ""


@dataclass(frozen=True, slots=True)
class PlatformSummaryDTO:
    organization_id: str
    account_count: int
    provider_count: int
    last_run_status: str | None
    last_run_id: str | None
    last_run_at: datetime | None
    health_overall: str
    validation_passed: bool | None


@dataclass(frozen=True, slots=True)
class SyncStatusDTO:
    organization_id: str
    accounts: list[dict[str, Any]]
    last_orchestration: dict[str, Any] | None
    aggregated_status: str


@dataclass(frozen=True, slots=True)
class PlatformDiagnosticsDTO:
    organization_id: str
    operation_id: str
    health: PlatformHealthDTO
    last_run: OrchestrationRunDTO | None
    sync: SyncStatusDTO
    notes: list[str] = field(default_factory=list)
