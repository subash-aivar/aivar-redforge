"""Detection read-model store port and in-memory implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from detection.application.projections.read_models import (
    DetectionCoverageMatrix,
    ExceptionExpiryView,
    ExecutionHealthView,
    FindingSummaryView,
    RuleFalsePositiveProfileView,
    TenantCoverageGapView,
)

PROJECTION_VERSION = 1


class IReadModelStore(ABC):
    @abstractmethod
    async def save_coverage_matrix(self, view: DetectionCoverageMatrix) -> None: ...

    @abstractmethod
    async def load_coverage_matrix(
        self, tenant_id: str
    ) -> DetectionCoverageMatrix | None: ...

    @abstractmethod
    async def save_fp_profile(self, view: RuleFalsePositiveProfileView) -> None: ...

    @abstractmethod
    async def load_fp_profile(
        self, tenant_id: str
    ) -> RuleFalsePositiveProfileView | None: ...

    @abstractmethod
    async def save_finding_summary(self, view: FindingSummaryView) -> None: ...

    @abstractmethod
    async def load_finding_summary(self, tenant_id: str) -> FindingSummaryView | None: ...

    @abstractmethod
    async def save_execution_health(self, view: ExecutionHealthView) -> None: ...

    @abstractmethod
    async def load_execution_health(self, tenant_id: str) -> ExecutionHealthView | None: ...

    @abstractmethod
    async def save_exception_expiry(self, view: ExceptionExpiryView) -> None: ...

    @abstractmethod
    async def load_exception_expiry(self, tenant_id: str) -> ExceptionExpiryView | None: ...

    @abstractmethod
    async def save_coverage_gap(self, view: TenantCoverageGapView) -> None: ...

    @abstractmethod
    async def load_coverage_gap(self, tenant_id: str) -> TenantCoverageGapView | None: ...

    @abstractmethod
    async def clear_tenant(self, tenant_id: str) -> None: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...


class InMemoryReadModelStore(IReadModelStore):
    def __init__(self) -> None:
        self.coverage: dict[str, DetectionCoverageMatrix] = {}
        self.fp_profiles: dict[str, RuleFalsePositiveProfileView] = {}
        self.findings: dict[str, FindingSummaryView] = {}
        self.executions: dict[str, ExecutionHealthView] = {}
        self.exceptions: dict[str, ExceptionExpiryView] = {}
        self.gaps: dict[str, TenantCoverageGapView] = {}

    async def save_coverage_matrix(self, view: DetectionCoverageMatrix) -> None:
        self.coverage[view.tenant_id] = view

    async def load_coverage_matrix(
        self, tenant_id: str
    ) -> DetectionCoverageMatrix | None:
        return self.coverage.get(tenant_id)

    async def save_fp_profile(self, view: RuleFalsePositiveProfileView) -> None:
        self.fp_profiles[view.tenant_id] = view

    async def load_fp_profile(
        self, tenant_id: str
    ) -> RuleFalsePositiveProfileView | None:
        return self.fp_profiles.get(tenant_id)

    async def save_finding_summary(self, view: FindingSummaryView) -> None:
        self.findings[view.tenant_id] = view

    async def load_finding_summary(self, tenant_id: str) -> FindingSummaryView | None:
        return self.findings.get(tenant_id)

    async def save_execution_health(self, view: ExecutionHealthView) -> None:
        self.executions[view.tenant_id] = view

    async def load_execution_health(self, tenant_id: str) -> ExecutionHealthView | None:
        return self.executions.get(tenant_id)

    async def save_exception_expiry(self, view: ExceptionExpiryView) -> None:
        self.exceptions[view.tenant_id] = view

    async def load_exception_expiry(self, tenant_id: str) -> ExceptionExpiryView | None:
        return self.exceptions.get(tenant_id)

    async def save_coverage_gap(self, view: TenantCoverageGapView) -> None:
        self.gaps[view.tenant_id] = view

    async def load_coverage_gap(self, tenant_id: str) -> TenantCoverageGapView | None:
        return self.gaps.get(tenant_id)

    async def clear_tenant(self, tenant_id: str) -> None:
        self.coverage.pop(tenant_id, None)
        self.fp_profiles.pop(tenant_id, None)
        self.findings.pop(tenant_id, None)
        self.executions.pop(tenant_id, None)
        self.exceptions.pop(tenant_id, None)
        self.gaps.pop(tenant_id, None)

    def status(self) -> dict[str, Any]:
        tenants = sorted(
            set(self.coverage)
            | set(self.fp_profiles)
            | set(self.findings)
            | set(self.executions)
            | set(self.exceptions)
            | set(self.gaps)
        )
        return {
            "backend": "in_memory",
            "projection_version": PROJECTION_VERSION,
            "tenants": tenants,
            "counts": {
                "coverage": len(self.coverage),
                "fp_profiles": len(self.fp_profiles),
                "findings": len(self.findings),
                "executions": len(self.executions),
                "exceptions": len(self.exceptions),
                "gaps": len(self.gaps),
            },
        }
