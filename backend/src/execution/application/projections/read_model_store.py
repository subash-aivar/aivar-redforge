"""Red-team read-model store port and in-memory implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from execution.application.projections.read_models import (
    ActionByTechniqueView,
    DetectionCoverageReport,
    EngagementSummaryView,
    EvidenceAuditView,
    OperationTimelineView,
    OperatorActivityView,
)

PROJECTION_VERSION = 1


class IReadModelStore(ABC):
    @abstractmethod
    async def save_engagement_summary(self, view: EngagementSummaryView) -> None: ...

    @abstractmethod
    async def load_engagement_summary(
        self, tenant_id: str, view_key: str
    ) -> EngagementSummaryView | None: ...

    @abstractmethod
    async def save_operation_timeline(self, view: OperationTimelineView) -> None: ...

    @abstractmethod
    async def load_operation_timeline(
        self, tenant_id: str, view_key: str
    ) -> OperationTimelineView | None: ...

    @abstractmethod
    async def save_action_by_technique(self, view: ActionByTechniqueView) -> None: ...

    @abstractmethod
    async def load_action_by_technique(
        self, tenant_id: str, view_key: str = "default"
    ) -> ActionByTechniqueView | None: ...

    @abstractmethod
    async def save_detection_coverage(self, view: DetectionCoverageReport) -> None: ...

    @abstractmethod
    async def load_detection_coverage(
        self, tenant_id: str, view_key: str = "default"
    ) -> DetectionCoverageReport | None: ...

    @abstractmethod
    async def save_evidence_audit(self, view: EvidenceAuditView) -> None: ...

    @abstractmethod
    async def load_evidence_audit(
        self, tenant_id: str, view_key: str = "default"
    ) -> EvidenceAuditView | None: ...

    @abstractmethod
    async def save_operator_activity(self, view: OperatorActivityView) -> None: ...

    @abstractmethod
    async def load_operator_activity(
        self, tenant_id: str, view_key: str = "default"
    ) -> OperatorActivityView | None: ...

    @abstractmethod
    async def list_operation_timelines(
        self, tenant_id: str
    ) -> list[OperationTimelineView]: ...

    @abstractmethod
    async def clear_tenant(self, tenant_id: str) -> None: ...

    @abstractmethod
    async def clear_all(self) -> None: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...


class InMemoryReadModelStore(IReadModelStore):
    def __init__(self) -> None:
        self.engagements: dict[tuple[str, str], EngagementSummaryView] = {}
        self.timelines: dict[tuple[str, str], OperationTimelineView] = {}
        self.techniques: dict[tuple[str, str], ActionByTechniqueView] = {}
        self.coverage: dict[tuple[str, str], DetectionCoverageReport] = {}
        self.evidence: dict[tuple[str, str], EvidenceAuditView] = {}
        self.operators: dict[tuple[str, str], OperatorActivityView] = {}

    async def save_engagement_summary(self, view: EngagementSummaryView) -> None:
        self.engagements[(view.tenant_id, view.view_key)] = view

    async def load_engagement_summary(
        self, tenant_id: str, view_key: str
    ) -> EngagementSummaryView | None:
        return self.engagements.get((tenant_id, view_key))

    async def save_operation_timeline(self, view: OperationTimelineView) -> None:
        self.timelines[(view.tenant_id, view.view_key)] = view

    async def load_operation_timeline(
        self, tenant_id: str, view_key: str
    ) -> OperationTimelineView | None:
        return self.timelines.get((tenant_id, view_key))

    async def save_action_by_technique(self, view: ActionByTechniqueView) -> None:
        self.techniques[(view.tenant_id, view.view_key)] = view

    async def load_action_by_technique(
        self, tenant_id: str, view_key: str = "default"
    ) -> ActionByTechniqueView | None:
        return self.techniques.get((tenant_id, view_key))

    async def save_detection_coverage(self, view: DetectionCoverageReport) -> None:
        self.coverage[(view.tenant_id, view.view_key)] = view

    async def load_detection_coverage(
        self, tenant_id: str, view_key: str = "default"
    ) -> DetectionCoverageReport | None:
        return self.coverage.get((tenant_id, view_key))

    async def save_evidence_audit(self, view: EvidenceAuditView) -> None:
        self.evidence[(view.tenant_id, view.view_key)] = view

    async def load_evidence_audit(
        self, tenant_id: str, view_key: str = "default"
    ) -> EvidenceAuditView | None:
        return self.evidence.get((tenant_id, view_key))

    async def save_operator_activity(self, view: OperatorActivityView) -> None:
        self.operators[(view.tenant_id, view.view_key)] = view

    async def load_operator_activity(
        self, tenant_id: str, view_key: str = "default"
    ) -> OperatorActivityView | None:
        return self.operators.get((tenant_id, view_key))

    async def list_operation_timelines(
        self, tenant_id: str
    ) -> list[OperationTimelineView]:
        return [v for (t, _), v in self.timelines.items() if t == tenant_id]

    async def clear_tenant(self, tenant_id: str) -> None:
        for store in (
            self.engagements,
            self.timelines,
            self.techniques,
            self.coverage,
            self.evidence,
            self.operators,
        ):
            for key in [k for k in store if k[0] == tenant_id]:
                del store[key]

    async def clear_all(self) -> None:
        self.engagements.clear()
        self.timelines.clear()
        self.techniques.clear()
        self.coverage.clear()
        self.evidence.clear()
        self.operators.clear()

    def status(self) -> dict[str, Any]:
        tenants = sorted(
            {k[0] for k in self.engagements}
            | {k[0] for k in self.timelines}
            | {k[0] for k in self.techniques}
            | {k[0] for k in self.coverage}
            | {k[0] for k in self.evidence}
            | {k[0] for k in self.operators}
        )
        return {
            "backend": "in_memory",
            "projection_version": PROJECTION_VERSION,
            "tenants": tenants,
            "counts": {
                "engagements": len(self.engagements),
                "timelines": len(self.timelines),
                "techniques": len(self.techniques),
                "coverage": len(self.coverage),
                "evidence": len(self.evidence),
                "operators": len(self.operators),
            },
        }
