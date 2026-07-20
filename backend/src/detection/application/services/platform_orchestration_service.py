"""PlatformOrchestrationService — end-to-end detection lifecycle integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from detection.application.projections.projection_coordinator import (
        ProjectionCoordinator,
    )
    from detection.application.services.correlation_coordinator import (
        CorrelationCoordinator,
    )
    from detection.application.services.execution_finding_application_service import (
        ExecutionFindingApplicationService,
    )
    from detection.application.services.phase4_application_service import (
        PackExceptionEvidenceApplicationService,
    )
    from detection.application.services.projection_application_service import (
        ProjectionApplicationService,
    )
    from detection.application.services.rule_application_service import (
        RuleApplicationService,
    )
    from detection.application.services.telemetry_application_service import (
        TelemetryApplicationService,
    )
    from detection.domain.events.base import BaseDomainEvent


class PlatformOrchestrationService:
    """
    Integrates Phases 1-5 services into a coherent platform surface.

    Does not invent new domains - composes existing application services and
    feeds domain events into the projection coordinator.
    """

    LIFECYCLE_STAGES = (
        "DetectionRule",
        "TelemetrySource",
        "RuleSimulation",
        "DetectionExecution",
        "DetectionFinding",
        "Correlation",
        "DetectionException",
        "DetectionEvidence",
        "DetectionPack",
        "Coverage",
        "Projection",
        "ReadModels",
    )

    def __init__(
        self,
        *,
        rule_service: RuleApplicationService,
        telemetry_service: TelemetryApplicationService,
        execution_finding_service: ExecutionFindingApplicationService,
        phase4_service: PackExceptionEvidenceApplicationService,
        correlation_coordinator: CorrelationCoordinator,
        projection_service: ProjectionApplicationService,
        projection_coordinator: ProjectionCoordinator,
    ) -> None:
        self.rules = rule_service
        self.telemetry = telemetry_service
        self.executions = execution_finding_service
        self.phase4 = phase4_service
        self.correlation = correlation_coordinator
        self.projections = projection_service
        self.coordinator = projection_coordinator

    def lifecycle_map(self) -> dict[str, Any]:
        return {
            "stages": list(self.LIFECYCLE_STAGES),
            "description": (
                "DetectionRule → TelemetrySource → Simulation → Execution → "
                "Finding → Correlation → Exception → Evidence → Pack → "
                "Coverage → Projection → ReadModels"
            ),
        }

    async def project_events(self, events: list[BaseDomainEvent]) -> dict[str, Any]:
        """Feed committed domain events into projection pipeline."""
        return await self.coordinator.handle_batch(events)

    async def platform_status(self, tenant_id: UUID) -> dict[str, Any]:
        readiness = await self.projections.platform_readiness(tenant_id)
        return {
            "lifecycle": self.lifecycle_map(),
            "readiness": readiness,
            "services": {
                "rules": True,
                "telemetry": True,
                "executions_findings": True,
                "phase4": True,
                "correlation": True,
                "projections": True,
            },
        }
