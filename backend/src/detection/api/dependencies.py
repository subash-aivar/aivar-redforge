"""FastAPI dependencies for detection routes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import Depends, Request

from detection.application.services.correlation_coordinator import CorrelationCoordinator
from detection.application.services.execution_finding_application_service import (
    ExecutionFindingApplicationService,
)
from detection.application.services.phase4_application_service import (
    PackExceptionEvidenceApplicationService,
)
from detection.application.services.platform_orchestration_service import (
    PlatformOrchestrationService,
)
from detection.application.services.projection_application_service import (
    ProjectionApplicationService,
)
from detection.application.services.rule_application_service import RuleApplicationService
from detection.application.services.telemetry_application_service import (
    TelemetryApplicationService,
)
from redforge.api.security import TenantContext, get_tenant_context

if TYPE_CHECKING:
    from detection.infrastructure.container import DetectionContainer


async def get_detection_container(request: Request) -> DetectionContainer:
    container: DetectionContainer = request.app.state.detection_container
    return container


def get_tenant_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.organization_id)


def get_principal_uuid(tenant: TenantContext = Depends(get_tenant_context)) -> UUID:
    return UUID(tenant.user_id)


async def get_rule_service(
    container: DetectionContainer = Depends(get_detection_container),
) -> RuleApplicationService:
    return container.rule_service


async def get_telemetry_service(
    container: DetectionContainer = Depends(get_detection_container),
) -> TelemetryApplicationService:
    return container.telemetry_service


async def get_execution_finding_service(
    container: DetectionContainer = Depends(get_detection_container),
) -> ExecutionFindingApplicationService:
    return container.execution_finding_service


async def get_phase4_service(
    container: DetectionContainer = Depends(get_detection_container),
) -> PackExceptionEvidenceApplicationService:
    return container.phase4_service


async def get_correlation_coordinator(
    container: DetectionContainer = Depends(get_detection_container),
) -> CorrelationCoordinator:
    return container.correlation_coordinator


async def get_projection_service(
    container: DetectionContainer = Depends(get_detection_container),
) -> ProjectionApplicationService:
    return container.projection_service


async def get_platform_orchestration(
    container: DetectionContainer = Depends(get_detection_container),
) -> PlatformOrchestrationService:
    return container.platform_orchestration


RuleServiceDep = Annotated[RuleApplicationService, Depends(get_rule_service)]
TelemetryServiceDep = Annotated[TelemetryApplicationService, Depends(get_telemetry_service)]
ExecutionFindingServiceDep = Annotated[
    ExecutionFindingApplicationService, Depends(get_execution_finding_service)
]
Phase4ServiceDep = Annotated[
    PackExceptionEvidenceApplicationService, Depends(get_phase4_service)
]
CorrelationCoordinatorDep = Annotated[
    CorrelationCoordinator, Depends(get_correlation_coordinator)
]
ProjectionServiceDep = Annotated[
    ProjectionApplicationService, Depends(get_projection_service)
]
PlatformOrchestrationDep = Annotated[
    PlatformOrchestrationService, Depends(get_platform_orchestration)
]
TenantIdDep = Annotated[UUID, Depends(get_tenant_uuid)]
PrincipalIdDep = Annotated[UUID, Depends(get_principal_uuid)]
