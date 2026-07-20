"""FastAPI exception handlers for detection domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from detection.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.domain.exceptions.domain_exceptions import (
    DetectionExecutionNotFound,
    DetectionFindingNotFound,
    DetectionRuleAlreadyExists,
    DetectionRuleNotFound,
    ExecutionLifecycleBlocked,
    FindingLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
    OptimisticLockConflict,
    ProviderNotRegistered,
    RulePromotionBlocked,
    RuleVersionImmutable,
    SchemaValidationFailed,
    SchemaVersionMismatch,
    SimulationBlocked,
    TelemetrySourceAlreadyExists,
    TelemetrySourceNotFound,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_detection_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(DetectionRuleNotFound)
    async def handle_rule_not_found(
        _request: Request, exc: DetectionRuleNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationNotFoundError)
    async def handle_app_not_found(
        _request: Request, exc: ApplicationNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(DetectionRuleAlreadyExists)
    async def handle_rule_exists(
        _request: Request, exc: DetectionRuleAlreadyExists
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ApplicationConflictError)
    async def handle_app_conflict(
        _request: Request, exc: ApplicationConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflict)
    async def handle_lock_conflict(
        _request: Request, exc: OptimisticLockConflict
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RulePromotionBlocked)
    async def handle_promotion_blocked(
        _request: Request, exc: RulePromotionBlocked
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RuleVersionImmutable)
    async def handle_version_immutable(
        _request: Request, exc: RuleVersionImmutable
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidStateTransition)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidArgument)
    async def handle_invalid_argument(_request: Request, exc: InvalidArgument) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(_request: Request, exc: TenantMismatch) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TelemetrySourceNotFound)
    async def handle_source_not_found(
        _request: Request, exc: TelemetrySourceNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(TelemetrySourceAlreadyExists)
    async def handle_source_exists(
        _request: Request, exc: TelemetrySourceAlreadyExists
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(SimulationBlocked)
    async def handle_simulation_blocked(
        _request: Request, exc: SimulationBlocked
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(SchemaValidationFailed)
    async def handle_schema_validation(
        _request: Request, exc: SchemaValidationFailed
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ProviderNotRegistered)
    async def handle_provider_missing(
        _request: Request, exc: ProviderNotRegistered
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(SchemaVersionMismatch)
    async def handle_schema_mismatch(
        _request: Request, exc: SchemaVersionMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DetectionExecutionNotFound)
    async def handle_execution_not_found(
        _request: Request, exc: DetectionExecutionNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(DetectionFindingNotFound)
    async def handle_finding_not_found(
        _request: Request, exc: DetectionFindingNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ExecutionLifecycleBlocked)
    async def handle_execution_blocked(
        _request: Request, exc: ExecutionLifecycleBlocked
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(FindingLifecycleBlocked)
    async def handle_finding_blocked(
        _request: Request, exc: FindingLifecycleBlocked
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
