"""FastAPI exception handlers for operation domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from operation.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from operation.domain.exceptions.domain_exceptions import (
    ApprovalAuthorityInsufficient,
    ConcurrentExecutingPlanError,
    CyclicDependencyError,
    EngagementNotActive,
    ExecutionPlanVersionNotFound,
    InvalidArgument,
    InvalidStateTransition,
    OperationNotFound,
    OptimisticLockConflict,
    PlanImmutabilityViolation,
    PlanValidationError,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_operation_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(OperationNotFound)
    async def handle_operation_not_found(
        _request: Request, exc: OperationNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ExecutionPlanVersionNotFound)
    async def handle_plan_not_found(
        _request: Request, exc: ExecutionPlanVersionNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationNotFoundError)
    async def handle_app_not_found(
        _request: Request, exc: ApplicationNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflict)
    async def handle_lock_conflict(
        _request: Request, exc: OptimisticLockConflict
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ApplicationConflictError)
    async def handle_app_conflict(
        _request: Request, exc: ApplicationConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ConcurrentExecutingPlanError)
    async def handle_concurrent_executing(
        _request: Request, exc: ConcurrentExecutingPlanError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(PlanImmutabilityViolation)
    async def handle_immutability(
        _request: Request, exc: PlanImmutabilityViolation
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidStateTransition)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidArgument)
    async def handle_invalid_argument(
        _request: Request, exc: InvalidArgument
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(CyclicDependencyError)
    async def handle_cycle(_request: Request, exc: CyclicDependencyError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(PlanValidationError)
    async def handle_plan_validation(
        _request: Request, exc: PlanValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApprovalAuthorityInsufficient)
    async def handle_authority(
        _request: Request, exc: ApprovalAuthorityInsufficient
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EngagementNotActive)
    async def handle_engagement_inactive(
        _request: Request, exc: EngagementNotActive
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(
        _request: Request, exc: TenantMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
