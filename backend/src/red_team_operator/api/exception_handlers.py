"""FastAPI exception handlers for operator domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from red_team_operator.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from red_team_operator.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    OperatorNotAuthorized,
    OperatorNotFound,
    OptimisticLockConflict,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_operator_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(OperatorNotFound)
    async def handle_operator_not_found(
        _request: Request, exc: OperatorNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationNotFoundError)
    async def handle_app_not_found(
        _request: Request, exc: ApplicationNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

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

    @app.exception_handler(OperatorNotAuthorized)
    async def handle_not_authorized(
        _request: Request, exc: OperatorNotAuthorized
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(
        _request: Request, exc: TenantMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
