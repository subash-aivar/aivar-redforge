"""FastAPI exception handlers for payload domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from payload.application.exceptions import (
    ApplicationAuthorizationError,
    ApplicationConflictError,
    ApplicationIntegrityError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from payload.domain.exceptions.domain_exceptions import (
    CisoApprovalRequired,
    InvalidArgument,
    InvalidStateTransition,
    OptimisticLockConflict,
    PayloadHashMismatch,
    PayloadNotFound,
    PluginNotFound,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_payload_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PayloadNotFound)
    async def handle_payload_not_found(
        _request: Request, exc: PayloadNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(PluginNotFound)
    async def handle_plugin_not_found(
        _request: Request, exc: PluginNotFound
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

    @app.exception_handler(CisoApprovalRequired)
    async def handle_ciso(
        _request: Request, exc: CisoApprovalRequired
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(PayloadHashMismatch)
    async def handle_hash_mismatch(
        _request: Request, exc: PayloadHashMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationIntegrityError)
    async def handle_integrity(
        _request: Request, exc: ApplicationIntegrityError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

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
    async def handle_validation(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationAuthorizationError)
    async def handle_authz(
        _request: Request, exc: ApplicationAuthorizationError
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant(
        _request: Request, exc: TenantMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
