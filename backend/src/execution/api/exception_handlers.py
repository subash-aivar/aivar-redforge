"""FastAPI exception handlers for execution domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from execution.application.exceptions import (
    ApplicationAuthorizationError,
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from execution.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    AttackActionNotFound,
    AuthorizationDenied,
    ExecutionWorkerNotFound,
    InvalidArgument,
    InvalidStateTransition,
    JournalNotFound,
    KillSwitchNotFound,
    OptimisticLockConflict,
    PlatformWideReleaseAuthorizationInsufficient,
    SameOperatorReleaseForbidden,
    TenantMismatch,
    WorkerDecommissioned,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_execution_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(KillSwitchNotFound)
    async def handle_ks_not_found(_request: Request, exc: KillSwitchNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(JournalNotFound)
    async def handle_journal_not_found(_request: Request, exc: JournalNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(AttackActionNotFound)
    async def handle_action_not_found(
        _request: Request, exc: AttackActionNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ExecutionWorkerNotFound)
    async def handle_worker_not_found(
        _request: Request, exc: ExecutionWorkerNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationNotFoundError)
    async def handle_app_not_found(
        _request: Request, exc: ApplicationNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflict)
    async def handle_lock(_request: Request, exc: OptimisticLockConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ApplicationConflictError)
    async def handle_conflict(
        _request: Request, exc: ApplicationConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(AggregateSealed)
    async def handle_sealed(_request: Request, exc: AggregateSealed) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidStateTransition)
    async def handle_transition(
        _request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidArgument)
    async def handle_invalid_arg(_request: Request, exc: InvalidArgument) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(SameOperatorReleaseForbidden)
    async def handle_same_op(
        _request: Request, exc: SameOperatorReleaseForbidden
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(PlatformWideReleaseAuthorizationInsufficient)
    async def handle_platform_release(
        _request: Request, exc: PlatformWideReleaseAuthorizationInsufficient
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(AuthorizationDenied)
    async def handle_authz_denied(
        _request: Request, exc: AuthorizationDenied
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ApplicationAuthorizationError)
    async def handle_app_authz(
        _request: Request, exc: ApplicationAuthorizationError
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(WorkerDecommissioned)
    async def handle_decommissioned(
        _request: Request, exc: WorkerDecommissioned
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant(_request: Request, exc: TenantMismatch) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
