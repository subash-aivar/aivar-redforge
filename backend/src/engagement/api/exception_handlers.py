"""FastAPI exception handlers for engagement domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from engagement.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from engagement.domain.exceptions.domain_exceptions import (
    ArchivedImmutabilityViolation,
    AuthorizationReinstatementForbidden,
    DuplicateApproval,
    EngagementNotFound,
    InvalidArgument,
    InvalidStateTransition,
    OptimisticLockConflict,
    QuorumNotMet,
    ScopeImmutableViolation,
    TargetAuthorizationNotFound,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_engagement_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(EngagementNotFound)
    async def handle_engagement_not_found(
        _request: Request, exc: EngagementNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(TargetAuthorizationNotFound)
    async def handle_auth_not_found(
        _request: Request, exc: TargetAuthorizationNotFound
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

    @app.exception_handler(DuplicateApproval)
    async def handle_duplicate_approval(
        _request: Request, exc: DuplicateApproval
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ScopeImmutableViolation)
    async def handle_scope_immutable(
        _request: Request, exc: ScopeImmutableViolation
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ArchivedImmutabilityViolation)
    async def handle_archived(
        _request: Request, exc: ArchivedImmutabilityViolation
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(AuthorizationReinstatementForbidden)
    async def handle_reinstatement(
        _request: Request, exc: AuthorizationReinstatementForbidden
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

    @app.exception_handler(QuorumNotMet)
    async def handle_quorum(_request: Request, exc: QuorumNotMet) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(
        _request: Request, exc: TenantMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
