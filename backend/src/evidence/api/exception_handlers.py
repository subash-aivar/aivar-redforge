"""FastAPI exception handlers for evidence domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from evidence.application.exceptions import (
    ApplicationAuthorizationError,
    ApplicationConflictError,
    ApplicationIntegrityError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from evidence.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    EvidenceChainNotFound,
    EvidenceIntegrityViolation,
    EvidenceNotFound,
    EvidenceQuarantinedError,
    InvalidArgument,
    InvalidStateTransition,
    OptimisticLockConflict,
    RetentionWindowActive,
    SealerRoleRequired,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_evidence_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(EvidenceNotFound)
    async def handle_evidence_not_found(
        _request: Request, exc: EvidenceNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(EvidenceChainNotFound)
    async def handle_chain_not_found(
        _request: Request, exc: EvidenceChainNotFound
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

    @app.exception_handler(AggregateSealed)
    async def handle_sealed(
        _request: Request, exc: AggregateSealed
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RetentionWindowActive)
    async def handle_retention(
        _request: Request, exc: RetentionWindowActive
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(EvidenceQuarantinedError)
    async def handle_quarantined(
        _request: Request, exc: EvidenceQuarantinedError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(EvidenceIntegrityViolation)
    async def handle_integrity_violation(
        _request: Request, exc: EvidenceIntegrityViolation
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationIntegrityError)
    async def handle_app_integrity(
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
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(SealerRoleRequired)
    async def handle_sealer_role(
        _request: Request, exc: SealerRoleRequired
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ApplicationAuthorizationError)
    async def handle_app_authz(
        _request: Request, exc: ApplicationAuthorizationError
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(
        _request: Request, exc: TenantMismatch
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})
