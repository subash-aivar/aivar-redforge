"""FastAPI exception handlers for threat_report_intel domain/
application/infrastructure errors — mirrors
`infrastructure_intel.api.exception_handlers`'s convention exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from threat_report_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_report_intel.domain.exceptions.domain_exceptions import (
    DuplicateThreatReportError,
    EmptyIdentifierError,
    InvalidCanonicalTitleError,
    InvalidLifecycleTransitionError,
    MissingSupersededByError,
    TenantMismatchError,
)
from threat_report_intel.infrastructure.persistence.exceptions import (
    OptimisticLockConflictError,
    ThreatReportIntelIntegrityError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_threat_report_intel_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApplicationNotFoundError)
    async def handle_not_found(_request: Request, exc: ApplicationNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationForbiddenError)
    async def handle_forbidden(_request: Request, exc: ApplicationForbiddenError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatchError)
    async def handle_tenant_mismatch(_request: Request, exc: TenantMismatchError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidCanonicalTitleError)
    async def handle_invalid_canonical_title(
        _request: Request, exc: InvalidCanonicalTitleError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingSupersededByError)
    async def handle_missing_superseded_by(
        _request: Request, exc: MissingSupersededByError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicateThreatReportError)
    async def handle_duplicate(_request: Request, exc: DuplicateThreatReportError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidLifecycleTransitionError)
    async def handle_invalid_lifecycle_transition(
        _request: Request, exc: InvalidLifecycleTransitionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ThreatReportIntelIntegrityError)
    async def handle_integrity_error(
        _request: Request, exc: ThreatReportIntelIntegrityError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflictError)
    async def handle_optimistic_lock_conflict(
        _request: Request, exc: OptimisticLockConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})
