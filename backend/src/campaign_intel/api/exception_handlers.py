"""FastAPI exception handlers for campaign_intel domain/application/
infrastructure errors — mirrors `malware_intel.api.exception_handlers`'s
convention exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from campaign_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from campaign_intel.domain.exceptions.domain_exceptions import (
    DuplicateCampaignError,
    EmptyIdentifierError,
    InvalidCanonicalNameError,
    InvalidLifecycleTransitionError,
    InvalidRegionError,
    InvalidStatusTransitionError,
    InvalidTimelineError,
    MissingSupersededByError,
    TenantMismatchError,
)
from campaign_intel.infrastructure.persistence.exceptions import (
    CampaignIntelIntegrityError,
    OptimisticLockConflictError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_campaign_intel_exception_handlers(app: FastAPI) -> None:
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

    @app.exception_handler(InvalidCanonicalNameError)
    async def handle_invalid_canonical_name(
        _request: Request, exc: InvalidCanonicalNameError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidRegionError)
    async def handle_invalid_region(_request: Request, exc: InvalidRegionError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidTimelineError)
    async def handle_invalid_timeline(_request: Request, exc: InvalidTimelineError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingSupersededByError)
    async def handle_missing_superseded_by(
        _request: Request, exc: MissingSupersededByError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicateCampaignError)
    async def handle_duplicate(_request: Request, exc: DuplicateCampaignError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidLifecycleTransitionError)
    async def handle_invalid_lifecycle_transition(
        _request: Request, exc: InvalidLifecycleTransitionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidStatusTransitionError)
    async def handle_invalid_status_transition(
        _request: Request, exc: InvalidStatusTransitionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(CampaignIntelIntegrityError)
    async def handle_integrity_error(
        _request: Request, exc: CampaignIntelIntegrityError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflictError)
    async def handle_optimistic_lock_conflict(
        _request: Request, exc: OptimisticLockConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})
