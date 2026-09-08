"""FastAPI exception handlers for ioc_intelligence domain/application/
infrastructure errors (M51.2 Phase A4) — mirrors
`threat_actor_intel.api.exception_handlers`'s
`register_threat_actor_intel_exception_handlers` convention exactly:
one `@app.exception_handler` per exception type, translating to the
same HTTP status class mature contexts use. Never leaks internal
exception details or SQL errors — every handler returns only
`str(exc)`, and every persistence-layer exception (`IocIntelIntegrityError`)
is itself already a translated, driver-independent message (see
`PgIocRepository.save`), never a raw SQLAlchemy/asyncpg error."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from ioc_intelligence.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from ioc_intelligence.domain.exceptions.domain_exceptions import (
    DuplicateSourceAttributionError,
    EmptyIdentifierError,
    GlobalEvidenceCitationNotSupportedError,
    InvalidEpistemicStateTransitionError,
    InvalidIndicatorCanonicalKeyError,
    InvalidIndicatorValueError,
    InvalidLifecycleTransitionError,
    MissingTenantForObservationError,
    TenantMismatchError,
    UnrecognizedSourceSystemError,
    UnsourcedIocError,
)
from ioc_intelligence.infrastructure.persistence.exceptions import (
    IocIntelIntegrityError,
    OptimisticLockConflictError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_ioc_intelligence_exception_handlers(app: FastAPI) -> None:
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

    @app.exception_handler(UnsourcedIocError)
    async def handle_unsourced(_request: Request, exc: UnsourcedIocError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidIndicatorValueError)
    async def handle_invalid_value(
        _request: Request, exc: InvalidIndicatorValueError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidIndicatorCanonicalKeyError)
    async def handle_invalid_canonical_key(
        _request: Request, exc: InvalidIndicatorCanonicalKeyError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(UnrecognizedSourceSystemError)
    async def handle_unrecognized_source(
        _request: Request, exc: UnrecognizedSourceSystemError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(GlobalEvidenceCitationNotSupportedError)
    async def handle_global_evidence_not_supported(
        _request: Request, exc: GlobalEvidenceCitationNotSupportedError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingTenantForObservationError)
    async def handle_missing_tenant(
        _request: Request, exc: MissingTenantForObservationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicateSourceAttributionError)
    async def handle_duplicate_attribution(
        _request: Request, exc: DuplicateSourceAttributionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidLifecycleTransitionError)
    async def handle_invalid_lifecycle_transition(
        _request: Request, exc: InvalidLifecycleTransitionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidEpistemicStateTransitionError)
    async def handle_invalid_epistemic_transition(
        _request: Request, exc: InvalidEpistemicStateTransitionError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(IocIntelIntegrityError)
    async def handle_integrity_error(
        _request: Request, exc: IocIntelIntegrityError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflictError)
    async def handle_optimistic_lock_conflict(
        _request: Request, exc: OptimisticLockConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})
