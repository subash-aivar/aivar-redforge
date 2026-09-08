"""FastAPI exception handlers for threat_actor_intel domain/application
errors (M51.1 Phase 4) — mirrors `risk_engine.api.exception_handlers`'
`register_risk_engine_exception_handlers` convention exactly: one
`@app.exception_handler` per exception type, translating to the same
HTTP status class mature contexts use (404 not-found, 403 tenant/
authority violation, 409 conflict, 422 validation/state-precondition
failure). No custom exception framework — the same
`ApplicationError`/domain-exception -> `JSONResponse` translation
every other bounded context already uses."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from threat_actor_intel.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    AlreadyRetractedAssociationError,
    DuplicateActiveAssociationError,
    DuplicateAliasError,
    DuplicateIndicatorAssociationError,
    DuplicateTechniqueAssociationError,
    EmptyEvidenceCitationError,
    EmptyIdentifierError,
    EmptyMotivationSetError,
    EmptyThreatActorNameError,
    InvalidActivityStatusTransition,
    MissingTenantIdError,
    MissingThreatActorReferenceError,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_threat_actor_intel_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApplicationNotFoundError)
    async def handle_not_found(_request: Request, exc: ApplicationNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ApplicationForbiddenError)
    async def handle_forbidden(_request: Request, exc: ApplicationForbiddenError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_tenant_mismatch(_request: Request, exc: TenantMismatch) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicateActiveAssociationError)
    async def handle_duplicate_association(
        _request: Request, exc: DuplicateActiveAssociationError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(DuplicateAliasError)
    async def handle_duplicate_alias(_request: Request, exc: DuplicateAliasError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(DuplicateTechniqueAssociationError)
    async def handle_duplicate_technique(
        _request: Request, exc: DuplicateTechniqueAssociationError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(DuplicateIndicatorAssociationError)
    async def handle_duplicate_indicator(
        _request: Request, exc: DuplicateIndicatorAssociationError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(AlreadyRetractedAssociationError)
    async def handle_already_retracted(
        _request: Request, exc: AlreadyRetractedAssociationError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InvalidActivityStatusTransition)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidActivityStatusTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyMotivationSetError)
    async def handle_empty_motivations(
        _request: Request, exc: EmptyMotivationSetError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyThreatActorNameError)
    async def handle_empty_name(_request: Request, exc: EmptyThreatActorNameError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyEvidenceCitationError)
    async def handle_empty_citation(
        _request: Request, exc: EmptyEvidenceCitationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingTenantIdError)
    async def handle_missing_tenant(_request: Request, exc: MissingTenantIdError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingThreatActorReferenceError)
    async def handle_missing_actor_reference(
        _request: Request, exc: MissingThreatActorReferenceError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
