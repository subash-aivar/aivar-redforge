"""FastAPI exception handlers for intelligence_relationships domain/
application/infrastructure errors (M51.4 Phase C1) — mirrors
`attack_pattern_intel.api.exception_handlers`'s convention exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from intelligence_relationships.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from intelligence_relationships.domain.exceptions.domain_exceptions import (
    DuplicateRelationshipError,
    EmptyIdentifierError,
    IncompatibleRelationshipEndpointsError,
    InvalidEpistemicStateTransitionError,
    InvalidLifecycleTransitionError,
    InvalidValidityWindowError,
    MissingSupersededByError,
    SelfReferentialRelationshipError,
    TenantMismatchError,
    UnknownAttackPatternError,
    UnknownIocError,
    UnknownThreatActorError,
)
from intelligence_relationships.infrastructure.persistence.exceptions import (
    IntelligenceRelationshipsIntegrityError,
    OptimisticLockConflictError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_intelligence_relationships_exception_handlers(app: FastAPI) -> None:
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

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(IncompatibleRelationshipEndpointsError)
    async def handle_incompatible_endpoints(
        _request: Request, exc: IncompatibleRelationshipEndpointsError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(SelfReferentialRelationshipError)
    async def handle_self_referential(
        _request: Request, exc: SelfReferentialRelationshipError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidValidityWindowError)
    async def handle_invalid_validity(
        _request: Request, exc: InvalidValidityWindowError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(UnknownIocError)
    async def handle_unknown_ioc(_request: Request, exc: UnknownIocError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(UnknownThreatActorError)
    async def handle_unknown_threat_actor(
        _request: Request, exc: UnknownThreatActorError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(UnknownAttackPatternError)
    async def handle_unknown_attack_pattern(
        _request: Request, exc: UnknownAttackPatternError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(MissingSupersededByError)
    async def handle_missing_superseded_by(
        _request: Request, exc: MissingSupersededByError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicateRelationshipError)
    async def handle_duplicate(_request: Request, exc: DuplicateRelationshipError) -> JSONResponse:
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

    @app.exception_handler(IntelligenceRelationshipsIntegrityError)
    async def handle_integrity_error(
        _request: Request, exc: IntelligenceRelationshipsIntegrityError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflictError)
    async def handle_optimistic_lock_conflict(
        _request: Request, exc: OptimisticLockConflictError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})
