"""FastAPI exception handlers for risk_engine domain/application
errors — mirrors `operation.api.exception_handlers`'
`register_operation_exception_handlers` convention exactly: one
`@app.exception_handler` per exception type, translating to the same
HTTP status class mature contexts use (404 not-found, 403 tenant/
authority violation, 409 conflict, 422 validation/state-precondition
failure)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from risk_engine.application.exceptions import (
    EmptySignalsError,
    EnterpriseRiskProfileNotFoundError,
    InvalidSubjectReferenceError,
    RiskCorrelationSetNotFoundError,
    RiskProfileNotAcceptedError,
    RiskTenantIsolationViolationError,
)
from risk_engine.domain.exceptions.domain_exceptions import (
    EmptyContributionsError,
    EmptyIdentifierError,
    InvalidCorrelationSetError,
    InvalidNormalizedRiskScoreError,
    InvalidRiskProfileTransition,
    InvalidRiskSignalReferenceError,
    InvalidRiskWeightProfileError,
    TenantMismatch,
    UnsupportedRiskScaleError,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_risk_engine_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(EnterpriseRiskProfileNotFoundError)
    async def handle_profile_not_found(
        _request: Request, exc: EnterpriseRiskProfileNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(RiskCorrelationSetNotFoundError)
    async def handle_correlation_not_found(
        _request: Request, exc: RiskCorrelationSetNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(RiskTenantIsolationViolationError)
    async def handle_tenant_isolation(
        _request: Request, exc: RiskTenantIsolationViolationError
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_domain_tenant_mismatch(_request: Request, exc: TenantMismatch) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(RiskProfileNotAcceptedError)
    async def handle_not_accepted(
        _request: Request, exc: RiskProfileNotAcceptedError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidRiskProfileTransition)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidRiskProfileTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptySignalsError)
    async def handle_empty_signals(_request: Request, exc: EmptySignalsError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidSubjectReferenceError)
    async def handle_invalid_subject_reference(
        _request: Request, exc: InvalidSubjectReferenceError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyContributionsError)
    async def handle_empty_contributions(
        _request: Request, exc: EmptyContributionsError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidNormalizedRiskScoreError)
    async def handle_invalid_score(
        _request: Request, exc: InvalidNormalizedRiskScoreError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidRiskSignalReferenceError)
    async def handle_invalid_signal_reference(
        _request: Request, exc: InvalidRiskSignalReferenceError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidRiskWeightProfileError)
    async def handle_invalid_weight_profile(
        _request: Request, exc: InvalidRiskWeightProfileError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidCorrelationSetError)
    async def handle_invalid_correlation_set(
        _request: Request, exc: InvalidCorrelationSetError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(UnsupportedRiskScaleError)
    async def handle_unsupported_scale(
        _request: Request, exc: UnsupportedRiskScaleError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
