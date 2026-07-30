"""FastAPI exception handlers for attack_surface_management
domain/application errors — mirrors
`risk_engine.api.exception_handlers.register_risk_engine_exception_handlers`
convention exactly: one `@app.exception_handler` per exception type,
translating to the same HTTP status class mature contexts use (404
not-found, 403 tenant/authority violation, 422
validation/state-precondition failure)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from attack_surface_management.application.exceptions import (
    AssetNotFoundError,
    AssetTenantIsolationViolationError,
    EmptyAssetIdentifierInputError,
    InvalidPaginationError,
    NetworkRangeNotFoundError,
)
from attack_surface_management.domain.exceptions.domain_exceptions import (
    CertificateNotFoundError,
    DnsRecordNotFoundError,
    DuplicatePortError,
    EmptyAssetIdentifierError,
    EmptyIdentifierError,
    InvalidAssetLifecycleTransition,
    InvalidAssetOwnershipError,
    InvalidCertificateWindowError,
    InvalidCidrBlockError,
    InvalidCriticalityScoreError,
    InvalidDnsRecordError,
    InvalidDomainNameError,
    InvalidIpAddressError,
    InvalidNegativeCountError,
    InvalidNetworkRangeLifecycleTransition,
    InvalidPortNumberError,
    InvalidSubdomainError,
    InvalidTechnologyFingerprintError,
    PortNotFoundError,
    TenantMismatch,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_attack_surface_management_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AssetNotFoundError)
    async def handle_asset_not_found(_request: Request, exc: AssetNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(NetworkRangeNotFoundError)
    async def handle_network_range_not_found(
        _request: Request, exc: NetworkRangeNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(PortNotFoundError)
    async def handle_port_not_found(_request: Request, exc: PortNotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(CertificateNotFoundError)
    async def handle_certificate_not_found(
        _request: Request, exc: CertificateNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(DnsRecordNotFoundError)
    async def handle_dns_record_not_found(
        _request: Request, exc: DnsRecordNotFoundError
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(AssetTenantIsolationViolationError)
    async def handle_tenant_isolation(
        _request: Request, exc: AssetTenantIsolationViolationError
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(TenantMismatch)
    async def handle_domain_tenant_mismatch(_request: Request, exc: TenantMismatch) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(EmptyAssetIdentifierInputError)
    async def handle_empty_identifier_input(
        _request: Request, exc: EmptyAssetIdentifierInputError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidPaginationError)
    async def handle_invalid_pagination(
        _request: Request, exc: InvalidPaginationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyAssetIdentifierError)
    async def handle_empty_asset_identifier(
        _request: Request, exc: EmptyAssetIdentifierError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmptyIdentifierError)
    async def handle_empty_identifier(_request: Request, exc: EmptyIdentifierError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidDomainNameError)
    async def handle_invalid_domain_name(
        _request: Request, exc: InvalidDomainNameError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidSubdomainError)
    async def handle_invalid_subdomain(
        _request: Request, exc: InvalidSubdomainError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidIpAddressError)
    async def handle_invalid_ip_address(
        _request: Request, exc: InvalidIpAddressError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidCidrBlockError)
    async def handle_invalid_cidr_block(
        _request: Request, exc: InvalidCidrBlockError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidPortNumberError)
    async def handle_invalid_port_number(
        _request: Request, exc: InvalidPortNumberError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidCertificateWindowError)
    async def handle_invalid_certificate_window(
        _request: Request, exc: InvalidCertificateWindowError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidDnsRecordError)
    async def handle_invalid_dns_record(
        _request: Request, exc: InvalidDnsRecordError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidTechnologyFingerprintError)
    async def handle_invalid_technology_fingerprint(
        _request: Request, exc: InvalidTechnologyFingerprintError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidAssetOwnershipError)
    async def handle_invalid_asset_ownership(
        _request: Request, exc: InvalidAssetOwnershipError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidCriticalityScoreError)
    async def handle_invalid_criticality_score(
        _request: Request, exc: InvalidCriticalityScoreError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidAssetLifecycleTransition)
    async def handle_invalid_asset_lifecycle_transition(
        _request: Request, exc: InvalidAssetLifecycleTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidNetworkRangeLifecycleTransition)
    async def handle_invalid_network_range_lifecycle_transition(
        _request: Request, exc: InvalidNetworkRangeLifecycleTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(DuplicatePortError)
    async def handle_duplicate_port(_request: Request, exc: DuplicatePortError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(InvalidNegativeCountError)
    async def handle_invalid_negative_count(
        _request: Request, exc: InvalidNegativeCountError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
