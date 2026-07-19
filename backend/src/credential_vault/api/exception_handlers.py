"""FastAPI exception handlers for credential vault domain/application errors."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from credential_vault.application.exceptions import (
    ApplicationAuditFailure,
    ApplicationPortError,
    ApplicationValidationError,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    AccessDenied,
    ActiveVersionNotFound,
    BreakGlassJustificationRequired,
    ConcurrentRotationConflict,
    CredentialAlreadyExists,
    CredentialIsDeleted,
    CredentialIsExpired,
    CredentialIsRevoked,
    CredentialNotFound,
    DuplicatePolicyName,
    InsufficientApprovers,
    InvalidStateTransition,
    NoPolicyAttached,
    OptimisticLockConflict,
    PolicyInUse,
    PolicyNotFound,
    ResolvedSecretZeroized,
    VaultBackendInUse,
    VaultBackendNotFound,
    VersionNotFound,
)

if TYPE_CHECKING:
    from fastapi import FastAPI, Request


def register_credential_vault_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(CredentialNotFound)
    async def handle_credential_not_found(
        _request: Request, exc: CredentialNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(VersionNotFound)
    async def handle_version_not_found(_request: Request, exc: VersionNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(ActiveVersionNotFound)
    async def handle_active_version_not_found(
        _request: Request, exc: ActiveVersionNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(PolicyNotFound)
    async def handle_policy_not_found(_request: Request, exc: PolicyNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(VaultBackendNotFound)
    async def handle_backend_not_found(
        _request: Request, exc: VaultBackendNotFound
    ) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(CredentialAlreadyExists)
    async def handle_already_exists(
        _request: Request, exc: CredentialAlreadyExists
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(DuplicatePolicyName)
    async def handle_duplicate_policy(_request: Request, exc: DuplicatePolicyName) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ConcurrentRotationConflict)
    async def handle_rotation_conflict(
        _request: Request, exc: ConcurrentRotationConflict
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(OptimisticLockConflict)
    async def handle_lock_conflict(_request: Request, exc: OptimisticLockConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(AccessDenied)
    async def handle_access_denied(_request: Request, exc: AccessDenied) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(InsufficientApprovers)
    async def handle_insufficient_approvers(
        _request: Request, exc: InsufficientApprovers
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(BreakGlassJustificationRequired)
    async def handle_break_glass(
        _request: Request, exc: BreakGlassJustificationRequired
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(InvalidStateTransition)
    async def handle_invalid_transition(
        _request: Request, exc: InvalidStateTransition
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(NoPolicyAttached)
    async def handle_no_policy(_request: Request, exc: NoPolicyAttached) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(PolicyInUse)
    async def handle_policy_in_use(_request: Request, exc: PolicyInUse) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(VaultBackendInUse)
    async def handle_backend_in_use(_request: Request, exc: VaultBackendInUse) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(CredentialIsRevoked)
    async def handle_revoked(_request: Request, exc: CredentialIsRevoked) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(CredentialIsExpired)
    async def handle_expired(_request: Request, exc: CredentialIsExpired) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(ApplicationValidationError)
    async def handle_validation_error(
        _request: Request, exc: ApplicationValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(CredentialIsDeleted)
    async def handle_deleted(_request: Request, exc: CredentialIsDeleted) -> JSONResponse:
        return JSONResponse(status_code=410, content={"detail": str(exc)})

    @app.exception_handler(ApplicationAuditFailure)
    async def handle_audit_failure(_request: Request, exc: ApplicationAuditFailure) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(ResolvedSecretZeroized)
    async def handle_zeroized(_request: Request, exc: ResolvedSecretZeroized) -> JSONResponse:
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(ApplicationPortError)
    async def handle_port_error(_request: Request, exc: ApplicationPortError) -> JSONResponse:
        return JSONResponse(status_code=502, content={"detail": str(exc)})
