"""Credential vault API v1 routers."""

from fastapi import APIRouter

from credential_vault.api.v1 import audit_logs, credential_policies, credentials, vault_backends

router = APIRouter()
router.include_router(credentials.router, prefix="/credentials", tags=["credentials"])
router.include_router(
    credential_policies.router, prefix="/credential-policies", tags=["credential-policies"]
)
router.include_router(vault_backends.router, prefix="/vault-backends", tags=["vault-backends"])
router.include_router(audit_logs.router, prefix="/audit-logs", tags=["audit-logs"])
