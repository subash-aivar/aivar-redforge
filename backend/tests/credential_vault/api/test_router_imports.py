"""Minimal API router import tests."""

from __future__ import annotations


def test_credential_vault_routers_import() -> None:
    from credential_vault.api.v1 import router

    assert router.routes

    from credential_vault.api.v1 import (
        audit_logs,
        credential_policies,
        credentials,
        vault_backends,
    )

    assert credentials.router.prefix == ""
    assert credential_policies.router.prefix == ""
    assert vault_backends.router.prefix == ""
    assert audit_logs.router.prefix == ""
