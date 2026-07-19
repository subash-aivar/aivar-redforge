"""Tests for VaultBackend aggregate."""

from __future__ import annotations

import pytest

from credential_vault.domain.aggregates.vault_backend import VaultBackend
from credential_vault.domain.events.backend_events import (
    VaultBackendDeleted,
    VaultBackendRegistered,
)
from credential_vault.domain.exceptions.domain_exceptions import InvalidArgument, TenantMismatch
from credential_vault.domain.value_objects.audit_types import VaultBackendType


class TestVaultBackend:
    def test_create(self, vault_backend_id, tenant_id, now) -> None:
        backend = VaultBackend.create(
            backend_id=vault_backend_id,
            tenant_id=tenant_id,
            name="  primary  ",
            backend_type=VaultBackendType.LOCAL_ENCRYPTED,
            config={"region": "us-east-1"},
            is_default=True,
            now=now,
        )
        assert backend.name == "primary"
        events = backend.pop_events()
        assert isinstance(events[0], VaultBackendRegistered)

    def test_delete(self, vault_backend_id, tenant_id, now, principal_id) -> None:
        backend = VaultBackend.create(
            backend_id=vault_backend_id,
            tenant_id=tenant_id,
            name="primary",
            backend_type=VaultBackendType.LOCAL_ENCRYPTED,
            config={},
            is_default=False,
            now=now,
        )
        backend.pop_events()
        backend.delete(tenant_id, principal_id, now)
        events = backend.pop_events()
        assert isinstance(events[0], VaultBackendDeleted)

    def test_config_too_many_keys(self, vault_backend_id, tenant_id, now) -> None:
        config = {f"k{i}": "v" for i in range(101)}
        with pytest.raises(InvalidArgument, match="max 100 keys"):
            VaultBackend.create(
                backend_id=vault_backend_id,
                tenant_id=tenant_id,
                name="primary",
                backend_type=VaultBackendType.LOCAL_ENCRYPTED,
                config=config,
                is_default=False,
                now=now,
            )

    def test_tenant_mismatch(
        self, vault_backend_id, tenant_id, other_tenant_id, now, principal_id
    ) -> None:
        backend = VaultBackend.create(
            backend_id=vault_backend_id,
            tenant_id=tenant_id,
            name="primary",
            backend_type=VaultBackendType.LOCAL_ENCRYPTED,
            config={},
            is_default=False,
            now=now,
        )
        with pytest.raises(TenantMismatch):
            backend.delete(other_tenant_id, principal_id, now)
