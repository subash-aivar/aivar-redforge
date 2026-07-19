"""Repository ABC contract tests."""

from __future__ import annotations

import inspect
from abc import ABC

import pytest

from credential_vault.domain.repositories.i_audit_log_repository import IAuditLogRepository
from credential_vault.domain.repositories.i_credential_repository import ICredentialRepository
from credential_vault.domain.repositories.i_credential_version_repository import (
    ICredentialVersionRepository,
)
from credential_vault.domain.repositories.i_expiration_policy_repository import (
    IExpirationPolicyRepository,
)
from credential_vault.domain.repositories.i_rotation_policy_repository import (
    IRotationPolicyRepository,
)
from credential_vault.domain.repositories.i_vault_backend_repository import (
    IVaultBackendRepository,
)

REPOSITORY_CONTRACTS: list[tuple[type, list[str]]] = [
    (
        ICredentialRepository,
        [
            "save",
            "get_by_id",
            "get_by_name",
            "exists_by_name",
            "list_by_tenant",
            "list_with_rotation_policy",
            "list_with_expiration_policy",
            "list_with_vault_backend",
            "list_with_active_rotation_policy",
        ],
    ),
    (
        ICredentialVersionRepository,
        [
            "save",
            "get_by_id",
            "get_active_version",
            "list_by_credential",
            "atomic_promote",
            "update",
            "count_superseded",
        ],
    ),
    (
        IRotationPolicyRepository,
        ["save", "get_by_id", "delete", "list_by_tenant"],
    ),
    (
        IExpirationPolicyRepository,
        ["save", "get_by_id", "delete", "list_by_tenant"],
    ),
    (
        IVaultBackendRepository,
        ["save", "get_by_id", "get_default", "delete", "list_by_tenant"],
    ),
    (
        IAuditLogRepository,
        ["save", "get_by_credential", "append_entry", "list_entries"],
    ),
]


class TestRepositoryContracts:
    @pytest.mark.parametrize("repo_cls, methods", REPOSITORY_CONTRACTS)
    def test_cannot_instantiate_abc(self, repo_cls: type, methods: list[str]) -> None:
        assert issubclass(repo_cls, ABC)
        with pytest.raises(TypeError):
            repo_cls()  # type: ignore[abstract]

    @pytest.mark.parametrize("repo_cls, methods", REPOSITORY_CONTRACTS)
    def test_required_abstract_methods(self, repo_cls: type, methods: list[str]) -> None:
        abstract_methods = {
            name
            for name, member in inspect.getmembers(repo_cls)
            if getattr(member, "__isabstractmethod__", False)
        }
        assert abstract_methods == set(methods)
