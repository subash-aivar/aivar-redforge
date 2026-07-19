"""Port ABC contract tests."""

from __future__ import annotations

import inspect
from abc import ABC

import pytest

from credential_vault.domain.ports.i_approval_port import IApprovalPort
from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.ports.i_permission_port import IPermissionPort

PORT_CONTRACTS: list[tuple[type, list[str]]] = [
    (IEncryptionPort, ["encrypt", "decrypt"]),
    (IKeyManagementPort, ["generate_dek", "unwrap_dek", "rewrap_dek"]),
    (IPermissionPort, ["has_permission"]),
    (IApprovalPort, ["is_approved", "get_approver_count"]),
]


class TestPortContracts:
    @pytest.mark.parametrize("port_cls, methods", PORT_CONTRACTS)
    def test_cannot_instantiate_abc(self, port_cls: type, methods: list[str]) -> None:
        assert issubclass(port_cls, ABC)
        with pytest.raises(TypeError):
            port_cls()  # type: ignore[abstract]

    @pytest.mark.parametrize("port_cls, methods", PORT_CONTRACTS)
    def test_required_abstract_methods(self, port_cls: type, methods: list[str]) -> None:
        abstract_methods = {
            name
            for name, member in inspect.getmembers(port_cls)
            if getattr(member, "__isabstractmethod__", False)
        }
        assert abstract_methods == set(methods)

    def test_permission_constants(self) -> None:
        assert IPermissionPort.PERMISSION_READ == "READ"
        assert IPermissionPort.PERMISSION_BREAK_GLASS == "BREAK_GLASS"
