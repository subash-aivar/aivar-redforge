"""Tests for policy and backend command dataclasses."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from credential_vault.application.commands.backend_commands import (
    DeleteVaultBackendCommand,
    RegisterVaultBackendCommand,
)
from credential_vault.application.commands.policy_commands import (
    CreateExpirationPolicyCommand,
    CreateRotationPolicyCommand,
    DeleteExpirationPolicyCommand,
    DeleteRotationPolicyCommand,
    UpdateExpirationPolicyCommand,
    UpdateRotationPolicyCommand,
)
from redforge.shared.identifiers import EntityId


def test_create_rotation_policy_command_frozen() -> None:
    cmd = CreateRotationPolicyCommand(
        tenant_id=EntityId.generate(),
        principal_id=uuid4(),
        name="p",
        interval_days=30,
        max_versions_kept=5,
        notify_days_before=7,
        auto_rotate=True,
    )
    with pytest.raises(FrozenInstanceError):
        cmd.name = "x"  # type: ignore[misc]
    assert not hasattr(cmd, "__dict__")


def test_register_vault_backend_command_constructs() -> None:
    cmd = RegisterVaultBackendCommand(
        tenant_id=EntityId.generate(),
        principal_id=uuid4(),
        name="b",
        backend_type="LOCAL_ENCRYPTED",
        config={"k": "v"},
        is_default=True,
    )
    assert cmd.is_default is True
    assert cmd.__dataclass_params__.frozen  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "cls",
    [
        CreateRotationPolicyCommand,
        UpdateRotationPolicyCommand,
        DeleteRotationPolicyCommand,
        CreateExpirationPolicyCommand,
        UpdateExpirationPolicyCommand,
        DeleteExpirationPolicyCommand,
        RegisterVaultBackendCommand,
        DeleteVaultBackendCommand,
    ],
)
def test_policy_and_backend_commands_frozen_slotted(cls: type) -> None:
    assert cls.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert cls.__slots__
