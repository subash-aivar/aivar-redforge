"""Tests for credential command dataclasses."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from credential_vault.application.commands.credential_commands import (
    AbortRotationCommand,
    AttachExpirationPolicyCommand,
    AttachRotationPolicyCommand,
    CommitRotationCommand,
    CreateCredentialCommand,
    DetachExpirationPolicyCommand,
    DetachRotationPolicyCommand,
    DisableCredentialCommand,
    EmergencyRevokeCommand,
    EnableCredentialCommand,
    ExpireCredentialCommand,
    HardDeleteCredentialCommand,
    RecoverCredentialCommand,
    ResolveCredentialCommand,
    RevokeCredentialCommand,
    RollbackVersionCommand,
    RotateCredentialCommand,
    UpdateCredentialMetadataCommand,
)


def test_create_credential_command_has_exactly_11_fields() -> None:
    assert len(fields(CreateCredentialCommand)) == 11


def test_create_credential_command_frozen() -> None:
    cmd = CreateCredentialCommand(
        tenant_id=uuid4(),
        name="n",
        category="API_KEY",
        subtype="GENERIC",
        schema_id=None,
        owner_principal_id=uuid4(),
        vault_backend_id=uuid4(),
        plaintext_secret=b"secret",
        description=None,
        tags={},
    )
    with pytest.raises(FrozenInstanceError):
        cmd.name = "other"  # type: ignore[misc]


def test_create_credential_command_slots() -> None:
    cmd = CreateCredentialCommand(
        tenant_id=uuid4(),
        name="n",
        category="API_KEY",
        subtype="GENERIC",
        schema_id=None,
        owner_principal_id=uuid4(),
        vault_backend_id=uuid4(),
        plaintext_secret=b"secret",
        description=None,
        tags={},
        expires_at=datetime.now(UTC),
    )
    assert not hasattr(cmd, "__dict__")
    assert CreateCredentialCommand.__slots__


@pytest.mark.parametrize(
    "cls",
    [
        ResolveCredentialCommand,
        RotateCredentialCommand,
        CommitRotationCommand,
        AbortRotationCommand,
        DisableCredentialCommand,
        EnableCredentialCommand,
        RevokeCredentialCommand,
        EmergencyRevokeCommand,
        ExpireCredentialCommand,
        RecoverCredentialCommand,
        HardDeleteCredentialCommand,
        RollbackVersionCommand,
        UpdateCredentialMetadataCommand,
        AttachRotationPolicyCommand,
        DetachRotationPolicyCommand,
        AttachExpirationPolicyCommand,
        DetachExpirationPolicyCommand,
    ],
)
def test_credential_command_classes_are_frozen_and_slotted(cls: type) -> None:
    assert cls.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert cls.__slots__
