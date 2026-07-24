"""Validation stages for Credential Integration (M45D). Every stage is
a pure function that either returns successfully or raises one of
`cloud_security.application.exceptions`'s typed errors — never a bare
`ValueError`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    AccountMismatchError,
    EmptyBatchCredentialError,
    ProviderMismatchError,
)
from cloud_security.domain.value_objects.identifiers import AccountId, ProviderId

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.commands.credential_commands import AttachCredentialCommand


def validate_account_reference(account_id: object) -> None:
    if not isinstance(account_id, AccountId):
        raise AccountMismatchError("account_id must be a valid AccountId")


def validate_provider_reference(provider_id: object) -> None:
    if not isinstance(provider_id, ProviderId):
        raise ProviderMismatchError("provider_id must be a valid ProviderId")


def validate_batch_not_empty(commands: Sequence[AttachCredentialCommand]) -> None:
    if not commands:
        raise EmptyBatchCredentialError()
