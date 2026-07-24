"""Validation stages for Resource Discovery (M45E). Every stage is a
pure function that either returns successfully or raises one of
`cloud_security.application.exceptions`'s typed errors — never a bare
`ValueError`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    AccountMismatchError,
    EmptyBatchDiscoveryError,
    MissingDiscoveryCapabilityError,
    ProviderMismatchError,
    ProviderNotEnabledError,
)
from cloud_security.domain.value_objects.enums import ProviderCapability, ProviderStatus

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.commands.discovery_commands import StartDiscoveryCommand
    from cloud_security.domain.aggregates.cloud_account import CloudAccount
    from cloud_security.domain.aggregates.cloud_provider_registration import (
        CloudProviderRegistration,
    )


def validate_account_matches(account: CloudAccount, account_id: object) -> None:
    if account.account_id != account_id:
        raise AccountMismatchError("command.account_id does not match the given account")


def validate_provider_matches(provider: CloudProviderRegistration, provider_id: object) -> None:
    if provider.provider_id != provider_id:
        raise ProviderMismatchError("command.provider_id does not match the given provider")


def validate_provider_enabled(provider: CloudProviderRegistration) -> None:
    if provider.status != ProviderStatus.ENABLED:
        raise ProviderNotEnabledError(provider.provider_id)


def validate_provider_has_discovery_capability(provider: CloudProviderRegistration) -> None:
    if ProviderCapability.DISCOVERY not in provider.capabilities:
        raise MissingDiscoveryCapabilityError(provider.provider_id)


def validate_batch_not_empty(commands: Sequence[StartDiscoveryCommand]) -> None:
    if not commands:
        raise EmptyBatchDiscoveryError()
