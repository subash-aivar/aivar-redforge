"""Validation stages for the Security Baseline / CSPM Foundation
(M45F). Every stage is a pure function that either returns
successfully or raises one of `cloud_security.application.exceptions`'s
typed errors — never a bare `ValueError`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    AccountMismatchError,
    AssetNotActiveError,
    EmptyBatchBaselineError,
    MissingBaselineCapabilityError,
    ProviderNotEnabledError,
)
from cloud_security.domain.value_objects.enums import (
    CloudAssetLifecycleState,
    ProviderCapability,
    ProviderStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.commands.baseline_commands import EvaluateAccountCommand
    from cloud_security.domain.aggregates.cloud_account import CloudAccount
    from cloud_security.domain.aggregates.cloud_asset import CloudAsset
    from cloud_security.domain.aggregates.cloud_provider_registration import (
        CloudProviderRegistration,
    )


def validate_account_matches(account: CloudAccount, account_id: object) -> None:
    if account.account_id != account_id:
        raise AccountMismatchError("command.account_id does not match the given account")


def validate_provider_enabled(provider: CloudProviderRegistration) -> None:
    if provider.status != ProviderStatus.ENABLED:
        raise ProviderNotEnabledError(provider.provider_id)


def validate_provider_has_baseline_capability(provider: CloudProviderRegistration) -> None:
    if ProviderCapability.SECURITY_BASELINE not in provider.capabilities:
        raise MissingBaselineCapabilityError(provider.provider_id)


def validate_asset_active(asset: CloudAsset) -> None:
    if asset.lifecycle_state != CloudAssetLifecycleState.ACTIVE:
        raise AssetNotActiveError(asset.asset_id)


def validate_batch_not_empty(commands: Sequence[EvaluateAccountCommand]) -> None:
    if not commands:
        raise EmptyBatchBaselineError()
