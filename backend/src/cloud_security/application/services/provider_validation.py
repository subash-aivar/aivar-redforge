"""Validation stages for the Provider Framework (M45C). Every stage is
a pure function that either returns successfully or raises one of
`cloud_security.application.exceptions`'s typed errors — never a bare
`ValueError`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.application.exceptions import (
    EmptyBatchProviderError,
    InvalidDisplayNameError,
    InvalidProviderError,
)
from cloud_security.domain.value_objects.enums import CloudPlatformType

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.application.commands.provider_commands import RegisterProviderCommand

_SUPPORTED_PLATFORMS = {CloudPlatformType.AWS, CloudPlatformType.AZURE, CloudPlatformType.GCP}


def validate_display_name(display_name: str) -> None:
    if not display_name.strip():
        raise InvalidDisplayNameError("display_name must be a non-empty string")


def validate_platform_supported(platform_type: CloudPlatformType) -> None:
    if platform_type not in _SUPPORTED_PLATFORMS:
        raise InvalidProviderError(
            f"platform type {platform_type!r} is not a supported platform for registration"
        )


def validate_batch_not_empty(commands: Sequence[RegisterProviderCommand]) -> None:
    if not commands:
        raise EmptyBatchProviderError()
