"""ICloudCredentialProvider — the extension point for resolving and
validating a `CloudCredentialReference` against an external credential
store (M45A). No concrete implementation exists in this milestone —
actual secret material handling is infrastructure, deferred."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )
    from cloud_security.domain.value_objects.enums import CloudPlatformType


class ICloudCredentialProvider(Protocol):
    @property
    def platform_type(self) -> CloudPlatformType: ...

    def validate(self, credential_ref: CloudCredentialReference) -> bool:
        """Return whether the referenced credential is currently valid
        and usable. Never resolves or returns the underlying secret
        material itself."""
        ...
