"""ICredentialReferenceProvider — the extension point for validating a
`CloudCredentialReference` (M45D). Provider-agnostic: no
`platform_type` or vendor-specific shape — this framework never knows
or cares which vault backend a reference resolves against. No concrete
implementation exists in this milestone: actually checking a reference
against the Credential Vault is infrastructure, explicitly deferred.
This context never resolves the underlying secret, only asks whether
the reference is currently usable."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.cloud_credential_reference import (
        CloudCredentialReference,
    )


class ICredentialReferenceProvider(Protocol):
    def validate(self, reference: CloudCredentialReference) -> bool:
        """Return whether the referenced credential is currently valid
        and usable. Never resolves or returns the underlying secret
        material itself."""
        ...
