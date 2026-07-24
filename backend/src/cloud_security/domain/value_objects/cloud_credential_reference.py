"""CloudCredentialReference — a pointer to externally-managed
credential material (M45A).

This domain layer never holds actual secret material — only a
reference (an id + a type tag) that an infrastructure-layer credential
store resolves later. Deferred to a future infrastructure milestone;
see `ICloudCredentialProvider`."""

from __future__ import annotations

from dataclasses import dataclass

from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class CloudCredentialReference:
    credential_id: str
    credential_type: str

    def __post_init__(self) -> None:
        if not self.credential_id.strip():
            raise EmptyIdentifierError("CloudCredentialReference.credential_id")
        if not self.credential_type.strip():
            raise EmptyIdentifierError("CloudCredentialReference.credential_type")
