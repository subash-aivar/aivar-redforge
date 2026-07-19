"""CredentialVersion entity belonging to the Credential aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import InvalidStateTransition
from credential_vault.domain.value_objects.states import VersionState

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
        VersionId,
    )
    from credential_vault.domain.value_objects.payloads import EncryptedPayload, KeyEnvelope
    from credential_vault.domain.value_objects.rotation_context import RotationContext


class CredentialVersion:
    """
    Belongs to Credential aggregate. Not independently loadable without credential context.
    Created by application service, owned by Credential via active_version_id pointer.
    """

    __slots__ = (
        "created_at",
        "created_by",
        "credential_id",
        "encrypted_payload",
        "expires_at",
        "key_envelope",
        "rotation_context",
        "tenant_id",
        "version_id",
        "version_number",
        "version_state",
    )

    def __init__(
        self,
        version_id: VersionId,
        credential_id: CredentialId,
        tenant_id: TenantId,
        version_number: int,
        encrypted_payload: EncryptedPayload,
        key_envelope: KeyEnvelope,
        version_state: VersionState,
        rotation_context: RotationContext | None,
        created_at: datetime,
        created_by: PrincipalId,
        expires_at: datetime | None,
    ) -> None:
        if version_number < 1:
            raise ValueError("version_number must be >= 1")
        self.version_id = version_id
        self.credential_id = credential_id
        self.tenant_id = tenant_id
        self.version_number = version_number
        self.encrypted_payload = encrypted_payload
        self.key_envelope = key_envelope
        self.version_state = version_state
        self.rotation_context = rotation_context
        self.created_at = created_at
        self.created_by = created_by
        self.expires_at = expires_at

    def promote(self) -> None:
        """Transition PENDING → ACTIVE."""
        if self.version_state != VersionState.PENDING:
            raise InvalidStateTransition(
                current=self.version_state.value,
                attempted="promote",
                credential_id=self.credential_id,
            )
        self.version_state = VersionState.ACTIVE

    def supersede(self) -> None:
        """Transition ACTIVE → SUPERSEDED."""
        if self.version_state != VersionState.ACTIVE:
            raise InvalidStateTransition(
                current=self.version_state.value,
                attempted="supersede",
                credential_id=self.credential_id,
            )
        self.version_state = VersionState.SUPERSEDED

    def revoke(self) -> None:
        """Transition any non-REVOKED state → REVOKED."""
        if self.version_state == VersionState.REVOKED:
            raise InvalidStateTransition(
                current=self.version_state.value,
                attempted="revoke",
                credential_id=self.credential_id,
            )
        self.version_state = VersionState.REVOKED

    def rewrap_key(self, new_envelope: KeyEnvelope) -> None:
        """Replace key_envelope after master key rotation."""
        if self.version_state == VersionState.REVOKED:
            raise InvalidStateTransition(
                current=self.version_state.value,
                attempted="rewrap_key",
                credential_id=self.credential_id,
            )
        self.key_envelope = new_envelope

    def is_resolvable(self) -> bool:
        """True iff version can be decrypted and returned."""
        return self.version_state == VersionState.ACTIVE
