"""IKeyManagementPort — DEK lifecycle via external KMS/HSM."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.payloads import KeyEnvelope


class IKeyManagementPort(ABC):
    """
    Manages DEK lifecycle using an external KMS/HSM.
    Domain never sees plaintext DEKs except transiently during resolve/encrypt.
    """

    @abstractmethod
    async def generate_dek(self) -> tuple[bytes, KeyEnvelope]:
        """Generate a new DEK and wrap it. Caller must zero plaintext_dek after use."""

    @abstractmethod
    async def unwrap_dek(self, envelope: KeyEnvelope) -> bytes:
        """Unwrap DEK. Caller must zero after use."""

    @abstractmethod
    async def rewrap_dek(
        self, old_envelope: KeyEnvelope, new_master_key_id: str
    ) -> KeyEnvelope:
        """Re-encrypt DEK under new_master_key_id. Old DEK bytes zeroed internally."""
