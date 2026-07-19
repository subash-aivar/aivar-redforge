"""Local AES key-wrap KMS adapter for development/test."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from credential_vault.domain.exceptions.domain_exceptions import KmsKeyNotFound
from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
from credential_vault.domain.value_objects.payloads import KeyEnvelope


class LocalAesKwKmsAdapter(IKeyManagementPort):
    """AES-KW-256 local KMS. Master key from CREDENTIAL_VAULT_LOCAL_MASTER_KEY."""

    def __init__(self, master_key: bytes, master_key_id: str) -> None:
        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes")
        self._master_key = master_key
        self._master_key_id = master_key_id

    @classmethod
    def from_env(cls) -> LocalAesKwKmsAdapter:
        import base64

        raw = os.environ.get("CREDENTIAL_VAULT_LOCAL_MASTER_KEY")
        if not raw:
            # Deterministic test/dev key — not for production.
            raw_b64 = base64.b64encode(b"\x11" * 32).decode()
            os.environ.setdefault("CREDENTIAL_VAULT_LOCAL_MASTER_KEY", raw_b64)
            raw = raw_b64
        master_key = base64.b64decode(raw)
        key_id = os.environ.get("CREDENTIAL_VAULT_LOCAL_MASTER_KEY_ID", "local-master-v1")
        return cls(master_key=master_key, master_key_id=key_id)

    async def generate_dek(self) -> tuple[bytes, KeyEnvelope]:
        dek = bytearray(os.urandom(32))
        wrapped = aes_key_wrap(
            wrapping_key=self._master_key,
            key_to_wrap=bytes(dek),
            backend=default_backend(),
        )
        envelope = KeyEnvelope(
            wrapped_dek=wrapped,
            master_key_id=self._master_key_id,
            wrapping_algorithm="AES-KW-256",
            created_at=datetime.now(UTC),
        )
        plaintext = bytes(dek)
        for i in range(len(dek)):
            dek[i] = 0
        return plaintext, envelope

    async def unwrap_dek(self, envelope: KeyEnvelope) -> bytes:
        if envelope.master_key_id != self._master_key_id:
            raise KmsKeyNotFound(envelope.master_key_id)
        dek = aes_key_unwrap(
            wrapping_key=self._master_key,
            wrapped_key=envelope.wrapped_dek,
            backend=default_backend(),
        )
        return bytearray(dek)  # type: ignore[return-value]

    async def rewrap_dek(self, old_envelope: KeyEnvelope, new_master_key_id: str) -> KeyEnvelope:
        raise NotImplementedError("rewrap not supported in LocalAesKwKmsAdapter")
