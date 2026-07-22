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
    """AES-KW-256 local KMS. Master key from CREDENTIAL_VAULT_LOCAL_MASTER_KEY.

    Supports rewrapping to a *different* local master key id when one is
    registered via ``other_keys`` (or the matching
    ``CREDENTIAL_VAULT_LOCAL_MASTER_KEY_<ID>`` env var through
    :meth:`from_env`) — e.g. for key-rotation drills against the local
    adapter without needing a cloud KMS.
    """

    def __init__(
        self,
        master_key: bytes,
        master_key_id: str,
        other_keys: dict[str, bytes] | None = None,
    ) -> None:
        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes")
        self._master_key_id = master_key_id
        self._keys: dict[str, bytes] = {master_key_id: master_key}
        for key_id, key in (other_keys or {}).items():
            if len(key) != 32:
                raise ValueError(f"master_key for {key_id!r} must be 32 bytes")
            self._keys[key_id] = key

    @property
    def _master_key(self) -> bytes:
        return self._keys[self._master_key_id]

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

        prefix = "CREDENTIAL_VAULT_LOCAL_MASTER_KEY_"
        other_keys: dict[str, bytes] = {}
        for env_name, env_value in os.environ.items():
            if not env_name.startswith(prefix) or env_name == prefix + "ID":
                continue
            other_key_id = env_name[len(prefix) :]
            other_keys[other_key_id] = base64.b64decode(env_value)

        return cls(master_key=master_key, master_key_id=key_id, other_keys=other_keys)

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
        wrapping_key = self._keys.get(envelope.master_key_id)
        if wrapping_key is None:
            raise KmsKeyNotFound(envelope.master_key_id)
        dek = aes_key_unwrap(
            wrapping_key=wrapping_key,
            wrapped_key=envelope.wrapped_dek,
            backend=default_backend(),
        )
        return bytearray(dek)  # type: ignore[return-value]

    async def rewrap_dek(self, old_envelope: KeyEnvelope, new_master_key_id: str) -> KeyEnvelope:
        new_key = self._keys.get(new_master_key_id)
        if new_key is None:
            raise KmsKeyNotFound(new_master_key_id)
        dek = await self.unwrap_dek(old_envelope)
        try:
            wrapped = aes_key_wrap(
                wrapping_key=new_key,
                key_to_wrap=bytes(dek),
                backend=default_backend(),
            )
        finally:
            for i in range(len(dek)):
                dek[i] = 0
        return KeyEnvelope(
            wrapped_dek=wrapped,
            master_key_id=new_master_key_id,
            wrapping_algorithm="AES-KW-256",
            created_at=datetime.now(UTC),
        )
