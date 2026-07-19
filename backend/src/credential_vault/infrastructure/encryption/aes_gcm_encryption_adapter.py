"""AES-256-GCM encryption adapter."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from credential_vault.domain.exceptions.domain_exceptions import (
    EncryptionAuthTagFailure,
    InvalidArgument,
)
from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
from credential_vault.domain.value_objects.payloads import EncryptedPayload


class AesGcmEncryptionAdapter(IEncryptionPort):
    """AES-256-GCM encrypt/decrypt. Zeros mutable DEK buffers after use."""

    async def encrypt(self, plaintext: bytes, dek: bytes) -> EncryptedPayload:
        if len(dek) != 32:
            raise InvalidArgument("dek", "must be 32 bytes")
        iv = os.urandom(12)
        aesgcm = AESGCM(bytes(dek))
        ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        self._zero_dek(dek)
        return EncryptedPayload(
            ciphertext=ciphertext,
            algorithm="AES-256-GCM",
            iv=iv,
            tag=tag,
            payload_size=len(plaintext),
        )

    async def decrypt(self, payload: EncryptedPayload, dek: bytes) -> bytes:
        if len(dek) != 32:
            raise InvalidArgument("dek", "must be 32 bytes")
        aesgcm = AESGCM(bytes(dek))
        ciphertext_with_tag = payload.ciphertext + payload.tag
        try:
            plaintext = aesgcm.decrypt(payload.iv, ciphertext_with_tag, None)
        except InvalidTag as exc:
            self._zero_dek(dek)
            raise EncryptionAuthTagFailure() from exc
        self._zero_dek(dek)
        return plaintext

    @staticmethod
    def _zero_dek(dek: bytes) -> None:
        if isinstance(dek, bytearray):
            for i in range(len(dek)):
                dek[i] = 0
