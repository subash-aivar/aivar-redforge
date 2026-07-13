"""TOTP secret at-rest encryption.

Uses `cryptography`'s Fernet (AES-128-CBC + HMAC-SHA256, authenticated
symmetric encryption) — a mature, audited primitive, not a hand-rolled
scheme. The key comes from server configuration
(`Settings.mfa_encryption_key`), never from a per-user or derived value,
and is never persisted alongside the ciphertext it protects.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class TOTPSecretCipher:
    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode())

    def encrypt(self, plaintext_secret: str) -> str:
        return self._fernet.encrypt(plaintext_secret.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("MFA secret ciphertext could not be decrypted") from exc
