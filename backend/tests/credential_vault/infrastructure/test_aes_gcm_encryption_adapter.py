"""Unit tests for AesGcmEncryptionAdapter."""

from __future__ import annotations

import pytest

from credential_vault.domain.exceptions.domain_exceptions import EncryptionAuthTagFailure
from credential_vault.domain.value_objects.payloads import EncryptedPayload
from credential_vault.infrastructure.encryption.aes_gcm_encryption_adapter import (
    AesGcmEncryptionAdapter,
)


@pytest.fixture
def adapter() -> AesGcmEncryptionAdapter:
    return AesGcmEncryptionAdapter()


@pytest.mark.asyncio
async def test_encrypt_decrypt_round_trip(adapter: AesGcmEncryptionAdapter) -> None:
    dek = bytearray(b"\x01" * 32)
    plaintext = b"super-secret-value"
    payload = await adapter.encrypt(plaintext, dek)
    dek2 = bytearray(b"\x01" * 32)
    recovered = await adapter.decrypt(payload, dek2)
    assert recovered == plaintext


@pytest.mark.asyncio
async def test_different_iv_per_call(adapter: AesGcmEncryptionAdapter) -> None:
    dek = bytearray(b"\x02" * 32)
    p1 = await adapter.encrypt(b"same", dek)
    dek = bytearray(b"\x02" * 32)
    p2 = await adapter.encrypt(b"same", dek)
    assert p1.iv != p2.iv


@pytest.mark.asyncio
async def test_wrong_tag_raises_auth_failure(adapter: AesGcmEncryptionAdapter) -> None:
    dek = bytearray(b"\x03" * 32)
    payload = await adapter.encrypt(b"data", dek)
    bad = EncryptedPayload(
        ciphertext=payload.ciphertext,
        algorithm=payload.algorithm,
        iv=payload.iv,
        tag=b"\x00" * 16,
        payload_size=payload.payload_size,
    )
    dek2 = bytearray(b"\x03" * 32)
    with pytest.raises(EncryptionAuthTagFailure):
        await adapter.decrypt(bad, dek2)


@pytest.mark.asyncio
async def test_dek_zeroed_after_encrypt(adapter: AesGcmEncryptionAdapter) -> None:
    dek = bytearray(b"\x04" * 32)
    await adapter.encrypt(b"x", dek)
    assert all(b == 0 for b in dek)


@pytest.mark.asyncio
async def test_dek_zeroed_after_decrypt(adapter: AesGcmEncryptionAdapter) -> None:
    dek = bytearray(b"\x05" * 32)
    payload = await adapter.encrypt(b"x", dek)
    dek2 = bytearray(b"\x05" * 32)
    await adapter.decrypt(payload, dek2)
    assert all(b == 0 for b in dek2)
