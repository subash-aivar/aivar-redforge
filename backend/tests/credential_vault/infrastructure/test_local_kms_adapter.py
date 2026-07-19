"""Unit tests for LocalAesKwKmsAdapter."""

from __future__ import annotations

import pytest

from credential_vault.domain.exceptions.domain_exceptions import KmsKeyNotFound
from credential_vault.domain.value_objects.payloads import KeyEnvelope
from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter


@pytest.fixture
def adapter() -> LocalAesKwKmsAdapter:
    return LocalAesKwKmsAdapter(master_key=b"\xab" * 32, master_key_id="test-master")


@pytest.mark.asyncio
async def test_generate_and_unwrap_round_trip(adapter: LocalAesKwKmsAdapter) -> None:
    dek, envelope = await adapter.generate_dek()
    unwrapped = await adapter.unwrap_dek(envelope)
    assert bytes(unwrapped) == dek


@pytest.mark.asyncio
async def test_unwrap_wrong_key_id_raises(adapter: LocalAesKwKmsAdapter) -> None:
    _, envelope = await adapter.generate_dek()
    bad = KeyEnvelope(
        wrapped_dek=envelope.wrapped_dek,
        master_key_id="wrong-key",
        wrapping_algorithm=envelope.wrapping_algorithm,
        created_at=envelope.created_at,
    )
    with pytest.raises(KmsKeyNotFound):
        await adapter.unwrap_dek(bad)


@pytest.mark.asyncio
async def test_dek_bytes_are_32(adapter: LocalAesKwKmsAdapter) -> None:
    dek, _ = await adapter.generate_dek()
    assert len(dek) == 32
