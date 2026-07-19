"""Tests for EncryptedPayload, KeyEnvelope, and ResolvedSecret."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from credential_vault.domain.exceptions.domain_exceptions import ResolvedSecretZeroized
from credential_vault.domain.value_objects.identifiers import CredentialId, VersionId
from credential_vault.domain.value_objects.payloads import (
    EncryptedPayload,
    KeyEnvelope,
    ResolvedSecret,
)


class TestEncryptedPayload:
    def test_valid_payload(self) -> None:
        payload = EncryptedPayload(
            ciphertext=b"data",
            algorithm="AES-256-GCM",
            iv=b"0123456789abcdef",
            tag=b"0123456789abcdef",
            payload_size=4,
        )
        assert payload.payload_size == 4

    def test_empty_ciphertext_rejected(self) -> None:
        with pytest.raises(ValueError, match="ciphertext empty"):
            EncryptedPayload(
                ciphertext=b"",
                algorithm="AES-256-GCM",
                iv=b"0123456789abcdef",
                tag=b"0123456789abcdef",
                payload_size=1,
            )


class TestKeyEnvelope:
    def test_valid_envelope(self) -> None:
        env = KeyEnvelope(
            wrapped_dek=b"wrapped",
            master_key_id="mk-1",
            wrapping_algorithm="RSA-OAEP",
            created_at=datetime.now(UTC),
        )
        assert env.master_key_id == "mk-1"

    def test_empty_wrapped_dek_rejected(self) -> None:
        with pytest.raises(ValueError, match="wrapped_dek empty"):
            KeyEnvelope(
                wrapped_dek=b"",
                master_key_id="mk-1",
                wrapping_algorithm="RSA-OAEP",
                created_at=datetime.now(UTC),
            )


class TestResolvedSecret:
    def test_get_plaintext(self) -> None:
        secret = ResolvedSecret(
            plaintext=b"secret-value",
            credential_id=CredentialId(uuid4()),
            version_id=VersionId(uuid4()),
            resolved_at=datetime.now(UTC),
        )
        assert secret.get_plaintext() == b"secret-value"

    def test_zero_prevents_get_plaintext(self) -> None:
        secret = ResolvedSecret(
            plaintext=b"secret-value",
            credential_id=CredentialId(uuid4()),
            version_id=VersionId(uuid4()),
            resolved_at=datetime.now(UTC),
        )
        secret.zero()
        with pytest.raises(ResolvedSecretZeroized):
            secret.get_plaintext()

    def test_repr_redacted(self) -> None:
        secret = ResolvedSecret(
            plaintext=b"secret-value",
            credential_id=CredentialId(uuid4()),
            version_id=VersionId(uuid4()),
            resolved_at=datetime.now(UTC),
        )
        assert "REDACTED" in repr(secret)
