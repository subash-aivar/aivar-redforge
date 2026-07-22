"""Unit tests for the credential_vault KMS provider factory."""

from __future__ import annotations

import pytest

from credential_vault.infrastructure.encryption.kms_factory import (
    KmsConfigurationError,
    build_kms_adapter,
)
from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter
from credential_vault.infrastructure.kms.aws_kms_adapter import AwsKmsAdapter


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "CREDENTIAL_VAULT_KMS_PROVIDER",
        "REDFORGE_ENVIRONMENT",
        "CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION",
        "CREDENTIAL_VAULT_AWS_KMS_KEY_ARN",
        "CREDENTIAL_VAULT_AWS_REGION",
    ):
        monkeypatch.delenv(name, raising=False)


def test_defaults_to_local_adapter_outside_production() -> None:
    adapter = build_kms_adapter()
    assert isinstance(adapter, LocalAesKwKmsAdapter)


def test_local_adapter_refused_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDFORGE_ENVIRONMENT", "production")
    with pytest.raises(KmsConfigurationError, match="production"):
        build_kms_adapter()


def test_local_adapter_allowed_in_production_with_explicit_opt_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REDFORGE_ENVIRONMENT", "production")
    monkeypatch.setenv("CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION", "true")
    adapter = build_kms_adapter()
    assert isinstance(adapter, LocalAesKwKmsAdapter)


def test_aws_provider_requires_key_arn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_VAULT_KMS_PROVIDER", "aws")
    with pytest.raises(KmsConfigurationError, match="CREDENTIAL_VAULT_AWS_KMS_KEY_ARN"):
        build_kms_adapter()


def test_aws_provider_builds_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_VAULT_KMS_PROVIDER", "aws")
    monkeypatch.setenv("CREDENTIAL_VAULT_AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:1:key/abc")
    monkeypatch.setenv("CREDENTIAL_VAULT_AWS_REGION", "us-east-1")
    adapter = build_kms_adapter()
    assert isinstance(adapter, AwsKmsAdapter)


def test_unknown_provider_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CREDENTIAL_VAULT_KMS_PROVIDER", "azure")
    with pytest.raises(KmsConfigurationError, match="unknown"):
        build_kms_adapter()
