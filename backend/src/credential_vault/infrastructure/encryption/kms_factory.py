"""Select the KMS adapter for credential_vault from environment configuration.

LocalAesKwKmsAdapter wraps DEKs with a key that either comes from
CREDENTIAL_VAULT_LOCAL_MASTER_KEY or, if that's unset, a hardcoded
deterministic dev key. That is the right default for local development and
tests, and the wrong one for any environment that stores real secrets — a
misconfigured production deployment would otherwise wrap every credential
under a key that ships in the source tree.

This factory makes the choice explicit and env-driven:
- CREDENTIAL_VAULT_KMS_PROVIDER=aws builds an AwsKmsAdapter against
  CREDENTIAL_VAULT_AWS_KMS_KEY_ARN.
- CREDENTIAL_VAULT_KMS_PROVIDER unset/"local" uses LocalAesKwKmsAdapter,
  unless REDFORGE_ENVIRONMENT=production, in which case it fails fast rather
  than silently persisting secrets under the dev key. Set
  CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION=true to opt out of this
  guard for deployments that genuinely intend to run the local adapter in
  production (e.g. an on-prem HSM-backed master key supplied via
  CREDENTIAL_VAULT_LOCAL_MASTER_KEY rather than AWS KMS).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter

if TYPE_CHECKING:
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort


class KmsConfigurationError(RuntimeError):
    """Raised when the configured KMS provider cannot be constructed safely."""


def build_kms_adapter() -> IKeyManagementPort:
    provider = os.environ.get("CREDENTIAL_VAULT_KMS_PROVIDER", "local").strip().lower()

    if provider == "aws":
        return _build_aws_kms_adapter()

    if provider != "local":
        raise KmsConfigurationError(
            f"unknown CREDENTIAL_VAULT_KMS_PROVIDER={provider!r} (expected 'local' or 'aws')"
        )

    environment = os.environ.get("REDFORGE_ENVIRONMENT", "development")
    allow_local_in_prod = (
        os.environ.get("CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION", "false").strip().lower()
        == "true"
    )
    if environment == "production" and not allow_local_in_prod:
        raise KmsConfigurationError(
            "credential_vault is configured to use the local KMS adapter in a "
            "production environment (REDFORGE_ENVIRONMENT=production). Set "
            "CREDENTIAL_VAULT_KMS_PROVIDER=aws (with CREDENTIAL_VAULT_AWS_KMS_KEY_ARN), "
            "or explicitly set CREDENTIAL_VAULT_ALLOW_LOCAL_KMS_IN_PRODUCTION=true "
            "if this deployment intentionally supplies its own "
            "CREDENTIAL_VAULT_LOCAL_MASTER_KEY."
        )
    return LocalAesKwKmsAdapter.from_env()


def _build_aws_kms_adapter() -> IKeyManagementPort:
    from credential_vault.infrastructure.kms.aws_kms_adapter import AwsKmsAdapter

    key_arn = os.environ.get("CREDENTIAL_VAULT_AWS_KMS_KEY_ARN")
    if not key_arn:
        raise KmsConfigurationError(
            "CREDENTIAL_VAULT_KMS_PROVIDER=aws requires CREDENTIAL_VAULT_AWS_KMS_KEY_ARN"
        )

    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - boto3 is a declared dependency
        raise KmsConfigurationError(
            "boto3 is required for CREDENTIAL_VAULT_KMS_PROVIDER=aws"
        ) from exc

    region = (
        os.environ.get("CREDENTIAL_VAULT_AWS_REGION")
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
    )
    kms_client = boto3.client("kms", region_name=region) if region else boto3.client("kms")
    return AwsKmsAdapter(kms_client=kms_client, master_key_arn=key_arn)
