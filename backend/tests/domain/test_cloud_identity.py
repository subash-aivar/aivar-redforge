import pytest

from redforge.domain.inventory.identity import (
    IdentityNormalizationError,
    IdentityScheme,
    build_external_id,
)


def test_aws_account_id_canonical_form() -> None:
    ext = build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "AWS:123456789012")
    assert ext == "cloud_account_id:aws:123456789012"


def test_provider_lowercased_account_id_preserved() -> None:
    ext = build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "gcp:My-Project-ID")
    assert ext == "cloud_account_id:gcp:My-Project-ID"


def test_missing_provider_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "123456789012")


def test_unsupported_provider_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "digitalocean:abc123")


def test_same_account_id_different_provider_never_collides() -> None:
    aws = build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "aws:1234567890")
    azure = build_external_id(IdentityScheme.CLOUD_ACCOUNT_ID, "azure:1234567890")
    assert aws != azure


def test_cloud_resource_id_preserves_arn_case() -> None:
    arn = "arn:aws:s3:::My-Bucket-Name"
    ext = build_external_id(IdentityScheme.CLOUD_RESOURCE_ID, arn)
    assert ext == f"cloud_resource_id:{arn}"
