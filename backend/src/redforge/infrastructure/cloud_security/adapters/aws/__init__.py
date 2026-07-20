"""AWS cloud provider adapter."""

from __future__ import annotations

from redforge.infrastructure.cloud_security.adapters.aws.adapter import (
    AWSCloudProviderAdapter,
    AwsDiscoveryClient,
    Boto3AwsDiscoveryClient,
    StaticAwsDiscoveryClient,
)

__all__ = [
    "AWSCloudProviderAdapter",
    "AwsDiscoveryClient",
    "Boto3AwsDiscoveryClient",
    "StaticAwsDiscoveryClient",
]
