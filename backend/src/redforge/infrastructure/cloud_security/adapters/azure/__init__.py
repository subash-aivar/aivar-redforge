"""Azure cloud provider adapter."""

from __future__ import annotations

from redforge.infrastructure.cloud_security.adapters.azure.adapter import (
    AzureCloudProviderAdapter,
    AzureDiscoveryClient,
    DictBasedAzureDiscoveryClient,
    SdkAzureDiscoveryClient,
    StaticAzureDiscoveryClient,
)

__all__ = [
    "AzureCloudProviderAdapter",
    "AzureDiscoveryClient",
    "DictBasedAzureDiscoveryClient",
    "SdkAzureDiscoveryClient",
    "StaticAzureDiscoveryClient",
]
