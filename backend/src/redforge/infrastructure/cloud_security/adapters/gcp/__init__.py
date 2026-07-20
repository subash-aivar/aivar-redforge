"""GCP cloud provider adapter."""

from __future__ import annotations

from redforge.infrastructure.cloud_security.adapters.gcp.adapter import (
    DictBasedGcpDiscoveryClient,
    GCPCloudProviderAdapter,
    GcpDiscoveryClient,
    SdkGcpDiscoveryClient,
    StaticGcpDiscoveryClient,
)

__all__ = [
    "DictBasedGcpDiscoveryClient",
    "GCPCloudProviderAdapter",
    "GcpDiscoveryClient",
    "SdkGcpDiscoveryClient",
    "StaticGcpDiscoveryClient",
]
