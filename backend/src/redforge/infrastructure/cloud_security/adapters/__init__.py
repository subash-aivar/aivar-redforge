"""Cloud provider adapters for M26 Phase 2 discovery."""

from __future__ import annotations

from redforge.infrastructure.cloud_security.adapters.aws import AWSCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.azure import AzureCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.gcp import GCPCloudProviderAdapter

__all__ = [
    "AWSCloudProviderAdapter",
    "AzureCloudProviderAdapter",
    "GCPCloudProviderAdapter",
]
