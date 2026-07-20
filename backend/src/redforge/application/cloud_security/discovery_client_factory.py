"""Factories that build provider discovery clients from CredentialRef."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from redforge.core.exceptions import CredentialResolutionError
from redforge.domain.cloud_security.value_objects import CloudProviderType, CredentialRef
from redforge.infrastructure.cloud_security.adapters.aws.adapter import (
    Boto3AwsDiscoveryClient,
    StaticAwsDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.azure.adapter import (
    StaticAzureDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.common import CredentialMaterial
from redforge.infrastructure.cloud_security.adapters.gcp.adapter import (
    StaticGcpDiscoveryClient,
)


class DiscoveryClientFactory(Protocol):
    def create(self, provider_type: CloudProviderType, credential_ref: CredentialRef) -> Any: ...


class EnvironmentCloudCredentialResolver:
    """Maps CredentialRef.reference_id to REDFORGE_CLOUD_{REF}_* env vars.

    Example: reference_id ``prod_aws`` resolves:
      REDFORGE_CLOUD_PROD_AWS_ACCESS_KEY_ID
      REDFORGE_CLOUD_PROD_AWS_SECRET_ACCESS_KEY
      REDFORGE_CLOUD_PROD_AWS_SESSION_TOKEN (optional)
      REDFORGE_CLOUD_PROD_AWS_REGIONS (optional, comma-separated)
    Azure/GCP use TENANT_ID/CLIENT_ID/CLIENT_SECRET/SUBSCRIPTION_ID or
    PROJECT_ID/SERVICE_ACCOUNT_JSON respectively.
    """

    def resolve(self, credential_ref: CredentialRef) -> CredentialMaterial:
        ref = credential_ref.reference_id.strip().upper().replace("-", "_")
        if not ref:
            raise CredentialResolutionError("(empty credential reference_id)")
        prefix = f"REDFORGE_CLOUD_{ref}"

        def _get(suffix: str) -> str | None:
            value = os.environ.get(f"{prefix}_{suffix}", "").strip()
            return value or None

        regions_raw = _get("REGIONS") or ""
        regions = tuple(r.strip() for r in regions_raw.split(",") if r.strip())
        return CredentialMaterial(
            access_key_id=_get("ACCESS_KEY_ID"),
            secret_access_key=_get("SECRET_ACCESS_KEY"),
            session_token=_get("SESSION_TOKEN"),
            tenant_id=_get("TENANT_ID"),
            client_id=_get("CLIENT_ID"),
            client_secret=_get("CLIENT_SECRET"),
            subscription_id=_get("SUBSCRIPTION_ID"),
            project_id=_get("PROJECT_ID"),
            service_account_json=_get("SERVICE_ACCOUNT_JSON"),
            regions=regions,
        )


@dataclass
class StaticDiscoveryClientFactory:
    """Returns preconfigured static clients (tests / demos)."""

    aws_client: StaticAwsDiscoveryClient = field(default_factory=StaticAwsDiscoveryClient)
    azure_client: StaticAzureDiscoveryClient = field(default_factory=StaticAzureDiscoveryClient)
    gcp_client: StaticGcpDiscoveryClient = field(default_factory=StaticGcpDiscoveryClient)

    def create(self, provider_type: CloudProviderType, credential_ref: CredentialRef) -> Any:
        del credential_ref
        if provider_type is CloudProviderType.AWS:
            return self.aws_client
        if provider_type is CloudProviderType.AZURE:
            return self.azure_client
        if provider_type is CloudProviderType.GCP:
            return self.gcp_client
        raise ValueError(f"Unsupported provider_type: {provider_type}")


@dataclass
class Boto3DiscoveryClientFactory:
    """Builds Boto3AwsDiscoveryClient from environment-resolved credentials.

    Azure/GCP fall back to static empty clients unless a custom override is
    injected — SDK packages are optional and not required in pyproject.
    """

    resolver: EnvironmentCloudCredentialResolver = field(
        default_factory=EnvironmentCloudCredentialResolver
    )
    azure_client: StaticAzureDiscoveryClient | None = None
    gcp_client: StaticGcpDiscoveryClient | None = None

    def create(self, provider_type: CloudProviderType, credential_ref: CredentialRef) -> Any:
        material = self.resolver.resolve(credential_ref)
        if provider_type is CloudProviderType.AWS:
            if not material.access_key_id or not material.secret_access_key:
                ref = credential_ref.reference_id.upper().replace("-", "_")
                raise CredentialResolutionError(f"REDFORGE_CLOUD_{ref}_ACCESS_KEY_ID")
            return Boto3AwsDiscoveryClient(material)
        if provider_type is CloudProviderType.AZURE:
            return self.azure_client or StaticAzureDiscoveryClient(
                subscription={
                    "subscription_id": material.subscription_id or "",
                    "display_name": material.subscription_id or "azure",
                }
            )
        if provider_type is CloudProviderType.GCP:
            return self.gcp_client or StaticGcpDiscoveryClient(
                project={
                    "project_id": material.project_id or "",
                    "display_name": material.project_id or "gcp",
                }
            )
        raise ValueError(f"Unsupported provider_type: {provider_type}")
