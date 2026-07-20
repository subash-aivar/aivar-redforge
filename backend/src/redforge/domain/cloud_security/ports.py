"""Provider adapter protocol and raw DTOs — interfaces only (no SDK implementations)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudAssetType,
    CloudProviderType,
    CredentialRef,
)


@dataclass(frozen=True, slots=True)
class CloudCredential:
    """Resolved credential handle for adapter authentication (never logs secrets)."""

    provider_type: CloudProviderType
    credential_ref: CredentialRef


@dataclass(frozen=True, slots=True)
class DiscoveredAccount:
    external_id: str
    display_name: str
    account_type: CloudAccountType
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawAsset:
    provider_id: str
    asset_type: CloudAssetType
    region_code: str | None
    display_name: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawIAMPrincipal:
    provider_id: str
    principal_type: str
    display_name: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawRuntimeEvent:
    event_id: str
    event_time: datetime
    source: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawK8sCluster:
    provider_id: str
    display_name: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RawAIService:
    provider_id: str
    service_type: str
    display_name: str
    payload: dict[str, Any] = field(default_factory=dict)


class CloudProviderAdapter(Protocol):
    """Implemented once per cloud provider. Never called outside infrastructure.

    Phase 2 adapters live under ``infrastructure/cloud_security/adapters/``
    (AWSCloudProviderAdapter, AzureCloudProviderAdapter, GCPCloudProviderAdapter)
    and are driven by injectable discovery clients (Static*/Boto3*/DictBased*).
    """

    async def discover_accounts(self, credential: CloudCredential) -> list[DiscoveredAccount]: ...

    def list_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]: ...

    def list_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]: ...

    def ingest_runtime_events(
        self, account: CloudAccount, since: datetime
    ) -> AsyncIterator[RawRuntimeEvent]: ...

    def describe_k8s_clusters(self, account: CloudAccount) -> AsyncIterator[RawK8sCluster]: ...

    def list_ai_services(self, account: CloudAccount) -> AsyncIterator[RawAIService]: ...
