"""Azure CloudProviderAdapter backed by an injectable AzureDiscoveryClient."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.ports import (
    CloudCredential,
    DiscoveredAccount,
    RawAIService,
    RawAsset,
    RawIAMPrincipal,
    RawK8sCluster,
    RawRuntimeEvent,
)
from redforge.domain.cloud_security.value_objects import CloudAccountType, CloudAssetType
from redforge.infrastructure.cloud_security.adapters.common import (
    CloudAdapterDependencyError,
    CredentialMaterial,
    empty_async_iterator,
)


class AzureDiscoveryClient(Protocol):
    def subscription_info(self) -> dict[str, str]: ...

    def list_subscriptions(self) -> list[dict[str, Any]]: ...

    def list_virtual_machines(self, region: str) -> list[dict[str, Any]]: ...

    def list_virtual_networks(self, region: str) -> list[dict[str, Any]]: ...

    def list_network_security_groups(self, region: str) -> list[dict[str, Any]]: ...

    def list_storage_accounts(self, region: str) -> list[dict[str, Any]]: ...

    def list_sql_databases(self, region: str) -> list[dict[str, Any]]: ...

    def list_aks_clusters(self, region: str) -> list[dict[str, Any]]: ...

    def list_key_vaults(self, region: str) -> list[dict[str, Any]]: ...

    def list_function_apps(self, region: str) -> list[dict[str, Any]]: ...

    def list_iam_users(self) -> list[dict[str, Any]]: ...

    def list_iam_groups(self) -> list[dict[str, Any]]: ...

    def list_service_principals(self) -> list[dict[str, Any]]: ...

    def list_managed_identities(self) -> list[dict[str, Any]]: ...

    def list_role_assignments(self) -> list[dict[str, Any]]: ...


@dataclass
class StaticAzureDiscoveryClient:
    """Alias-friendly static client for tests (same as DictBased)."""

    subscription: dict[str, str] = field(
        default_factory=lambda: {
            "subscription_id": "00000000-0000-0000-0000-000000000000",
            "display_name": "static",
        }
    )
    subscriptions: list[dict[str, Any]] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["eastus"])
    virtual_machines: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    virtual_networks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    network_security_groups: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    storage_accounts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    sql_databases: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    aks_clusters: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    key_vaults: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    function_apps: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    iam_users: list[dict[str, Any]] = field(default_factory=list)
    iam_groups: list[dict[str, Any]] = field(default_factory=list)
    service_principals: list[dict[str, Any]] = field(default_factory=list)
    managed_identities: list[dict[str, Any]] = field(default_factory=list)
    role_assignments: list[dict[str, Any]] = field(default_factory=list)

    def subscription_info(self) -> dict[str, str]:
        return dict(self.subscription)

    def list_subscriptions(self) -> list[dict[str, Any]]:
        return list(self.subscriptions) or [
            {
                "subscription_id": self.subscription.get("subscription_id", ""),
                "display_name": self.subscription.get("display_name", ""),
            }
        ]

    def list_virtual_machines(self, region: str) -> list[dict[str, Any]]:
        return list(self.virtual_machines.get(region, []))

    def list_virtual_networks(self, region: str) -> list[dict[str, Any]]:
        return list(self.virtual_networks.get(region, []))

    def list_network_security_groups(self, region: str) -> list[dict[str, Any]]:
        return list(self.network_security_groups.get(region, []))

    def list_storage_accounts(self, region: str) -> list[dict[str, Any]]:
        return list(self.storage_accounts.get(region, []))

    def list_sql_databases(self, region: str) -> list[dict[str, Any]]:
        return list(self.sql_databases.get(region, []))

    def list_aks_clusters(self, region: str) -> list[dict[str, Any]]:
        return list(self.aks_clusters.get(region, []))

    def list_key_vaults(self, region: str) -> list[dict[str, Any]]:
        return list(self.key_vaults.get(region, []))

    def list_function_apps(self, region: str) -> list[dict[str, Any]]:
        return list(self.function_apps.get(region, []))

    def list_iam_users(self) -> list[dict[str, Any]]:
        return list(self.iam_users)

    def list_iam_groups(self) -> list[dict[str, Any]]:
        return list(self.iam_groups)

    def list_service_principals(self) -> list[dict[str, Any]]:
        return list(self.service_principals)

    def list_managed_identities(self) -> list[dict[str, Any]]:
        return list(self.managed_identities)

    def list_role_assignments(self) -> list[dict[str, Any]]:
        return list(self.role_assignments)


DictBasedAzureDiscoveryClient = StaticAzureDiscoveryClient


class SdkAzureDiscoveryClient:
    """Optional SDK-backed client — azure packages imported lazily inside methods."""

    def __init__(self, material: CredentialMaterial) -> None:
        self._material = material
        self._cache: dict[str, Any] = {}

    def _credential(self) -> Any:
        if "credential" in self._cache:
            return self._cache["credential"]
        try:
            from azure.identity import ClientSecretCredential
        except ImportError as exc:
            raise CloudAdapterDependencyError(
                "Azure SDK packages are not installed. Install azure-identity and "
                "azure-mgmt-* or use DictBasedAzureDiscoveryClient / StaticAzureDiscoveryClient."
            ) from exc
        if not (
            self._material.tenant_id and self._material.client_id and self._material.client_secret
        ):
            raise CloudAdapterDependencyError(
                "Azure CredentialMaterial requires tenant_id, client_id, and client_secret"
            )
        cred = ClientSecretCredential(
            tenant_id=self._material.tenant_id,
            client_id=self._material.client_id,
            client_secret=self._material.client_secret,
        )
        self._cache["credential"] = cred
        return cred

    def _subscription_id(self) -> str:
        return self._material.subscription_id or ""

    def subscription_info(self) -> dict[str, str]:
        sub_id = self._subscription_id()
        return {"subscription_id": sub_id, "display_name": f"Azure Subscription {sub_id}"}

    def list_subscriptions(self) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.resource import SubscriptionClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-resource is not installed") from exc
        client = SubscriptionClient(self._credential())
        return [
            {
                "subscription_id": str(sub.subscription_id),
                "display_name": str(sub.display_name or sub.subscription_id),
            }
            for sub in client.subscriptions.list()
            if sub.subscription_id
        ]

    def list_virtual_machines(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.compute import ComputeManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-compute is not installed") from exc
        client = ComputeManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for vm in client.virtual_machines.list_all():
            loc = str(getattr(vm, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            props = getattr(vm, "storage_profile", None)
            os_type = None
            if props is not None and getattr(props, "os_disk", None) is not None:
                os_type = str(getattr(props.os_disk, "os_type", "") or "") or None
            hw = getattr(vm, "hardware_profile", None)
            identity = getattr(vm, "identity", None)
            out.append(
                {
                    "provider_id": str(vm.id or vm.name),
                    "display_name": str(vm.name or vm.id),
                    "vm_size": str(getattr(hw, "vm_size", "") or "") if hw else None,
                    "os_type": os_type,
                    "identity_principal_id": str(getattr(identity, "principal_id", "") or "")
                    if identity
                    else None,
                    "tags": dict(vm.tags or {}),
                    "vnet_id": None,
                    "nsg_id": None,
                    "public_ip": None,
                    "state": None,
                }
            )
        return out

    def list_virtual_networks(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.network import NetworkManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-network is not installed") from exc
        client = NetworkManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for vnet in client.virtual_networks.list_all():
            loc = str(getattr(vnet, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            prefixes: list[str] = []
            space = getattr(vnet, "address_space", None)
            if space is not None:
                prefixes = [str(p) for p in (space.address_prefixes or [])]
            out.append(
                {
                    "provider_id": str(vnet.id or vnet.name),
                    "display_name": str(vnet.name or vnet.id),
                    "address_prefixes": prefixes,
                    "tags": dict(vnet.tags or {}),
                }
            )
        return out

    def list_network_security_groups(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.network import NetworkManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-network is not installed") from exc
        client = NetworkManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for nsg in client.network_security_groups.list_all():
            loc = str(getattr(nsg, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            out.append(
                {
                    "provider_id": str(nsg.id or nsg.name),
                    "display_name": str(nsg.name or nsg.id),
                    "tags": dict(nsg.tags or {}),
                }
            )
        return out

    def list_storage_accounts(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.storage import StorageManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-storage is not installed") from exc
        client = StorageManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for acct in client.storage_accounts.list():
            loc = str(getattr(acct, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            sku = getattr(acct, "sku", None)
            endpoints = getattr(acct, "primary_endpoints", None)
            out.append(
                {
                    "provider_id": str(acct.id or acct.name),
                    "display_name": str(acct.name or acct.id),
                    "sku": str(getattr(sku, "name", "") or "") if sku else None,
                    "kind": str(getattr(acct, "kind", "") or "") or None,
                    "allow_blob_public_access": getattr(acct, "allow_blob_public_access", None),
                    "primary_endpoint": str(getattr(endpoints, "blob", "") or "")
                    if endpoints
                    else None,
                    "encryption_at_rest": True,
                    "tags": dict(acct.tags or {}),
                }
            )
        return out

    def list_sql_databases(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.sql import SqlManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-sql is not installed") from exc
        client = SqlManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for server in client.servers.list():
            loc = str(getattr(server, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            # Resource group is embedded in ARM id.
            server_id = str(server.id or "")
            parts = server_id.split("/")
            rg = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts else ""
            if not rg or not server.name:
                continue
            for db in client.databases.list_by_server(rg, server.name):
                if str(db.name).lower() == "master":
                    continue
                out.append(
                    {
                        "provider_id": str(db.id or db.name),
                        "display_name": str(db.name or db.id),
                        "server_name": str(server.name),
                        "status": str(getattr(db, "status", "") or "") or None,
                        "edition": str(getattr(db, "edition", "") or "") or None,
                        "public_network_access": str(
                            getattr(server, "public_network_access", "") or ""
                        )
                        or None,
                        "tags": dict(db.tags or {}),
                    }
                )
        return out

    def list_aks_clusters(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.containerservice import ContainerServiceClient
        except ImportError as exc:
            raise CloudAdapterDependencyError(
                "azure-mgmt-containerservice is not installed"
            ) from exc
        client = ContainerServiceClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for cluster in client.managed_clusters.list():
            loc = str(getattr(cluster, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            identity = getattr(cluster, "identity", None)
            out.append(
                {
                    "provider_id": str(cluster.id or cluster.name),
                    "display_name": str(cluster.name or cluster.id),
                    "kubernetes_version": str(getattr(cluster, "kubernetes_version", "") or "")
                    or None,
                    "fqdn": str(getattr(cluster, "fqdn", "") or "") or None,
                    "identity_principal_id": str(getattr(identity, "principal_id", "") or "")
                    if identity
                    else None,
                    "api_server_public": not bool(
                        getattr(cluster, "api_server_access_profile", None)
                    ),
                    "tags": dict(cluster.tags or {}),
                }
            )
        return out

    def list_key_vaults(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-keyvault is not installed") from exc
        client = KeyVaultManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for vault in client.vaults.list():
            # list() returns Resource; need get for location — use id/name only.
            out.append(
                {
                    "provider_id": str(vault.id or vault.name),
                    "display_name": str(vault.name or vault.id),
                    "vault_uri": None,
                    "tags": {},
                }
            )
        del region
        return out

    def list_function_apps(self, region: str) -> list[dict[str, Any]]:
        try:
            from azure.mgmt.web import WebSiteManagementClient
        except ImportError as exc:
            raise CloudAdapterDependencyError("azure-mgmt-web is not installed") from exc
        client = WebSiteManagementClient(self._credential(), self._subscription_id())
        out: list[dict[str, Any]] = []
        for app in client.web_apps.list():
            loc = str(getattr(app, "location", "") or "")
            if region and loc and loc.lower() != region.lower():
                continue
            kind = str(getattr(app, "kind", "") or "")
            if "functionapp" not in kind.lower():
                continue
            identity = getattr(app, "identity", None)
            out.append(
                {
                    "provider_id": str(app.id or app.name),
                    "display_name": str(app.name or app.id),
                    "kind": kind,
                    "default_hostname": str(getattr(app, "default_host_name", "") or "") or None,
                    "identity_principal_id": str(getattr(identity, "principal_id", "") or "")
                    if identity
                    else None,
                    "state": str(getattr(app, "state", "") or "") or None,
                    "tags": dict(app.tags or {}),
                }
            )
        return out

    def list_iam_users(self) -> list[dict[str, Any]]:
        return []

    def list_iam_groups(self) -> list[dict[str, Any]]:
        return []

    def list_service_principals(self) -> list[dict[str, Any]]:
        return []

    def list_managed_identities(self) -> list[dict[str, Any]]:
        return []

    def list_role_assignments(self) -> list[dict[str, Any]]:
        return []


_LISTERS: dict[
    CloudAssetType,
    Callable[[AzureDiscoveryClient, str], list[dict[str, Any]]],
] = {
    CloudAssetType.AZURE_VM: lambda c, r: c.list_virtual_machines(r),
    CloudAssetType.AZURE_VNET: lambda c, r: c.list_virtual_networks(r),
    CloudAssetType.AZURE_NSG: lambda c, r: c.list_network_security_groups(r),
    CloudAssetType.AZURE_STORAGE_ACCOUNT: lambda c, r: c.list_storage_accounts(r),
    CloudAssetType.AZURE_SQL_DATABASE: lambda c, r: c.list_sql_databases(r),
    CloudAssetType.AZURE_AKS_CLUSTER: lambda c, r: c.list_aks_clusters(r),
    CloudAssetType.AZURE_KEYVAULT: lambda c, r: c.list_key_vaults(r),
    CloudAssetType.AZURE_FUNCTION_APP: lambda c, r: c.list_function_apps(r),
}


class AzureCloudProviderAdapter:
    def __init__(self, client: AzureDiscoveryClient) -> None:
        self._client = client

    async def discover_accounts(self, credential: CloudCredential) -> list[DiscoveredAccount]:
        del credential
        subs = self._client.list_subscriptions()
        if not subs:
            info = self._client.subscription_info()
            subs = [info]
        return [
            DiscoveredAccount(
                external_id=str(s.get("subscription_id") or s.get("id", "")),
                display_name=str(s.get("display_name") or s.get("subscription_id", "")),
                account_type=CloudAccountType.STANDALONE,
            )
            for s in subs
            if s.get("subscription_id") or s.get("id")
        ]

    def list_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        return self._iter_assets(account, asset_types)

    async def _iter_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        regions = [r.region_code for r in account.regions] or ["eastus"]
        for asset_type in asset_types:
            lister = _LISTERS.get(asset_type)
            if lister is None:
                continue
            for region in regions:
                for item in lister(self._client, region):
                    provider_id = str(item.get("provider_id") or "")
                    if not provider_id:
                        continue
                    yield RawAsset(
                        provider_id=provider_id,
                        asset_type=asset_type,
                        region_code=region,
                        display_name=str(item.get("display_name") or provider_id),
                        payload=dict(item),
                    )

    def list_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        return self._iter_iam_principals(account)

    async def _iter_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        account_id = account.external_id
        assignments = self._client.list_role_assignments()
        by_principal: dict[str, list[dict[str, Any]]] = {}
        for assignment in assignments:
            pid = str(
                assignment.get("principal_id")
                or assignment.get("principalId")
                or assignment.get("provider_id")
                or ""
            )
            if not pid:
                continue
            by_principal.setdefault(pid, []).append(
                {
                    "role_definition_id": assignment.get("role_definition_id")
                    or assignment.get("roleDefinitionId")
                    or assignment.get("id"),
                    "role_name": assignment.get("role_name")
                    or assignment.get("roleName")
                    or assignment.get("display_name"),
                    "attachment_type": "ROLE_ASSIGNMENT",
                    "policy_provider_id": assignment.get("role_definition_id")
                    or assignment.get("roleDefinitionId")
                    or assignment.get("id"),
                    "policy_name": assignment.get("role_name")
                    or assignment.get("roleName")
                    or assignment.get("display_name"),
                }
            )
        emitters: list[tuple[str, list[dict[str, Any]]]] = [
            ("USER", self._client.list_iam_users()),
            ("GROUP", self._client.list_iam_groups()),
            ("SERVICE_PRINCIPAL", self._client.list_service_principals()),
            ("MANAGED_IDENTITY", self._client.list_managed_identities()),
        ]
        for principal_type, items in emitters:
            for item in items:
                provider_id = str(item.get("provider_id") or "")
                if not provider_id:
                    continue
                payload = dict(item)
                payload.setdefault("account_id", account_id)
                payload["provider_id"] = provider_id
                existing = list(payload.get("role_assignments") or [])
                if not isinstance(existing, list):
                    existing = []
                matched = by_principal.get(provider_id, [])
                if matched:
                    payload["role_assignments"] = existing + matched
                yield RawIAMPrincipal(
                    provider_id=provider_id,
                    principal_type=principal_type,
                    display_name=str(item.get("display_name") or provider_id),
                    payload=payload,
                )

    def ingest_runtime_events(
        self, account: CloudAccount, since: datetime
    ) -> AsyncIterator[RawRuntimeEvent]:
        del account, since
        return empty_async_iterator()

    def describe_k8s_clusters(self, account: CloudAccount) -> AsyncIterator[RawK8sCluster]:
        del account
        return empty_async_iterator()

    def list_ai_services(self, account: CloudAccount) -> AsyncIterator[RawAIService]:
        del account
        return empty_async_iterator()
