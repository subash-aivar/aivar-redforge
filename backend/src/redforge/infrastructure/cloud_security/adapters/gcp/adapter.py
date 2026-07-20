"""GCP CloudProviderAdapter backed by an injectable GcpDiscoveryClient."""

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


class GcpDiscoveryClient(Protocol):
    def project_info(self) -> dict[str, str]: ...

    def list_projects(self) -> list[dict[str, Any]]: ...

    def list_compute_instances(self, region: str) -> list[dict[str, Any]]: ...

    def list_vpc_networks(self, region: str) -> list[dict[str, Any]]: ...

    def list_storage_buckets(self, region: str) -> list[dict[str, Any]]: ...

    def list_cloud_sql_instances(self, region: str) -> list[dict[str, Any]]: ...

    def list_gke_clusters(self, region: str) -> list[dict[str, Any]]: ...

    def list_secrets(self, region: str) -> list[dict[str, Any]]: ...

    def list_cloud_functions(self, region: str) -> list[dict[str, Any]]: ...

    def list_service_accounts(self) -> list[dict[str, Any]]: ...

    def list_iam_bindings(self) -> list[dict[str, Any]]: ...

    def list_iam_roles(self) -> list[dict[str, Any]]: ...


@dataclass
class StaticGcpDiscoveryClient:
    project: dict[str, str] = field(
        default_factory=lambda: {"project_id": "demo-project", "display_name": "Demo"}
    )
    projects: list[dict[str, Any]] = field(default_factory=list)
    regions: list[str] = field(default_factory=lambda: ["us-central1"])
    compute_instances: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    vpc_networks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    storage_buckets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    cloud_sql_instances: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    gke_clusters: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    secrets: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    cloud_functions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    service_accounts: list[dict[str, Any]] = field(default_factory=list)
    iam_bindings: list[dict[str, Any]] = field(default_factory=list)
    iam_roles: list[dict[str, Any]] = field(default_factory=list)

    def project_info(self) -> dict[str, str]:
        return dict(self.project)

    def list_projects(self) -> list[dict[str, Any]]:
        return list(self.projects) or [
            {
                "project_id": self.project.get("project_id", ""),
                "display_name": self.project.get("display_name", ""),
            }
        ]

    def list_compute_instances(self, region: str) -> list[dict[str, Any]]:
        return list(self.compute_instances.get(region, []))

    def list_vpc_networks(self, region: str) -> list[dict[str, Any]]:
        return list(self.vpc_networks.get(region, []))

    def list_storage_buckets(self, region: str) -> list[dict[str, Any]]:
        return list(self.storage_buckets.get(region, []))

    def list_cloud_sql_instances(self, region: str) -> list[dict[str, Any]]:
        return list(self.cloud_sql_instances.get(region, []))

    def list_gke_clusters(self, region: str) -> list[dict[str, Any]]:
        return list(self.gke_clusters.get(region, []))

    def list_secrets(self, region: str) -> list[dict[str, Any]]:
        return list(self.secrets.get(region, []))

    def list_cloud_functions(self, region: str) -> list[dict[str, Any]]:
        return list(self.cloud_functions.get(region, []))

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return list(self.service_accounts)

    def list_iam_bindings(self) -> list[dict[str, Any]]:
        return list(self.iam_bindings)

    def list_iam_roles(self) -> list[dict[str, Any]]:
        return list(self.iam_roles)


DictBasedGcpDiscoveryClient = StaticGcpDiscoveryClient


class SdkGcpDiscoveryClient:
    """Optional SDK-backed client — google packages imported lazily inside methods."""

    def __init__(self, material: CredentialMaterial) -> None:
        self._material = material

    def _project_id(self) -> str:
        return self._material.project_id or ""

    def _credentials(self) -> Any:
        try:
            from google.oauth2 import service_account
        except ImportError as exc:
            raise CloudAdapterDependencyError(
                "Google Cloud SDK packages are not installed. Install google-cloud-* "
                "or use DictBasedGcpDiscoveryClient / StaticGcpDiscoveryClient."
            ) from exc
        if not self._material.service_account_json:
            raise CloudAdapterDependencyError(
                "GCP CredentialMaterial requires service_account_json"
            )
        import json

        info = json.loads(self._material.service_account_json)
        return service_account.Credentials.from_service_account_info(info)

    def project_info(self) -> dict[str, str]:
        pid = self._project_id()
        return {"project_id": pid, "display_name": f"GCP Project {pid}"}

    def list_projects(self) -> list[dict[str, Any]]:
        try:
            from google.cloud import resourcemanager_v3
        except ImportError as exc:
            raise CloudAdapterDependencyError(
                "google-cloud-resource-manager is not installed"
            ) from exc
        # Import validates the SDK is present; multi-project crawl is out of scope.
        _ = resourcemanager_v3
        pid = self._project_id()
        if pid:
            return [{"project_id": pid, "display_name": f"GCP Project {pid}"}]
        return []

    def list_compute_instances(self, region: str) -> list[dict[str, Any]]:
        try:
            from google.cloud import compute_v1
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-cloud-compute is not installed") from exc
        client = compute_v1.InstancesClient(credentials=self._credentials())
        # Aggregated list across zones; filter by region prefix.
        out: list[dict[str, Any]] = []
        request = compute_v1.AggregatedListInstancesRequest(project=self._project_id())
        for zone_name, scoped in client.aggregated_list(request=request):
            if region and region not in zone_name:
                continue
            for inst in scoped.instances or []:
                network = None
                public_ip = None
                subnet = None
                for iface in inst.network_interfaces or []:
                    network = iface.network or network
                    subnet = iface.subnetwork or subnet
                    for cfg in iface.access_configs or []:
                        if cfg.nat_i_p:
                            public_ip = cfg.nat_i_p
                sa = None
                if inst.service_accounts:
                    sa = inst.service_accounts[0].email
                zone = zone_name.split("/")[-1]
                provider_id = (
                    f"projects/{self._project_id()}/zones/{zone}/instances/{inst.name}"
                )
                out.append(
                    {
                        "provider_id": provider_id,
                        "display_name": str(inst.name or ""),
                        "status": inst.status,
                        "machine_type": inst.machine_type,
                        "zone": zone,
                        "network": network,
                        "subnetwork": subnet,
                        "public_ip": public_ip,
                        "service_account": sa,
                        "labels": dict(inst.labels or {}),
                    }
                )
        return out

    def list_vpc_networks(self, region: str) -> list[dict[str, Any]]:
        del region
        try:
            from google.cloud import compute_v1
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-cloud-compute is not installed") from exc
        client = compute_v1.NetworksClient(credentials=self._credentials())
        out: list[dict[str, Any]] = []
        for net in client.list(project=self._project_id()):
            out.append(
                {
                    "provider_id": str(net.self_link or net.name),
                    "display_name": str(net.name or ""),
                    "auto_create_subnetworks": net.auto_create_subnetworks,
                    "labels": {},
                }
            )
        return out

    def list_storage_buckets(self, region: str) -> list[dict[str, Any]]:
        try:
            from google.cloud import storage
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-cloud-storage is not installed") from exc
        client = storage.Client(project=self._project_id(), credentials=self._credentials())
        out: list[dict[str, Any]] = []
        for bucket in client.list_buckets():
            loc = str(bucket.location or "")
            if (
                region
                and loc
                and loc.lower() != region.lower()
                and not loc.lower().startswith(region.lower())
            ):
                continue
            out.append(
                {
                    "provider_id": f"gs://{bucket.name}",
                    "display_name": str(bucket.name),
                    "location": loc,
                    "storage_class": bucket.storage_class,
                    "kms_key_name": getattr(bucket, "default_kms_key_name", None),
                    "labels": dict(bucket.labels or {}),
                }
            )
        return out

    def list_cloud_sql_instances(self, region: str) -> list[dict[str, Any]]:
        try:
            from googleapiclient import discovery
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-api-python-client is not installed") from exc
        service = discovery.build(
            "sqladmin", "v1", credentials=self._credentials(), cache_discovery=False
        )
        resp = service.instances().list(project=self._project_id()).execute()
        out: list[dict[str, Any]] = []
        for inst in resp.get("items") or []:
            inst_region = str(inst.get("region") or "")
            if region and inst_region and inst_region != region:
                continue
            ip = None
            for addr in inst.get("ipAddresses") or []:
                if addr.get("type") == "PRIMARY":
                    ip = addr.get("ipAddress")
            settings = inst.get("settings") or {}
            ip_cfg = settings.get("ipConfiguration") or {}
            out.append(
                {
                    "provider_id": str(inst.get("selfLink") or inst.get("name", "")),
                    "display_name": str(inst.get("name") or ""),
                    "state": inst.get("state"),
                    "database_version": inst.get("databaseVersion"),
                    "tier": (settings.get("tier")),
                    "network": ip_cfg.get("privateNetwork"),
                    "public_ip": ip,
                    "public_ip_enabled": not bool(ip_cfg.get("ipv4Enabled") is False),
                    "labels": dict(settings.get("userLabels") or {}),
                }
            )
        return out

    def list_gke_clusters(self, region: str) -> list[dict[str, Any]]:
        try:
            from google.cloud import container_v1
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-cloud-container is not installed") from exc
        client = container_v1.ClusterManagerClient(credentials=self._credentials())
        parent = f"projects/{self._project_id()}/locations/{region or '-'}"
        resp = client.list_clusters(parent=parent)
        out: list[dict[str, Any]] = []
        for cluster in resp.clusters or []:
            out.append(
                {
                    "provider_id": str(cluster.self_link or cluster.name),
                    "display_name": str(cluster.name or ""),
                    "status": str(cluster.status.name) if cluster.status else None,
                    "endpoint": cluster.endpoint,
                    "network": cluster.network,
                    "subnetwork": cluster.subnetwork,
                    "current_master_version": cluster.current_master_version,
                    "endpoint_public": not bool(
                        cluster.private_cluster_config
                        and cluster.private_cluster_config.enable_private_endpoint
                    ),
                    "labels": dict(cluster.resource_labels or {}),
                }
            )
        return out

    def list_secrets(self, region: str) -> list[dict[str, Any]]:
        del region
        try:
            from google.cloud import secretmanager_v1
        except ImportError as exc:
            raise CloudAdapterDependencyError(
                "google-cloud-secret-manager is not installed"
            ) from exc
        client = secretmanager_v1.SecretManagerServiceClient(credentials=self._credentials())
        parent = f"projects/{self._project_id()}"
        out: list[dict[str, Any]] = []
        for secret in client.list_secrets(request={"parent": parent}):
            out.append(
                {
                    "provider_id": str(secret.name),
                    "display_name": str(secret.name).rsplit("/", 1)[-1],
                    "labels": dict(secret.labels or {}),
                    "replication": None,
                }
            )
        return out

    def list_cloud_functions(self, region: str) -> list[dict[str, Any]]:
        try:
            from google.cloud import functions_v2
        except ImportError as exc:
            raise CloudAdapterDependencyError("google-cloud-functions is not installed") from exc
        client = functions_v2.FunctionServiceClient(credentials=self._credentials())
        parent = f"projects/{self._project_id()}/locations/{region or '-'}"
        out: list[dict[str, Any]] = []
        for fn in client.list_functions(parent=parent):
            sa = None
            if fn.service_config:
                sa = fn.service_config.service_account_email
            url = None
            if fn.service_config:
                url = fn.service_config.uri
            out.append(
                {
                    "provider_id": str(fn.name),
                    "display_name": str(fn.name).rsplit("/", 1)[-1],
                    "state": str(fn.state.name) if fn.state else None,
                    "runtime": fn.build_config.runtime if fn.build_config else None,
                    "entry_point": fn.build_config.entry_point if fn.build_config else None,
                    "service_account": sa,
                    "https_trigger_url": url,
                    "labels": dict(fn.labels or {}),
                }
            )
        return out

    def list_service_accounts(self) -> list[dict[str, Any]]:
        return []

    def list_iam_bindings(self) -> list[dict[str, Any]]:
        return []

    def list_iam_roles(self) -> list[dict[str, Any]]:
        return []


_LISTERS: dict[
    CloudAssetType,
    Callable[[GcpDiscoveryClient, str], list[dict[str, Any]]],
] = {
    CloudAssetType.GCP_COMPUTE_INSTANCE: lambda c, r: c.list_compute_instances(r),
    CloudAssetType.GCP_VPC_NETWORK: lambda c, r: c.list_vpc_networks(r),
    CloudAssetType.GCP_STORAGE_BUCKET: lambda c, r: c.list_storage_buckets(r),
    CloudAssetType.GCP_CLOUD_SQL: lambda c, r: c.list_cloud_sql_instances(r),
    CloudAssetType.GCP_GKE_CLUSTER: lambda c, r: c.list_gke_clusters(r),
    CloudAssetType.GCP_SECRET_MANAGER: lambda c, r: c.list_secrets(r),
    CloudAssetType.GCP_CLOUD_FUNCTION: lambda c, r: c.list_cloud_functions(r),
}

_GLOBAL_TYPES = frozenset(
    {
        CloudAssetType.GCP_VPC_NETWORK,
        CloudAssetType.GCP_SECRET_MANAGER,
    }
)


class GCPCloudProviderAdapter:
    def __init__(self, client: GcpDiscoveryClient) -> None:
        self._client = client

    async def discover_accounts(self, credential: CloudCredential) -> list[DiscoveredAccount]:
        del credential
        projects = self._client.list_projects()
        if not projects:
            info = self._client.project_info()
            projects = [info]
        return [
            DiscoveredAccount(
                external_id=str(p.get("project_id") or p.get("id", "")),
                display_name=str(p.get("display_name") or p.get("project_id", "")),
                account_type=CloudAccountType.STANDALONE,
            )
            for p in projects
            if p.get("project_id") or p.get("id")
        ]

    def list_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        return self._iter_assets(account, asset_types)

    async def _iter_assets(
        self, account: CloudAccount, asset_types: list[CloudAssetType]
    ) -> AsyncIterator[RawAsset]:
        regions = [r.region_code for r in account.regions] or ["us-central1"]
        emitted_global: set[tuple[CloudAssetType, str]] = set()
        for asset_type in asset_types:
            lister = _LISTERS.get(asset_type)
            if lister is None:
                continue
            region_iter = ["global"] if asset_type in _GLOBAL_TYPES else regions
            for region in region_iter:
                lookup = regions[0] if region == "global" else region
                for item in lister(self._client, lookup):
                    provider_id = str(item.get("provider_id") or "")
                    if not provider_id:
                        continue
                    if asset_type in _GLOBAL_TYPES:
                        key = (asset_type, provider_id)
                        if key in emitted_global:
                            continue
                        emitted_global.add(key)
                    yield RawAsset(
                        provider_id=provider_id,
                        asset_type=asset_type,
                        region_code=None if region == "global" else region,
                        display_name=str(item.get("display_name") or provider_id),
                        payload=dict(item),
                    )

    def list_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        return self._iter_iam_principals(account)

    async def _iter_iam_principals(self, account: CloudAccount) -> AsyncIterator[RawIAMPrincipal]:
        account_id = account.external_id
        bindings = self._client.list_iam_bindings()
        for item in self._client.list_service_accounts():
            provider_id = str(item.get("provider_id") or "")
            if not provider_id:
                continue
            payload = dict(item)
            payload.setdefault("account_id", account_id)
            payload["provider_id"] = provider_id
            email = str(item.get("email") or provider_id)
            matched = [
                b
                for b in bindings
                if isinstance(b, dict)
                and any(
                    str(m) in {email, f"serviceAccount:{email}", provider_id}
                    for m in (b.get("members") or [])
                )
            ]
            if matched:
                payload["iam_bindings"] = matched
            yield RawIAMPrincipal(
                provider_id=provider_id,
                principal_type="SERVICE_ACCOUNT",
                display_name=str(item.get("display_name") or email or provider_id),
                payload=payload,
            )
        for item in self._client.list_iam_roles():
            provider_id = str(item.get("provider_id") or item.get("name") or "")
            if not provider_id:
                continue
            payload = dict(item)
            payload.setdefault("account_id", account_id)
            payload["provider_id"] = provider_id
            yield RawIAMPrincipal(
                provider_id=provider_id,
                principal_type="POLICY",
                display_name=str(item.get("display_name") or provider_id.rsplit("/", 1)[-1]),
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
