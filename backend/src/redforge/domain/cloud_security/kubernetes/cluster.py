"""KubernetesCluster aggregate root."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.kubernetes.events import (
    ClusterDiscovered,
    KubernetesDomainEvent,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ClusterId,
    K8sClusterType,
    K8sSecurityScore,
)
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    OrganizationId,
)


@dataclass
class KubernetesCluster:
    id: ClusterId
    organization_id: OrganizationId
    cloud_account_id: CloudAccountId
    cloud_asset_id: CloudAssetId | None
    cluster_type: K8sClusterType
    name: str
    version: str
    api_server_endpoint: str
    region: str
    credential_ref_id: str
    labels: dict[str, str]
    pod_security_standards: dict[str, str]
    security_score: K8sSecurityScore
    discovered_at: datetime
    last_synced_at: datetime | None
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[KubernetesDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def discover(
        cls,
        *,
        organization_id: OrganizationId,
        cloud_account_id: CloudAccountId,
        cluster_type: K8sClusterType | str,
        name: str,
        version: str,
        api_server_endpoint: str = "",
        region: str = "",
        credential_ref_id: str = "",
        cloud_asset_id: CloudAssetId | None = None,
        labels: dict[str, str] | None = None,
        pod_security_standards: dict[str, str] | None = None,
        now: datetime | None = None,
        cluster_id: ClusterId | None = None,
    ) -> KubernetesCluster:
        cleaned = (name or "").strip()
        if not cleaned or len(cleaned) > 253:
            raise InvalidKubernetesArgumentError("name", "required, max 253 chars")
        ctype = (
            cluster_type
            if isinstance(cluster_type, K8sClusterType)
            else K8sClusterType(str(cluster_type).upper())
        )
        ts = now or datetime.now(UTC)
        cid = cluster_id or ClusterId.new()
        cluster = cls(
            id=cid,
            organization_id=organization_id,
            cloud_account_id=cloud_account_id,
            cloud_asset_id=cloud_asset_id,
            cluster_type=ctype,
            name=cleaned,
            version=(version or "").strip()[:64],
            api_server_endpoint=(api_server_endpoint or "").strip()[:512],
            region=(region or "").strip()[:64],
            credential_ref_id=(credential_ref_id or "").strip()[:256],
            labels=dict(labels or {}),
            pod_security_standards=dict(pod_security_standards or {}),
            security_score=K8sSecurityScore(value=100),
            discovered_at=ts,
            last_synced_at=ts,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        cluster._pending_events.append(
            ClusterDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cid.value,
                cluster_name=cleaned,
                cluster_type=ctype.value,
                cloud_asset_id=cloud_asset_id.value if cloud_asset_id else None,
            )
        )
        return cluster

    def mark_synced(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.last_synced_at = ts
        self.updated_at = ts
        self.row_version += 1

    def update_security_score(
        self, score: K8sSecurityScore, *, now: datetime | None = None
    ) -> None:
        ts = now or datetime.now(UTC)
        self.security_score = score
        self.updated_at = ts
        self.row_version += 1

    def bind_cloud_asset(self, asset_id: CloudAssetId, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.cloud_asset_id = asset_id
        self.updated_at = ts
        self.row_version += 1

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
