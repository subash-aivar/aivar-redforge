"""KubernetesNamespace aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.kubernetes.events import (
    KubernetesDomainEvent,
    NamespaceDiscovered,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId, NamespaceId
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass
class KubernetesNamespace:
    id: NamespaceId
    cluster_id: ClusterId
    organization_id: OrganizationId
    name: str
    labels: dict[str, str]
    annotations: dict[str, str]
    pod_security_level: str
    resource_quotas: dict[str, str]
    has_network_policy: bool
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[KubernetesDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def discover(
        cls,
        *,
        cluster_id: ClusterId,
        organization_id: OrganizationId,
        name: str,
        labels: dict[str, str] | None = None,
        annotations: dict[str, str] | None = None,
        pod_security_level: str = "UNKNOWN",
        resource_quotas: dict[str, str] | None = None,
        has_network_policy: bool = False,
        now: datetime | None = None,
        namespace_id: NamespaceId | None = None,
    ) -> KubernetesNamespace:
        cleaned = (name or "").strip()
        if not cleaned or len(cleaned) > 253:
            raise InvalidKubernetesArgumentError("name", "required, max 253 chars")
        ts = now or datetime.now(UTC)
        nid = namespace_id or NamespaceId.new()
        ns = cls(
            id=nid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=cleaned,
            labels=dict(labels or {}),
            annotations=dict(annotations or {}),
            pod_security_level=pod_security_level.upper(),
            resource_quotas=dict(resource_quotas or {}),
            has_network_policy=has_network_policy,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        ns._pending_events.append(
            NamespaceDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cluster_id.value,
                namespace=cleaned,
                namespace_id=nid.value,
            )
        )
        return ns

    def mark_network_policy(self, present: bool, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.has_network_policy = present
        self.updated_at = ts
        self.row_version += 1

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
