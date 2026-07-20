"""KubernetesNode aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.kubernetes.events import KubernetesDomainEvent, NodeDiscovered
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class NodeId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> NodeId:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> NodeId:
        return cls(UUID(raw))


@dataclass
class KubernetesNode:
    id: NodeId
    cluster_id: ClusterId
    organization_id: OrganizationId
    name: str
    uid: str
    kubelet_version: str
    os_image: str
    container_runtime: str
    roles: tuple[str, ...]
    labels: dict[str, str]
    taints: tuple[str, ...]
    unschedulable: bool
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
        uid: str = "",
        kubelet_version: str = "",
        os_image: str = "",
        container_runtime: str = "",
        roles: list[str] | None = None,
        labels: dict[str, str] | None = None,
        taints: list[str] | None = None,
        unschedulable: bool = False,
        now: datetime | None = None,
        node_id: NodeId | None = None,
    ) -> KubernetesNode:
        cleaned = (name or "").strip()
        if not cleaned:
            raise InvalidKubernetesArgumentError("name", "required")
        ts = now or datetime.now(UTC)
        nid = node_id or NodeId.new()
        node = cls(
            id=nid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=cleaned[:253],
            uid=(uid or "")[:128],
            kubelet_version=(kubelet_version or "")[:64],
            os_image=(os_image or "")[:256],
            container_runtime=(container_runtime or "")[:128],
            roles=tuple(roles or ()),
            labels=dict(labels or {}),
            taints=tuple(taints or ()),
            unschedulable=unschedulable,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        node._pending_events.append(
            NodeDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cluster_id.value,
                node_id=nid.value,
                node_name=cleaned,
            )
        )
        return node

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
