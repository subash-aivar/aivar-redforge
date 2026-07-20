"""KubernetesService aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.kubernetes.events import KubernetesDomainEvent
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId, K8sNetworkExposure
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class K8sServiceId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> K8sServiceId:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> K8sServiceId:
        return cls(UUID(raw))


@dataclass
class KubernetesService:
    id: K8sServiceId
    cluster_id: ClusterId
    organization_id: OrganizationId
    namespace: str
    name: str
    service_type: str
    cluster_ip: str
    external_ips: tuple[str, ...]
    load_balancer_ingress: tuple[str, ...]
    ports: tuple[dict[str, object], ...]
    selector: dict[str, str]
    exposure: K8sNetworkExposure
    is_public: bool
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
        namespace: str,
        name: str,
        service_type: str = "ClusterIP",
        cluster_ip: str = "",
        external_ips: list[str] | None = None,
        load_balancer_ingress: list[str] | None = None,
        ports: list[dict[str, object]] | None = None,
        selector: dict[str, str] | None = None,
        now: datetime | None = None,
        service_id: K8sServiceId | None = None,
    ) -> KubernetesService:
        ns = (namespace or "").strip()
        svc_name = (name or "").strip()
        if not ns or not svc_name:
            raise InvalidKubernetesArgumentError("namespace/name", "required")
        stype = (service_type or "ClusterIP").strip()
        ext = tuple(external_ips or ())
        lb = tuple(load_balancer_ingress or ())
        is_public = stype in {"LoadBalancer", "NodePort"} or bool(ext) or bool(lb)
        exposure = (
            K8sNetworkExposure.PUBLIC
            if is_public
            else K8sNetworkExposure.INTERNAL
            if stype == "ClusterIP"
            else K8sNetworkExposure.UNKNOWN
        )
        ts = now or datetime.now(UTC)
        sid = service_id or K8sServiceId.new()
        return cls(
            id=sid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=ns,
            name=svc_name,
            service_type=stype,
            cluster_ip=(cluster_ip or "")[:64],
            external_ips=ext,
            load_balancer_ingress=lb,
            ports=tuple(ports or ()),
            selector=dict(selector or {}),
            exposure=exposure,
            is_public=is_public,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
