"""KubernetesWorkload aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.kubernetes.entities import (
    PodContainer,
    ServiceAccountReference,
)
from redforge.domain.cloud_security.kubernetes.events import (
    KubernetesDomainEvent,
    WorkloadDiscovered,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import (
    ClusterId,
    PodSecurityLevel,
    WorkloadExposure,
    WorkloadId,
    WorkloadKind,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass
class KubernetesWorkload:
    id: WorkloadId
    cluster_id: ClusterId
    organization_id: OrganizationId
    namespace: str
    name: str
    kind: WorkloadKind
    uid: str
    service_account: ServiceAccountReference
    containers: tuple[PodContainer, ...]
    host_network: bool
    host_pid: bool
    host_ipc: bool
    privileged: bool
    security_level: PodSecurityLevel
    exposure: WorkloadExposure
    labels: dict[str, str]
    annotations: dict[str, str]
    replicas: int
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
        kind: WorkloadKind | str,
        uid: str = "",
        service_account: ServiceAccountReference | None = None,
        containers: list[PodContainer] | None = None,
        host_network: bool = False,
        host_pid: bool = False,
        host_ipc: bool = False,
        labels: dict[str, str] | None = None,
        annotations: dict[str, str] | None = None,
        replicas: int = 1,
        exposure: WorkloadExposure | str = WorkloadExposure.CLUSTER_LOCAL,
        now: datetime | None = None,
        workload_id: WorkloadId | None = None,
    ) -> KubernetesWorkload:
        ns = (namespace or "").strip()
        wl_name = (name or "").strip()
        if not ns or not wl_name:
            raise InvalidKubernetesArgumentError("namespace/name", "required")
        if len(ns) > 253 or len(wl_name) > 253:
            raise InvalidKubernetesArgumentError("namespace/name", "max 253 chars")
        wkind = kind if isinstance(kind, WorkloadKind) else WorkloadKind(str(kind).upper())
        conts = tuple(containers or [])
        privileged = any(c.privileged for c in conts)
        level = _infer_security_level(
            privileged=privileged,
            host_network=host_network,
            host_pid=host_pid,
            host_ipc=host_ipc,
            containers=conts,
        )
        exp = (
            exposure
            if isinstance(exposure, WorkloadExposure)
            else WorkloadExposure(str(exposure).upper())
        )
        ts = now or datetime.now(UTC)
        wid = workload_id or WorkloadId.new()
        sa = service_account or ServiceAccountReference(name="default", namespace=ns)
        wl = cls(
            id=wid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=ns,
            name=wl_name,
            kind=wkind,
            uid=(uid or "").strip()[:128],
            service_account=sa,
            containers=conts,
            host_network=host_network,
            host_pid=host_pid,
            host_ipc=host_ipc,
            privileged=privileged,
            security_level=level,
            exposure=exp,
            labels=dict(labels or {}),
            annotations=dict(annotations or {}),
            replicas=max(0, int(replicas)),
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        wl._pending_events.append(
            WorkloadDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cluster_id.value,
                workload_id=wid.value,
                namespace=ns,
                name=wl_name,
                kind=wkind.value,
            )
        )
        return wl

    def posture_snapshot(self) -> dict[str, Any]:
        """Provider-agnostic snapshot for CSPM PolicyEvaluationEngine."""
        images = [c.image.to_dict() for c in self.containers]
        caps = sorted({cap for c in self.containers for cap in c.capabilities_add})
        return {
            "asset_type": "K8S_WORKLOAD",
            "workload_kind": self.kind.value,
            "namespace": self.namespace,
            "name": self.name,
            "host_network": self.host_network,
            "host_pid": self.host_pid,
            "host_ipc": self.host_ipc,
            "privileged": self.privileged,
            "security_level": self.security_level.value,
            "exposure": self.exposure.value,
            "service_account": self.service_account.to_dict(),
            "containers": [c.to_dict() for c in self.containers],
            "images": images,
            "capabilities_add": caps,
            "uses_latest_tag": any(c.image.uses_latest_tag for c in self.containers),
            "read_only_root_filesystem": all(c.read_only_root_filesystem for c in self.containers)
            if self.containers
            else False,
            "run_as_non_root": all(c.run_as_non_root for c in self.containers)
            if self.containers
            else False,
            "allow_privilege_escalation": any(
                c.allow_privilege_escalation for c in self.containers
            ),
            "image_pull_policy_always": all(
                c.image_pull_policy.lower() == "always" for c in self.containers
            )
            if self.containers
            else False,
            "normalized_config": {
                "host_network": self.host_network,
                "host_pid": self.host_pid,
                "host_ipc": self.host_ipc,
                "privileged": self.privileged,
                "security_level": self.security_level.value,
                "network_exposure": self.exposure.value,
                "uses_latest_tag": any(c.image.uses_latest_tag for c in self.containers),
                "read_only_root_filesystem": all(
                    c.read_only_root_filesystem for c in self.containers
                )
                if self.containers
                else False,
                "run_as_non_root": all(c.run_as_non_root for c in self.containers)
                if self.containers
                else False,
                "allow_privilege_escalation": any(
                    c.allow_privilege_escalation for c in self.containers
                ),
                "image_pull_policy_always": all(
                    c.image_pull_policy.lower() == "always" for c in self.containers
                )
                if self.containers
                else False,
                "capabilities_add": caps,
                "attributes": {
                    "workload_kind": self.kind.value,
                    "namespace": self.namespace,
                },
            },
        }

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events


def _infer_security_level(
    *,
    privileged: bool,
    host_network: bool,
    host_pid: bool,
    host_ipc: bool,
    containers: tuple[PodContainer, ...],
) -> PodSecurityLevel:
    if privileged or host_network or host_pid or host_ipc:
        return PodSecurityLevel.PRIVILEGED
    if any(c.capabilities_add for c in containers):
        return PodSecurityLevel.BASELINE
    if containers and all(c.run_as_non_root and c.read_only_root_filesystem for c in containers):
        return PodSecurityLevel.RESTRICTED
    if not containers:
        return PodSecurityLevel.UNKNOWN
    return PodSecurityLevel.BASELINE
