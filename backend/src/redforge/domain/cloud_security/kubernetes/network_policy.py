"""KubernetesNetworkPolicy aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.kubernetes.entities import NetworkRule
from redforge.domain.cloud_security.kubernetes.events import (
    KubernetesDomainEvent,
    NetworkPolicyDiscovered,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class NetworkPolicyId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> NetworkPolicyId:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> NetworkPolicyId:
        return cls(UUID(raw))


@dataclass
class KubernetesNetworkPolicy:
    id: NetworkPolicyId
    cluster_id: ClusterId
    organization_id: OrganizationId
    namespace: str
    name: str
    pod_selector: dict[str, str]
    policy_types: tuple[str, ...]
    ingress_rules: tuple[NetworkRule, ...]
    egress_rules: tuple[NetworkRule, ...]
    allows_cross_namespace: bool
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
        pod_selector: dict[str, str] | None = None,
        policy_types: list[str] | None = None,
        ingress_rules: list[NetworkRule] | None = None,
        egress_rules: list[NetworkRule] | None = None,
        allows_cross_namespace: bool = False,
        now: datetime | None = None,
        policy_id: NetworkPolicyId | None = None,
    ) -> KubernetesNetworkPolicy:
        ns = (namespace or "").strip()
        pname = (name or "").strip()
        if not ns or not pname:
            raise InvalidKubernetesArgumentError("namespace/name", "required")
        ts = now or datetime.now(UTC)
        pid = policy_id or NetworkPolicyId.new()
        policy = cls(
            id=pid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            namespace=ns,
            name=pname,
            pod_selector=dict(pod_selector or {}),
            policy_types=tuple(policy_types or ("Ingress",)),
            ingress_rules=tuple(ingress_rules or ()),
            egress_rules=tuple(egress_rules or ()),
            allows_cross_namespace=allows_cross_namespace,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        policy._pending_events.append(
            NetworkPolicyDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cluster_id.value,
                policy_id=pid.value,
                namespace=ns,
                name=pname,
            )
        )
        return policy

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
