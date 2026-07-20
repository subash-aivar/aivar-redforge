"""KubernetesRBACPrincipal aggregate — RBAC inventory only (no escalation paths)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.kubernetes.entities import RBACBinding
from redforge.domain.cloud_security.kubernetes.events import KubernetesDomainEvent, RBACDiscovered
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import ClusterId, RBACPrincipalKind
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class RBACPrincipalId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> RBACPrincipalId:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> RBACPrincipalId:
        return cls(UUID(raw))


@dataclass
class KubernetesRBACPrincipal:
    id: RBACPrincipalId
    cluster_id: ClusterId
    organization_id: OrganizationId
    kind: RBACPrincipalKind
    name: str
    namespace: str
    bindings: tuple[RBACBinding, ...]
    roles: tuple[str, ...]
    cluster_roles: tuple[str, ...]
    trust_references: tuple[str, ...]
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
        kind: RBACPrincipalKind | str,
        name: str,
        namespace: str = "",
        bindings: list[RBACBinding] | None = None,
        roles: list[str] | None = None,
        cluster_roles: list[str] | None = None,
        trust_references: list[str] | None = None,
        now: datetime | None = None,
        principal_id: RBACPrincipalId | None = None,
    ) -> KubernetesRBACPrincipal:
        cleaned = (name or "").strip()
        if not cleaned:
            raise InvalidKubernetesArgumentError("name", "required")
        pkind = (
            kind if isinstance(kind, RBACPrincipalKind) else RBACPrincipalKind(str(kind).upper())
        )
        ts = now or datetime.now(UTC)
        pid = principal_id or RBACPrincipalId.new()
        principal = cls(
            id=pid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            kind=pkind,
            name=cleaned[:253],
            namespace=(namespace or "")[:253],
            bindings=tuple(bindings or ()),
            roles=tuple(roles or ()),
            cluster_roles=tuple(cluster_roles or ()),
            trust_references=tuple(trust_references or ()),
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )
        principal._pending_events.append(
            RBACDiscovered(
                occurred_at=ts,
                organization_id=str(organization_id),
                cluster_id=cluster_id.value,
                principal_id=pid.value,
                principal_kind=pkind.value,
                principal_name=cleaned,
            )
        )
        return principal

    def inventory_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "name": self.name,
            "namespace": self.namespace,
            "roles": list(self.roles),
            "cluster_roles": list(self.cluster_roles),
            "bindings": [b.to_dict() for b in self.bindings],
            "trust_references": list(self.trust_references),
            "has_wildcard_verb": any("*" in b.verbs for b in self.bindings),
            "has_wildcard_resource": any("*" in b.resources for b in self.bindings),
            "bound_cluster_admin": "cluster-admin" in self.cluster_roles
            or any(b.role_ref_name == "cluster-admin" for b in self.bindings),
        }

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
