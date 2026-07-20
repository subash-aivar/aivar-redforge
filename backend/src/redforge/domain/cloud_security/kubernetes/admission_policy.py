"""KubernetesAdmissionPolicy aggregate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.kubernetes.entities import AdmissionViolation
from redforge.domain.cloud_security.kubernetes.events import (
    AdmissionPolicyEvaluated,
    KubernetesDomainEvent,
)
from redforge.domain.cloud_security.kubernetes.exceptions import InvalidKubernetesArgumentError
from redforge.domain.cloud_security.kubernetes.value_objects import AdmissionMode, ClusterId
from redforge.domain.cloud_security.value_objects import OrganizationId


@dataclass(frozen=True, slots=True)
class AdmissionPolicyId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def new(cls) -> AdmissionPolicyId:
        return cls(uuid4())

    @classmethod
    def from_str(cls, raw: str) -> AdmissionPolicyId:
        return cls(UUID(raw))


@dataclass
class KubernetesAdmissionPolicy:
    id: AdmissionPolicyId
    cluster_id: ClusterId
    organization_id: OrganizationId
    name: str
    mode: AdmissionMode
    controller: str
    rules: tuple[dict[str, object], ...]
    violations: tuple[AdmissionViolation, ...]
    evaluated_at: datetime | None
    created_at: datetime
    updated_at: datetime
    row_version: int = 1
    _pending_events: list[KubernetesDomainEvent] = field(default_factory=list, repr=False)

    @classmethod
    def register(
        cls,
        *,
        cluster_id: ClusterId,
        organization_id: OrganizationId,
        name: str,
        mode: AdmissionMode | str = AdmissionMode.UNKNOWN,
        controller: str = "",
        rules: list[dict[str, object]] | None = None,
        now: datetime | None = None,
        policy_id: AdmissionPolicyId | None = None,
    ) -> KubernetesAdmissionPolicy:
        cleaned = (name or "").strip()
        if not cleaned:
            raise InvalidKubernetesArgumentError("name", "required")
        amode = mode if isinstance(mode, AdmissionMode) else AdmissionMode(str(mode).upper())
        ts = now or datetime.now(UTC)
        pid = policy_id or AdmissionPolicyId.new()
        return cls(
            id=pid,
            cluster_id=cluster_id,
            organization_id=organization_id,
            name=cleaned[:253],
            mode=amode,
            controller=(controller or "")[:128],
            rules=tuple(rules or ()),
            violations=(),
            evaluated_at=None,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )

    def record_evaluation(
        self,
        *,
        violations: list[AdmissionViolation],
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        self.violations = tuple(violations)
        self.evaluated_at = ts
        self.updated_at = ts
        self.row_version += 1
        self._pending_events.append(
            AdmissionPolicyEvaluated(
                occurred_at=ts,
                organization_id=str(self.organization_id),
                cluster_id=self.cluster_id.value,
                policy_id=self.id.value,
                mode=self.mode.value,
                violation_count=len(violations),
            )
        )

    def pop_events(self) -> list[KubernetesDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
