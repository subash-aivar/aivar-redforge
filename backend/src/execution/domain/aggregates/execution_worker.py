"""ExecutionWorker aggregate — registered distributed execution agent."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from execution.domain.events.pipeline_events import (
    ExecutionAssigned,
    ExecutionCompleted,
    ExecutionWorkerDecommissioned,
    ExecutionWorkerHealthDegraded,
    ExecutionWorkerHeartbeatReceived,
    ExecutionWorkerRegistered,
)
from execution.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    SignedManifestRequired,
    TenantMismatch,
    WorkerCapabilityInsufficient,
    WorkerDecommissioned,
    WorkerTrustInsufficient,
)
from execution.domain.value_objects.enums import (
    WorkerHealthStatus,
    trust_allows_impact,
)
from execution.domain.value_objects.execution_vos import SignedCapabilityManifest
from execution.domain.value_objects.identifiers import ExecutionWorkerId

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.events.base import BaseDomainEvent
    from execution.domain.value_objects.enums import WorkerTrustLevel, WorkerType
    from execution.domain.value_objects.execution_vos import TechniqueRef
    from execution.domain.value_objects.identifiers import OperatorId, TenantId


class ExecutionWorker:
    """Capabilities immutable after registration; LowTrust cannot run Exploit+."""

    __slots__ = (
        "_pending_events",
        "_version",
        "capabilities",
        "created_at",
        "decommissioned_at",
        "health_status",
        "last_heartbeat_at",
        "manifest_hash",
        "network_zone",
        "registered_at",
        "signer_operator_id",
        "tenant_id",
        "trust_level",
        "updated_at",
        "worker_id",
        "worker_type",
    )

    def __init__(
        self,
        worker_id: ExecutionWorkerId,
        tenant_id: TenantId,
        worker_type: WorkerType,
        capabilities: frozenset[str],
        trust_level: WorkerTrustLevel,
        health_status: WorkerHealthStatus,
        network_zone: str,
        manifest_hash: str,
        signer_operator_id: OperatorId,
        registered_at: datetime,
        created_at: datetime,
        updated_at: datetime,
        version: int,
        last_heartbeat_at: datetime | None = None,
        decommissioned_at: datetime | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.tenant_id = tenant_id
        self.worker_type = worker_type
        self.capabilities = capabilities
        self.trust_level = trust_level
        self.health_status = health_status
        self.network_zone = network_zone
        self.manifest_hash = manifest_hash
        self.signer_operator_id = signer_operator_id
        self.registered_at = registered_at
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self.last_heartbeat_at = last_heartbeat_at
        self.decommissioned_at = decommissioned_at
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> ExecutionWorkerId:
        return self.worker_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def register(
        cls,
        tenant_id: TenantId,
        worker_type: WorkerType,
        network_zone: str,
        manifest: SignedCapabilityManifest,
        now: datetime,
    ) -> ExecutionWorker:
        if manifest is None:
            raise SignedManifestRequired()
        if not network_zone.strip():
            raise InvalidArgument("network_zone", "must not be empty")
        # Manifest must be signed by redteam:admin authority (Hardening §5).
        # Signature presence is required; role of signer is enforced at application layer.
        worker_id = ExecutionWorkerId.generate()
        manifest_hash = manifest.manifest_hash()
        worker = cls(
            worker_id=worker_id,
            tenant_id=tenant_id,
            worker_type=worker_type,
            capabilities=manifest.techniques,
            trust_level=manifest.trust_level,
            health_status=WorkerHealthStatus.HEALTHY,
            network_zone=network_zone.strip(),
            manifest_hash=manifest_hash,
            signer_operator_id=manifest.signer_operator_id,
            registered_at=now,
            created_at=now,
            updated_at=now,
            version=0,
            last_heartbeat_at=now,
        )
        worker._emit(
            ExecutionWorkerRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(worker_id),
                aggregate_type="ExecutionWorker",
                worker_type=worker_type.value,
                trust_level=manifest.trust_level,
                network_zone=network_zone.strip(),
                manifest_hash=manifest_hash,
                signer_operator_id=str(manifest.signer_operator_id),
            )
        )
        return worker

    def record_heartbeat(
        self,
        tenant_id: TenantId,
        health_status: WorkerHealthStatus,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.health_status == WorkerHealthStatus.DECOMMISSIONED:
            raise WorkerDecommissioned(str(self.worker_id))
        previous = self.health_status
        self.health_status = health_status
        self.last_heartbeat_at = now
        self._mutate(now)
        self._emit(
            ExecutionWorkerHeartbeatReceived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.worker_id),
                aggregate_type="ExecutionWorker",
                health_status=health_status,
                heartbeat_at=now,
            )
        )
        if (
            health_status in (WorkerHealthStatus.DEGRADED, WorkerHealthStatus.UNAVAILABLE)
            and previous == WorkerHealthStatus.HEALTHY
        ):
            self._emit(
                ExecutionWorkerHealthDegraded(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.worker_id),
                    aggregate_type="ExecutionWorker",
                    previous_status=previous,
                    new_status=health_status,
                    heartbeat_at=now,
                )
            )

    def decommission(
        self,
        tenant_id: TenantId,
        authority_ref: OperatorId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.health_status == WorkerHealthStatus.DECOMMISSIONED:
            raise WorkerDecommissioned(str(self.worker_id))
        self.health_status = WorkerHealthStatus.DECOMMISSIONED
        self.decommissioned_at = now
        self._mutate(now)
        self._emit(
            ExecutionWorkerDecommissioned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.worker_id),
                aggregate_type="ExecutionWorker",
                authority_ref=str(authority_ref),
                decommissioned_at=now,
            )
        )

    def assert_can_execute(self, technique: TechniqueRef) -> None:
        if self.health_status == WorkerHealthStatus.DECOMMISSIONED:
            raise WorkerDecommissioned(str(self.worker_id))
        if technique.technique_id not in self.capabilities:
            raise WorkerCapabilityInsufficient(
                str(self.worker_id), technique.technique_id
            )
        if not trust_allows_impact(self.trust_level, technique.impact_ceiling):
            raise WorkerTrustInsufficient(
                str(self.worker_id),
                self.trust_level.value,
                technique.impact_ceiling.value,
            )

    def assign_action(
        self,
        tenant_id: TenantId,
        action_id: str,
        technique: TechniqueRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.assert_can_execute(technique)
        self._emit(
            ExecutionAssigned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.worker_id),
                aggregate_type="ExecutionWorker",
                action_id=action_id,
                worker_id=str(self.worker_id),
                technique_id=technique.technique_id,
            )
        )

    def report_execution_completed(
        self,
        tenant_id: TenantId,
        action_id: str,
        outcome: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._emit(
            ExecutionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.worker_id),
                aggregate_type="ExecutionWorker",
                action_id=action_id,
                worker_id=str(self.worker_id),
                outcome=outcome,
            )
        )

    def is_available(self) -> bool:
        return self.health_status in (
            WorkerHealthStatus.HEALTHY,
            WorkerHealthStatus.DEGRADED,
        )
