"""AIDiscoveryScanRun — bookkeeping aggregate for discovery batches."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_supply_chain.domain.events.supply_chain_events import (
    AIDiscoveryScanCompleted,
    UnmatchedAIServiceDiscovered,
)
from ai_supply_chain.domain.exceptions.domain_exceptions import TenantMismatch
from ai_supply_chain.domain.value_objects.enums import DiscoveryScanRunState

if TYPE_CHECKING:
    from datetime import datetime

    from ai_supply_chain.domain.events.base import BaseDomainEvent
    from ai_supply_chain.domain.value_objects.enums import DiscoverySourceType
    from ai_supply_chain.domain.value_objects.identifiers import (
        AIDiscoveryScanRunId,
        TenantId,
    )
    from ai_supply_chain.domain.value_objects.supply_chain_vos import DiscoveredAIService


class AIDiscoveryScanRun:
    __slots__ = (
        "_pending_events",
        "api_calls_used",
        "discovered",
        "ended_at",
        "failed_partitions",
        "partial",
        "scan_run_id",
        "sources",
        "started_at",
        "state",
        "tenant_id",
        "unmatched",
    )

    def __init__(
        self,
        scan_run_id: AIDiscoveryScanRunId,
        tenant_id: TenantId,
        sources: list[DiscoverySourceType],
        state: DiscoveryScanRunState,
        started_at: datetime,
        ended_at: datetime | None,
        discovered: list[DiscoveredAIService],
        unmatched: list[DiscoveredAIService],
        failed_partitions: list[str],
        api_calls_used: int,
        partial: bool,
    ) -> None:
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.sources = list(sources)
        self.state = state
        self.started_at = started_at
        self.ended_at = ended_at
        self.discovered = list(discovered)
        self.unmatched = list(unmatched)
        self.failed_partitions = list(failed_partitions)
        self.api_calls_used = api_calls_used
        self.partial = partial
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def start(
        cls,
        scan_run_id: AIDiscoveryScanRunId,
        tenant_id: TenantId,
        sources: list[DiscoverySourceType],
        now: datetime,
    ) -> AIDiscoveryScanRun:
        return cls(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            sources=sources,
            state=DiscoveryScanRunState.RUNNING,
            started_at=now,
            ended_at=None,
            discovered=[],
            unmatched=[],
            failed_partitions=[],
            api_calls_used=0,
            partial=False,
        )

    def record_discovery(
        self, tenant_id: TenantId, service: DiscoveredAIService, *, matched: bool
    ) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        self.discovered.append(service)
        self.api_calls_used += 1
        if not matched:
            self.unmatched.append(service)

    def record_partition_failure(self, partition: str) -> None:
        self.failed_partitions.append(partition)
        self.partial = True

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)
        self.ended_at = now
        if self.failed_partitions:
            self.state = DiscoveryScanRunState.PARTIAL
            self.partial = True
        else:
            self.state = DiscoveryScanRunState.COMPLETED
        for svc in self.unmatched:
            self._pending_events.append(
                UnmatchedAIServiceDiscovered(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.scan_run_id),
                    aggregate_type="AIDiscoveryScanRun",
                    discovery_source=svc.discovery_source.value,
                    cloud_account=svc.cloud_account,
                    resource_identifier=svc.resource_identifier,
                    service_type=svc.service_type,
                    region=svc.region,
                )
            )
        self._pending_events.append(
            AIDiscoveryScanCompleted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.scan_run_id),
                aggregate_type="AIDiscoveryScanRun",
                scan_run_id=str(self.scan_run_id),
                state=self.state.value,
                discovered_count=len(self.discovered),
                unmatched_count=len(self.unmatched),
                partial=self.partial,
            )
        )
