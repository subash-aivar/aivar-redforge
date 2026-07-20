"""IDetectionFindingRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_finding import DetectionFinding
    from detection.domain.value_objects.enums import FindingState
    from detection.domain.value_objects.execution_finding import FindingKey
    from detection.domain.value_objects.identifiers import (
        DetectionFindingId,
        DetectionRuleId,
        TenantId,
    )
    from detection.domain.value_objects.telemetry import TimeWindow


class IDetectionFindingRepository(ABC):
    @abstractmethod
    async def save(self, finding: DetectionFinding) -> None: ...

    @abstractmethod
    async def find_by_id(
        self,
        finding_id: DetectionFindingId,
        tenant_id: TenantId,
    ) -> DetectionFinding | None: ...

    @abstractmethod
    async def find_by_key(
        self,
        key: FindingKey,
        tenant_id: TenantId,
    ) -> DetectionFinding | None:
        """Dedup lookup — must be indexed for low-latency."""

    @abstractmethod
    async def find_open_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        states: list[FindingState] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]: ...

    @abstractmethod
    async def find_by_asset(
        self,
        asset_id: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]: ...

    @abstractmethod
    async def find_by_rule(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId,
        window: TimeWindow | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]: ...

    @abstractmethod
    async def find_by_attack_technique(
        self,
        technique_id: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionFinding]: ...
