"""IDetectionRuleRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_rule import DetectionRule
    from detection.domain.value_objects.enums import RuleLifecycleState
    from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
    from detection.domain.value_objects.keys import RuleKey


class IDetectionRuleRepository(ABC):
    @abstractmethod
    async def save(self, rule: DetectionRule) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None: ...

    @abstractmethod
    async def find_by_key(
        self, key: RuleKey, tenant_id: TenantId
    ) -> DetectionRule | None: ...

    @abstractmethod
    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]: ...

    @abstractmethod
    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]: ...

    @abstractmethod
    async def find_by_telemetry_source(
        self, tenant_id: TenantId, source_id: str
    ) -> list[DetectionRule]: ...

    @abstractmethod
    async def find_by_attack_technique(
        self, tenant_id: TenantId, technique_id: str
    ) -> list[DetectionRule]: ...

    @abstractmethod
    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionRule]: ...
