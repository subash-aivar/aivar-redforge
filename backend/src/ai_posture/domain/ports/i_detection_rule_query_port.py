"""IDetectionRuleQueryPort — ACL to M28 for threat profile completeness."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.enums import AIThreatCategory
    from ai_posture.domain.value_objects.identifiers import TenantId


class IDetectionRuleQueryPort(ABC):
    @abstractmethod
    async def has_rules_for_category(
        self, category: AIThreatCategory, tenant_id: TenantId
    ) -> bool: ...
