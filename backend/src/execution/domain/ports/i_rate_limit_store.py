"""IRateLimitStore — atomic rate limit operations (Redis TIME + INCR / SET NX)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from execution.domain.value_objects.enums import RateLimitDecision
    from execution.domain.value_objects.execution_vos import RateLimitPolicy
    from execution.domain.value_objects.identifiers import TargetId, TenantId


class IRateLimitStore(ABC):
    @abstractmethod
    async def evaluate_and_consume(
        self,
        tenant_id: TenantId,
        target_id: TargetId,
        technique_category: str,
        policy: RateLimitPolicy,
        *,
        engagement_id: UUID,
        is_destruct: bool,
    ) -> RateLimitDecision:
        """
        Atomically evaluate rate limit using Redis TIME for timestamps.

        Destruct uses a separate SET NX engagement-scoped key (Hardening §4).
        """
        ...
