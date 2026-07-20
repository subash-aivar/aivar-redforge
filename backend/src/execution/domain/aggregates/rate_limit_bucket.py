"""RateLimitBucket — domain policy for execution rate limiting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from execution.domain.value_objects.enums import ImpactCeiling, RateLimitDecision
from execution.domain.value_objects.execution_vos import RateLimitPolicy
from execution.domain.value_objects.identifiers import RateLimitBucketId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from execution.domain.value_objects.identifiers import TargetId, TenantId


@dataclass(frozen=True, slots=True)
class RateLimitEvaluationInput:
    tenant_id: TenantId
    target_id: TargetId
    technique_category: str
    impact_ceiling: ImpactCeiling
    engagement_id: UUID
    policy: RateLimitPolicy


class RateLimitBucket:
    """
    Domain-side rate limit policy evaluator.

    Atomic increment / Destruct SET NX are performed by the rate limit store
    (Redis). This aggregate encodes hard-coded Destruct invariant (Hardening §4).
    """

    __slots__ = (
        "bucket_id",
        "current_window_count",
        "policy",
        "target_id",
        "technique_category",
        "tenant_id",
        "window_start",
    )

    def __init__(
        self,
        bucket_id: RateLimitBucketId,
        tenant_id: TenantId,
        target_id: TargetId,
        technique_category: str,
        policy: RateLimitPolicy,
        current_window_count: int,
        window_start: datetime | None,
    ) -> None:
        self.bucket_id = bucket_id
        self.tenant_id = tenant_id
        self.target_id = target_id
        self.technique_category = technique_category
        self.policy = policy
        self.current_window_count = current_window_count
        self.window_start = window_start

    @staticmethod
    def destruct_hard_limit() -> int:
        """Hard-coded max 1 Destruct action per engagement per target."""
        return 1

    @staticmethod
    def decide_from_count(
        count_after_increment: int,
        max_executions: int,
        *,
        is_destruct: bool,
        destruct_already_used: bool,
    ) -> RateLimitDecision:
        if is_destruct:
            if destruct_already_used:
                return RateLimitDecision.FORBIDDEN
            # First Destruct attempt: the store must SET NX; if NX failed,
            # destruct_already_used is True. count path still applies for non-destruct.
            if count_after_increment > RateLimitBucket.destruct_hard_limit():
                return RateLimitDecision.FORBIDDEN
            return RateLimitDecision.PERMITTED
        if count_after_increment > max_executions:
            return RateLimitDecision.THROTTLED
        return RateLimitDecision.PERMITTED

    @classmethod
    def bucket_key_parts(
        cls,
        tenant_id: TenantId,
        target_id: TargetId,
        technique_category: str,
    ) -> tuple[str, str, str]:
        return (str(tenant_id), str(target_id), technique_category)

    @classmethod
    def destruct_nx_key(cls, engagement_id: UUID, target_id: TargetId) -> str:
        return f"destruct:{engagement_id}:{target_id}"
