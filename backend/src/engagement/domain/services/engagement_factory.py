"""EngagementFactory — creates Draft engagements with default ApprovalPolicy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from engagement.domain.aggregates.engagement import Engagement
from engagement.domain.value_objects.engagement_vos import ApprovalPolicy
from engagement.domain.value_objects.enums import QuorumType
from engagement.domain.value_objects.identifiers import EngagementId

if TYPE_CHECKING:
    from datetime import datetime

    from engagement.domain.value_objects.enums import EngagementClassification
    from engagement.domain.value_objects.identifiers import TenantId


class EngagementFactory:
    """Creates a new Engagement with tenant governance defaults."""

    DEFAULT_REQUIRED_APPROVERS = 2
    DEFAULT_APPROVER_ROLES = ("redteam:approver", "redteam:ciso")

    def create(
        self,
        tenant_id: TenantId,
        name: str,
        classification: EngagementClassification,
        owner_id: str,
        now: datetime,
        *,
        approval_policy: ApprovalPolicy | None = None,
        engagement_id: EngagementId | None = None,
    ) -> Engagement:
        policy = approval_policy or ApprovalPolicy(
            required_approver_count=self.DEFAULT_REQUIRED_APPROVERS,
            required_approver_roles=list(self.DEFAULT_APPROVER_ROLES),
            quorum_type=QuorumType.MAJORITY,
        )
        return Engagement.create(
            engagement_id=engagement_id or EngagementId.generate(),
            tenant_id=tenant_id,
            name=name,
            classification=classification,
            owner_id=owner_id,
            approval_policy=policy,
            now=now,
        )
