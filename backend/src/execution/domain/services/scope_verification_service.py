"""ScopeVerificationService — cryptographic scope check via engagement ACL."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.value_objects.enums import ScopeVerificationStatus

if TYPE_CHECKING:
    from execution.domain.ports.i_engagement_scope_port import IEngagementScopePort
    from execution.domain.value_objects.execution_vos import (
        ScopeSnapshot,
        TargetRef,
        TechniqueRef,
    )
    from execution.domain.value_objects.identifiers import EngagementId, TenantId


class ScopeVerificationService:
    """
    Verifies target is in authorized set AND presented scope_hash matches
    current engagement version (Hardening §3).
    """

    def __init__(self, engagement_scope: IEngagementScopePort) -> None:
        self._engagement_scope = engagement_scope

    async def verify(
        self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        target_ref: TargetRef,
        technique_ref: TechniqueRef,
        *,
        presented_scope_hash: str | None = None,
        presented_engagement_version: int | None = None,
    ) -> tuple[ScopeVerificationStatus, ScopeSnapshot]:
        snapshot = await self._engagement_scope.get_scope_snapshot(
            engagement_id, tenant_id
        )
        if snapshot.degraded and not snapshot.authorized_target_ids:
            # Degraded empty scope cannot authorize any target.
            return ScopeVerificationStatus.FAILED, snapshot

        if target_ref.target_id.value not in snapshot.authorized_target_ids:
            return ScopeVerificationStatus.FAILED, snapshot

        if (
            snapshot.allowed_techniques
            and technique_ref.technique_id not in snapshot.allowed_techniques
        ):
            return ScopeVerificationStatus.FAILED, snapshot

        if presented_scope_hash is not None and presented_scope_hash != snapshot.scope_hash:
            return ScopeVerificationStatus.FAILED, snapshot

        if (
            presented_engagement_version is not None
            and presented_engagement_version != snapshot.engagement_version
        ):
            return ScopeVerificationStatus.FAILED, snapshot

        # Always verify hash is bound to current engagement version.
        if not snapshot.scope_hash:
            return ScopeVerificationStatus.FAILED, snapshot

        return ScopeVerificationStatus.VERIFIED, snapshot
