"""Domain services for engagement authorization and scope verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from engagement.domain.value_objects.engagement_vos import (
    compute_scope_hash,
    serialize_target_scope,
)
from engagement.domain.value_objects.enums import (
    AuthorizationDecision,
    EngagementState,
    KillSwitchState,
)

if TYPE_CHECKING:
    from datetime import datetime

    from engagement.domain.aggregates.engagement import Engagement
    from engagement.domain.value_objects.engagement_vos import (
        AttackTechniqueRef,
        ScopeHash,
        TargetRef,
    )


@dataclass(frozen=True, slots=True)
class AuthorizationEvaluation:
    decision: AuthorizationDecision
    reason: str


class EngagementAuthorizationService:
    """Evaluates target/technique/timing against engagement constraints."""

    def evaluate(
        self,
        engagement: Engagement,
        target: TargetRef,
        technique: AttackTechniqueRef,
        proposed_start_time: datetime,
    ) -> AuthorizationEvaluation:
        if engagement.state != EngagementState.ACTIVE:
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                f"engagement state is {engagement.state.value}, not Active",
            )
        if engagement.kill_switch_state != KillSwitchState.ARMED:
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                f"kill switch is {engagement.kill_switch_state.value}",
            )
        if not engagement.allows_new_operations():
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                "engagement does not allow new operations",
            )
        if not engagement.scope.contains(target.asset_id):
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                "target is outside engagement TargetScope",
            )
        if technique.technique_id not in engagement.allowed_technique_ids():
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                "technique not authorized by RulesOfEngagement",
            )
        if engagement.window is None:
            return AuthorizationEvaluation(
                AuthorizationDecision.DEFERRED,
                "engagement window not configured",
            )
        if not engagement.window.contains(proposed_start_time):
            return AuthorizationEvaluation(
                AuthorizationDecision.FORBIDDEN,
                "proposed start time outside EngagementWindow",
            )
        return AuthorizationEvaluation(
            AuthorizationDecision.AUTHORIZED,
            "authorized",
        )


class ScopeVerificationService:
    """Verifies TargetRef against signed ScopeHash + current engagement version."""

    def compute_current_hash(
        self,
        engagement: Engagement,
        approval_timestamp: datetime,
    ) -> ScopeHash:
        serialized = serialize_target_scope(engagement.scope.targets)
        return compute_scope_hash(
            serialized,
            engagement.engagement_version,
            approval_timestamp,
        )

    def verify_target_in_scope(
        self,
        engagement: Engagement,
        target: TargetRef,
    ) -> bool:
        if engagement.scope_hash is None:
            return False
        return engagement.scope.contains(target.asset_id)

    def verify_scope_hash(
        self,
        engagement: Engagement,
        expected: ScopeHash,
        approval_timestamp: datetime,
    ) -> bool:
        """Verify hash against current engagement version (HARDENING §3)."""
        current = self.compute_current_hash(engagement, approval_timestamp)
        return current.value == expected.value == (
            engagement.scope_hash.value if engagement.scope_hash else ""
        )
