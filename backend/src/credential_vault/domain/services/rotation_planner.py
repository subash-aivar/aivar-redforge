"""RotationPlannerService — pure domain rotation scheduling logic."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from credential_vault.domain.exceptions.domain_exceptions import NoPolicyAttached
from credential_vault.domain.value_objects.states import CredentialState

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.credential import Credential
    from credential_vault.domain.aggregates.rotation_policy import RotationPolicy


class RotationPlannerService:
    """
    Pure domain logic: given a Credential + RotationPolicy, determines
    whether rotation is due and computes the next rotation timestamp.
    No I/O. No scheduling. No queue interaction.
    """

    def is_rotation_due(
        self,
        credential: Credential,
        policy: RotationPolicy,
        current_version_created_at: datetime,
        now: datetime,
    ) -> bool:
        if credential.state != CredentialState.ACTIVE:
            return False
        if not policy.auto_rotate:
            return False
        if policy.interval_days is None:
            return False
        elapsed = now - current_version_created_at
        return elapsed >= timedelta(days=policy.interval_days)

    def next_rotation_at(
        self,
        current_version_created_at: datetime,
        policy: RotationPolicy,
    ) -> datetime:
        if policy.interval_days is None:
            raise NoPolicyAttached(
                credential_id=policy.policy_id,
                policy_type="rotation",
            )
        return current_version_created_at + timedelta(days=policy.interval_days)

    def should_warn(
        self,
        credential: Credential,
        policy: RotationPolicy,
        current_version_created_at: datetime,
        now: datetime,
    ) -> bool:
        if credential.state != CredentialState.ACTIVE:
            return False
        if policy.interval_days is None:
            return False
        next_at = self.next_rotation_at(current_version_created_at, policy)
        if now >= next_at:
            return False
        days_until = (next_at - now).days
        return days_until <= policy.notify_days_before
