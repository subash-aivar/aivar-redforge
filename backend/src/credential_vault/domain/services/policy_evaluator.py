"""PolicyEvaluatorService — expiration evaluation pure domain logic."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
    from credential_vault.domain.entities.credential_version import CredentialVersion


class PolicyEvaluatorService:
    """
    Evaluates expiration policies against credential versions.
    No I/O. No clock side-effects — receives `now` as parameter.
    """

    def is_version_expired(
        self,
        version: CredentialVersion,
        policy: ExpirationPolicy | None,
        now: datetime,
    ) -> bool:
        if version.expires_at is not None and now >= version.expires_at:
            return True
        if policy is None or not policy.hard_expire:
            return False
        return (now - version.created_at).days >= policy.ttl_days

    def should_warn_expiration(
        self,
        version: CredentialVersion,
        policy: ExpirationPolicy,
        now: datetime,
    ) -> bool:
        if self.is_version_expired(version, policy, now):
            return False
        expiry = version.expires_at
        if expiry is None:
            expiry = self.compute_version_expiry(version.created_at, policy)
        days_remaining = (expiry - now).days
        return days_remaining <= policy.warn_days_before

    def compute_version_expiry(
        self,
        created_at: datetime,
        policy: ExpirationPolicy,
    ) -> datetime:
        return created_at + timedelta(days=policy.ttl_days)
