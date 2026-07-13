"""MFAFactor entity.

The encrypted TOTP secret is deliberately NOT a field on this entity —
it lives only in the infrastructure model
(`infrastructure/database/models/mfa.py`) and is decrypted only inside
`MFAService` at verification time. This entity carries lifecycle state
only, so any code holding a `MFAFactor` structurally cannot leak secret
material even by accident (e.g. via a DTO that does `dataclasses.asdict`).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime

from redforge.domain.mfa.exceptions import MFANotActiveError
from redforge.domain.mfa.value_objects import FactorStatus, FactorType


@dataclass(frozen=True, slots=True)
class MFAFactor:
    id: str
    user_id: str
    factor_type: FactorType
    status: FactorStatus
    created_at: datetime
    activated_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None

    @property
    def is_active(self) -> bool:
        return self.status == FactorStatus.ACTIVE

    def activate(self) -> MFAFactor:
        return replace(
            self, status=FactorStatus.ACTIVE, activated_at=datetime.now(UTC),
        )

    def revoke(self, revoked_by: str) -> MFAFactor:
        if not self.is_active:
            raise MFANotActiveError
        return replace(
            self,
            status=FactorStatus.REVOKED,
            revoked_at=datetime.now(UTC),
            revoked_by=revoked_by,
        )
