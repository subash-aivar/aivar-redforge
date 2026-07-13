"""PrivilegedAssuranceService — the step-up authentication layer.

Establishes a short-lived, server-side "did you just prove MFA" record
after a successful TOTP verification, and validates it on demand for
high-impact platform mutations (grant/revoke platform access, suspend/
reactivate users and organizations).

The token handed to the client carries no cryptographic content — it is
an opaque random ID whose validity is a live database lookup
(expires_at, user_id match), matching the same "read live, never trust
a long-lived claim" principle M1 applied to platform role resolution
(api/security.py's PlatformContext). This means revocation/expiry is
immediate and cannot be forged by tampering with client-held state.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.application.mfa.service import MFAService
from redforge.domain.mfa.exceptions import PrivilegedAssuranceRequiredError
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.mfa_repository import (
    SqlAlchemyPrivilegedAssuranceRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class AssuranceResult:
    assurance_token: str
    expires_at: str


class PrivilegedAssuranceService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        mfa_service: MFAService,
        ttl_seconds: int,
    ) -> None:
        self._session_factory = session_factory
        self._mfa_service = mfa_service
        self._ttl_seconds = ttl_seconds

    async def establish(self, user_id: str, totp_code: str) -> AssuranceResult:
        """Step-up: verify the current TOTP code against the user's
        ACTIVE factor, then mint a new assurance record. A wrong code or
        a missing active factor produce the identical audited-denial
        outcome — no information leak about which failed.
        """
        ok = await self._mfa_service.verify_code_for_active_factor(user_id, totp_code)

        async with SessionUnitOfWork(self._session_factory) as uow:
            audit = PostgresPlatformAuditLog(uow.session)
            if not ok:
                await audit.record(
                    AuditEntry(
                        action=AuditAction.MFA_ASSURANCE_DENIED,
                        actor_id=user_id,
                        resource_type="privileged_assurance",
                        resource_id=user_id,
                        metadata={"outcome": "denied"},
                    )
                )
                await uow.commit()
                raise PrivilegedAssuranceRequiredError

            repo = SqlAlchemyPrivilegedAssuranceRepository(uow.session)
            assurance_id = secrets.token_urlsafe(32)
            expires_at = await repo.create(assurance_id, user_id, self._ttl_seconds)

            await audit.record(
                AuditEntry(
                    action=AuditAction.MFA_ASSURANCE_ESTABLISHED,
                    actor_id=user_id,
                    resource_type="privileged_assurance",
                    resource_id=user_id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()

        return AssuranceResult(
            assurance_token=assurance_id, expires_at=expires_at.isoformat(),
        )

    async def validate(self, user_id: str, assurance_token: str | None) -> bool:
        if not assurance_token:
            return False
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyPrivilegedAssuranceRepository(uow.session)
            return await repo.is_valid(assurance_token, user_id)
