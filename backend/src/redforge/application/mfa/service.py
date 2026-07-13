"""MFAService — TOTP enrollment, activation, verification, and revocation.

Security invariants enforced here (not just documented):
  - The plaintext TOTP secret is returned to the caller EXACTLY ONCE, at
    `begin_enrollment` — never again, not even to the same user.
  - `verify_and_activate` and `verify_code_for_active_factor` decrypt the
    stored secret only in-process, only long enough to call
    `pyotp.TOTP.verify()`; the plaintext is never logged, never stored,
    never included in any return value.
  - A user may hold at most one PENDING_ENROLLMENT and one ACTIVE factor
    at a time — beginning a new enrollment replaces any existing pending
    one (does not touch an already-ACTIVE factor; that must be revoked
    first, per MFAAlreadyActiveError).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pyotp

from redforge.domain.mfa.entity import MFAFactor
from redforge.domain.mfa.exceptions import (
    MFAAlreadyActiveError,
    MFAEnrollmentNotFoundError,
    MFAInvalidCodeError,
    MFANotActiveError,
)
from redforge.domain.mfa.value_objects import FactorStatus, FactorType
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.mfa_repository import (
    SqlAlchemyMFAFactorRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.infrastructure.mfa.secret_encryption import TOTPSecretCipher
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class MFAStatusDTO:
    user_id: str
    active: bool
    pending_enrollment: bool


@dataclass(frozen=True, slots=True)
class MFAEnrollmentBeginResult:
    enrollment_id: str
    secret: str  # plaintext — returned exactly once, this call only
    provisioning_uri: str


class MFAService:
    _ISSUER = "AIVAR RedForge"

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_key: str,
    ) -> None:
        self._session_factory = session_factory
        self._cipher = TOTPSecretCipher(encryption_key)

    async def get_status(self, user_id: str) -> MFAStatusDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMFAFactorRepository(uow.session)
            active = await repo.get_active_by_user(user_id)
            pending = await repo.get_pending_by_user(user_id)
        return MFAStatusDTO(
            user_id=user_id,
            active=active is not None,
            pending_enrollment=pending is not None,
        )

    async def begin_enrollment(
        self, user_id: str, account_email: str
    ) -> MFAEnrollmentBeginResult:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMFAFactorRepository(uow.session)

            existing_active = await repo.get_active_by_user(user_id)
            if existing_active is not None:
                raise MFAAlreadyActiveError

            # Replace any existing pending enrollment rather than leaving
            # it dangling — also required to avoid violating the partial
            # unique index on (user_id, status='pending_enrollment').
            await repo.delete_pending_by_user(user_id)

            secret = pyotp.random_base32()
            factor = MFAFactor(
                id=str(EntityId.generate()),
                user_id=user_id,
                factor_type=FactorType.TOTP,
                status=FactorStatus.PENDING_ENROLLMENT,
                created_at=datetime.now(UTC),
                activated_at=None,
                revoked_at=None,
                revoked_by=None,
            )
            ciphertext = self._cipher.encrypt(secret)
            await repo.save(factor, secret_ciphertext=ciphertext)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.MFA_ENROLLMENT_STARTED,
                    actor_id=user_id,
                    resource_type="mfa_factor",
                    resource_id=factor.id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()

        provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
            name=account_email, issuer_name=self._ISSUER
        )
        return MFAEnrollmentBeginResult(
            enrollment_id=factor.id, secret=secret, provisioning_uri=provisioning_uri,
        )

    async def verify_and_activate(self, user_id: str, enrollment_id: str, code: str) -> None:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMFAFactorRepository(uow.session)
            factor = await repo.get_by_id(enrollment_id)
            if (
                factor is None
                or factor.user_id != user_id
                or factor.status != FactorStatus.PENDING_ENROLLMENT
            ):
                raise MFAEnrollmentNotFoundError

            ciphertext = await repo.get_ciphertext(enrollment_id)
            assert ciphertext is not None
            secret = self._cipher.decrypt(ciphertext)
            totp = pyotp.TOTP(secret)
            if not totp.verify(code, valid_window=1):
                raise MFAInvalidCodeError

            activated = factor.activate()
            await repo.save(activated)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.MFA_FACTOR_ACTIVATED,
                    actor_id=user_id,
                    resource_type="mfa_factor",
                    resource_id=factor.id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()

    async def revoke(self, user_id: str, actor_id: str) -> None:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMFAFactorRepository(uow.session)
            factor = await repo.get_active_by_user(user_id)
            if factor is None:
                raise MFANotActiveError

            revoked = factor.revoke(actor_id)
            await repo.save(revoked)

            audit = PostgresPlatformAuditLog(uow.session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.MFA_FACTOR_REVOKED,
                    actor_id=actor_id,
                    resource_type="mfa_factor",
                    resource_id=factor.id,
                    metadata={"outcome": "success"},
                )
            )
            await uow.commit()

    async def verify_code_for_active_factor(self, user_id: str, code: str) -> bool:
        """Used by the privileged-assurance step-up flow. Returns False
        for: no active factor, invalid code — never raises, so callers
        can produce a uniform step-up-denied response without leaking
        whether the failure was "no factor" vs "wrong code."
        """
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyMFAFactorRepository(uow.session)
            factor = await repo.get_active_by_user(user_id)
            if factor is None:
                return False
            ciphertext = await repo.get_ciphertext(factor.id)
            if ciphertext is None:
                return False
            secret = self._cipher.decrypt(ciphertext)
        return pyotp.TOTP(secret).verify(code, valid_window=1)
