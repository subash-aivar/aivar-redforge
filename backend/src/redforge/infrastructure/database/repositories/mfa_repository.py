"""SQLAlchemy repository for MFA factors and privileged assurance records."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from redforge.domain.mfa.entity import MFAFactor
from redforge.domain.mfa.value_objects import FactorStatus, FactorType
from redforge.infrastructure.database.models.mfa import (
    MFAFactorModel,
    PlatformPrivilegedAssuranceModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _ensure_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _to_entity(model: MFAFactorModel) -> MFAFactor:
    return MFAFactor(
        id=model.id,
        user_id=model.user_id,
        factor_type=FactorType(model.factor_type),
        status=FactorStatus(model.status),
        created_at=_ensure_utc(model.created_at),
        activated_at=_ensure_utc(model.activated_at) if model.activated_at else None,
        revoked_at=_ensure_utc(model.revoked_at) if model.revoked_at else None,
        revoked_by=model.revoked_by,
    )


class SqlAlchemyMFAFactorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, factor_id: str) -> MFAFactor | None:
        result = await self._session.execute(
            select(MFAFactorModel).where(MFAFactorModel.id == factor_id)
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model else None

    async def get_active_by_user(self, user_id: str) -> MFAFactor | None:
        result = await self._session.execute(
            select(MFAFactorModel).where(
                MFAFactorModel.user_id == user_id,
                MFAFactorModel.status == FactorStatus.ACTIVE.value,
            )
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model else None

    async def get_pending_by_user(self, user_id: str) -> MFAFactor | None:
        result = await self._session.execute(
            select(MFAFactorModel).where(
                MFAFactorModel.user_id == user_id,
                MFAFactorModel.status == FactorStatus.PENDING_ENROLLMENT.value,
            )
        )
        model = result.scalar_one_or_none()
        return _to_entity(model) if model else None

    async def delete_pending_by_user(self, user_id: str) -> None:
        """Discards any existing PENDING_ENROLLMENT row for this user.
        Called before starting a new enrollment so re-enrolling never
        violates the partial-unique "one pending per user" index — a
        pending, never-activated factor carries no security value worth
        preserving once superseded.
        """
        await self._session.execute(
            delete(MFAFactorModel).where(
                MFAFactorModel.user_id == user_id,
                MFAFactorModel.status == FactorStatus.PENDING_ENROLLMENT.value,
            )
        )
        await self._session.flush()

    async def get_ciphertext(self, factor_id: str) -> str | None:
        """The ONLY method that returns encrypted secret material — used
        exclusively by MFAService at verification time, never surfaced
        through any DTO or API response.
        """
        result = await self._session.execute(
            select(MFAFactorModel.secret_ciphertext).where(MFAFactorModel.id == factor_id)
        )
        row = result.first()
        return row[0] if row else None

    async def save(self, factor: MFAFactor, secret_ciphertext: str | None = None) -> None:
        existing = await self._session.get(MFAFactorModel, factor.id)
        if existing is not None:
            existing.status = factor.status.value
            existing.activated_at = factor.activated_at
            existing.revoked_at = factor.revoked_at
            existing.revoked_by = factor.revoked_by
            await self._session.flush()
            return

        if secret_ciphertext is None:
            raise ValueError("secret_ciphertext required when creating a new MFAFactor")
        model = MFAFactorModel(
            id=factor.id,
            user_id=factor.user_id,
            factor_type=factor.factor_type.value,
            status=factor.status.value,
            secret_ciphertext=secret_ciphertext,
            created_at=factor.created_at,
            activated_at=factor.activated_at,
            revoked_at=factor.revoked_at,
            revoked_by=factor.revoked_by,
        )
        self._session.add(model)
        await self._session.flush()


class SqlAlchemyPrivilegedAssuranceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(self, assurance_id: str, user_id: str, ttl_seconds: int) -> datetime:
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)
        model = PlatformPrivilegedAssuranceModel(
            id=assurance_id,
            user_id=user_id,
            established_at=now,
            expires_at=expires_at,
            revoked_at=None,
        )
        self._session.add(model)
        await self._session.flush()
        return expires_at

    async def is_valid(self, assurance_id: str, user_id: str) -> bool:
        result = await self._session.execute(
            select(PlatformPrivilegedAssuranceModel).where(
                PlatformPrivilegedAssuranceModel.id == assurance_id,
                PlatformPrivilegedAssuranceModel.user_id == user_id,
            )
        )
        model = result.scalar_one_or_none()
        if model is None or model.revoked_at is not None:
            return False
        expires_at = _ensure_utc(model.expires_at)
        return expires_at > datetime.now(UTC)
