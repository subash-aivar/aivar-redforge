"""SQLAlchemy implementation of UserRepository."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redforge.domain.identity.entities import User
from redforge.domain.identity.value_objects import Email, PasswordHash, UserStatus
from redforge.infrastructure.database.models.user import UserModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class SqlAlchemyUserRepository:
    """Async SQLAlchemy implementation of UserRepository."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, user_id: EntityId) -> User | None:
        stmt = select(UserModel).where(UserModel.id == str(user_id))
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return self._to_entity(model)

    async def get_by_email(self, email: Email) -> User | None:
        stmt = select(UserModel).where(UserModel.email == str(email))
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            return None
        return self._to_entity(model)

    async def email_exists(self, email: Email) -> bool:
        stmt = select(UserModel.id).where(UserModel.email == str(email))
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def save(self, user: User) -> None:
        model = UserModel(
            id=str(user.id),
            email=str(user.email),
            display_name=user.display_name,
            password_hash=user.password_hash.value if user.password_hash else None,
            status=str(user.status),
            created_at=user.timestamps.created_at,
            updated_at=user.timestamps.updated_at,
        )
        await self._session.merge(model)
        await self._session.flush()

    @staticmethod
    def _to_entity(model: UserModel) -> User:
        return User(
            id=EntityId.from_string(model.id),
            email=Email(model.email),
            display_name=model.display_name,
            password_hash=PasswordHash(model.password_hash) if model.password_hash else None,
            status=UserStatus(model.status),
            timestamps=AuditTimestamps(
                created_at=_ensure_utc(model.created_at),
                updated_at=_ensure_utc(model.updated_at),
            ),
        )
