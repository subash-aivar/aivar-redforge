"""Unit of Work — owns session lifecycle, commit, and rollback.

One request → One UnitOfWork → Many repositories → Single commit.

Repositories receive the shared session from UnitOfWork.
Only UnitOfWork calls commit() or rollback().
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.infrastructure.database.repositories.attacks.repository import (
    SqlAlchemyAttackRepository,
)
from redforge.infrastructure.database.repositories.evidence.repository import (
    SqlAlchemyEvidenceRepository,
)
from redforge.infrastructure.database.repositories.findings.repository import (
    SqlAlchemyFindingRepository,
)
from redforge.infrastructure.database.repositories.payloads.repository import (
    SqlAlchemyPayloadTemplateRepository,
)
from redforge.infrastructure.database.repositories.policies.repository import (
    SqlAlchemyPolicyRepository,
)
from redforge.infrastructure.database.repositories.providers.repository import (
    SqlAlchemyProviderRepository,
)
from redforge.infrastructure.database.repositories.validations.repository import (
    SqlAlchemyValidationRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


class SessionUnitOfWork:
    """Minimal UoW that provides a session and owns commit/rollback.

    Used by domain-entity services (auth, organizations, ai_targets) that
    instantiate their own specialized repos using the session.

    Usage:
        async with SessionUnitOfWork(session_factory) as uow:
            repo = SqlAlchemyOrgRepository(uow.session)
            await repo.save(entity)
            await uow.commit()
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> SessionUnitOfWork:
        self._session = self._session_factory()
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if exc_type is not None:
            await self.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None

    @property
    def session(self) -> AsyncSession:
        """Expose the active session for repo construction."""
        assert self._session is not None, "UoW must be used as async context manager"
        return self._session

    async def commit(self) -> None:
        """Commit the current transaction."""
        if self._session is not None:
            await self._session.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        if self._session is not None:
            await self._session.rollback()


class UnitOfWork:
    """Manages a single database transaction across multiple repositories.

    Usage:
        async with UnitOfWork(session_factory) as uow:
            await uow.validations.save(data)
            await uow.findings.save(data)
            await uow.commit()
        # rollback happens automatically if commit() is not called

    All repositories share the same session. If any operation fails,
    the entire transaction rolls back — ACID guaranteed.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> UnitOfWork:
        self._session = self._session_factory()
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if exc_type is not None:
            await self.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def commit(self) -> None:
        """Commit the current transaction. Only UnitOfWork calls this."""
        if self._session is not None:
            await self._session.commit()

    async def rollback(self) -> None:
        """Rollback the current transaction. Only UnitOfWork calls this."""
        if self._session is not None:
            await self._session.rollback()

    # ─── Repository Accessors ─────────────────────────────────────────────

    @property
    def validations(self) -> SqlAlchemyValidationRepository:
        assert self._session is not None
        return SqlAlchemyValidationRepository(self._session)

    @property
    def findings(self) -> SqlAlchemyFindingRepository:
        assert self._session is not None
        return SqlAlchemyFindingRepository(self._session)

    @property
    def evidence(self) -> SqlAlchemyEvidenceRepository:
        assert self._session is not None
        return SqlAlchemyEvidenceRepository(self._session)

    @property
    def attacks(self) -> SqlAlchemyAttackRepository:
        assert self._session is not None
        return SqlAlchemyAttackRepository(self._session)

    @property
    def policies(self) -> SqlAlchemyPolicyRepository:
        assert self._session is not None
        return SqlAlchemyPolicyRepository(self._session)

    @property
    def providers(self) -> SqlAlchemyProviderRepository:
        assert self._session is not None
        return SqlAlchemyProviderRepository(self._session)

    @property
    def payloads(self) -> SqlAlchemyPayloadTemplateRepository:
        assert self._session is not None
        return SqlAlchemyPayloadTemplateRepository(self._session)
