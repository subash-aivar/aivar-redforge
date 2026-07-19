"""CredentialVaultUnitOfWork — transactional boundary for repositories."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.application.ports.i_unit_of_work import IUnitOfWork
from credential_vault.infrastructure.persistence.repositories.pg_audit_log_repository import (
    PgAuditLogRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_credential_repository import (
    PgCredentialRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_credential_version_repository import (  # noqa: E501
    PgCredentialVersionRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_expiration_policy_repository import (  # noqa: E501
    PgExpirationPolicyRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_rotation_policy_repository import (
    PgRotationPolicyRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_vault_backend_repository import (
    PgVaultBackendRepository,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort


class CredentialVaultUnitOfWork(IUnitOfWork):
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_port: IEncryptionPort,
        kms_port: IKeyManagementPort,
    ) -> None:
        super().__init__()
        self._session_factory = session_factory
        self._encryption_port = encryption_port
        self._kms_port = kms_port
        self._session: AsyncSession | None = None

    async def __aenter__(self) -> CredentialVaultUnitOfWork:
        self._session = self._session_factory()
        assert self._session is not None
        self.credentials = PgCredentialRepository(self._session)
        self.versions = PgCredentialVersionRepository(self._session)
        self.rotation_policies = PgRotationPolicyRepository(self._session)
        self.expiration_policies = PgExpirationPolicyRepository(self._session)
        self.vault_backends = PgVaultBackendRepository(
            self._session, self._encryption_port, self._kms_port
        )
        self.audit_logs = PgAuditLogRepository(self._session)
        return self

    async def commit(self) -> None:
        if self._session is None:
            return
        await self._session.commit()
        self._committed = True

    async def rollback(self) -> None:
        if self._session is not None:
            await self._session.rollback()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed and self._session is not None:
            await self._session.rollback()
        if self._session is not None:
            await self._session.close()
            self._session = None


def make_credential_vault_uow_factory(
    session_factory: async_sessionmaker[AsyncSession],
    encryption_port: IEncryptionPort,
    kms_port: IKeyManagementPort,
) -> Callable[[], CredentialVaultUnitOfWork]:
    def factory() -> CredentialVaultUnitOfWork:
        return CredentialVaultUnitOfWork(session_factory, encryption_port, kms_port)

    return factory
