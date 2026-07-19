"""IUnitOfWork — transactional boundary for Credential Vault application services."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from credential_vault.domain.repositories.i_audit_log_repository import (
        IAuditLogRepository,
    )
    from credential_vault.domain.repositories.i_credential_repository import (
        ICredentialRepository,
    )
    from credential_vault.domain.repositories.i_credential_version_repository import (
        ICredentialVersionRepository,
    )
    from credential_vault.domain.repositories.i_expiration_policy_repository import (
        IExpirationPolicyRepository,
    )
    from credential_vault.domain.repositories.i_rotation_policy_repository import (
        IRotationPolicyRepository,
    )
    from credential_vault.domain.repositories.i_vault_backend_repository import (
        IVaultBackendRepository,
    )


class IUnitOfWork(ABC):
    """
    Unit of Work coordinating repository access within a single transaction.

    Subclasses must call ``super().__init__()`` so ``_committed`` is initialized.
    Concrete ``commit()`` implementations must call ``super().commit()`` (or set
    ``self._committed = True``) after a successful commit.
    """

    credentials: ICredentialRepository
    versions: ICredentialVersionRepository
    rotation_policies: IRotationPolicyRepository
    expiration_policies: IExpirationPolicyRepository
    vault_backends: IVaultBackendRepository
    audit_logs: IAuditLogRepository

    def __init__(self) -> None:
        self._committed = False

    async def __aenter__(self) -> IUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    @abstractmethod
    async def commit(self) -> None:
        """Persist all changes in the unit of work."""
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None:
        """Discard all uncommitted changes in the unit of work."""
