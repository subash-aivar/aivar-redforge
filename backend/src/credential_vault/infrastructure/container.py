"""CredentialVaultContainer — wires application services and adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from credential_vault.application.services.audit_query_service import AuditQueryService
from credential_vault.application.services.credential_application_service import (
    CredentialApplicationService,
)
from credential_vault.application.services.credential_query_service import CredentialQueryService
from credential_vault.application.services.expiration_policy_application_service import (
    ExpirationPolicyApplicationService,
)
from credential_vault.application.services.rotation_policy_application_service import (
    RotationPolicyApplicationService,
)
from credential_vault.application.services.vault_backend_application_service import (
    VaultBackendApplicationService,
)
from credential_vault.domain.ports.i_permission_port import IPermissionPort
from credential_vault.domain.services.access_control_policy import AccessControlPolicyService
from credential_vault.domain.services.break_glass_service import BreakGlassService
from credential_vault.domain.services.credential_resolver import CredentialResolverService
from credential_vault.domain.services.recovery_service import RecoveryService
from credential_vault.infrastructure.encryption.aes_gcm_encryption_adapter import (
    AesGcmEncryptionAdapter,
)
from credential_vault.infrastructure.encryption.local_kms_adapter import LocalAesKwKmsAdapter
from credential_vault.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)
from credential_vault.infrastructure.metrics_wrapper import MetricsCredentialApplicationService
from credential_vault.infrastructure.persistence.repositories.pg_audit_log_repository import (
    PgAuditLogRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_credential_repository import (
    PgCredentialRepository,
)
from credential_vault.infrastructure.persistence.repositories.pg_credential_version_repository import (  # noqa: E501
    PgCredentialVersionRepository,
)
from credential_vault.infrastructure.persistence.unit_of_work import (
    make_credential_vault_uow_factory,
)
from credential_vault.infrastructure.platform_adapters.approval_workflow_adapter import (
    ApprovalWorkflowAdapter,
)
from credential_vault.infrastructure.platform_adapters.rbac_permission_adapter import (
    RbacPermissionAdapter,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.domain.ports.i_approval_port import IApprovalPort
    from credential_vault.domain.ports.i_encryption_port import IEncryptionPort
    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
    from credential_vault.domain.value_objects.identifiers import (
        CredentialId,
        PrincipalId,
        TenantId,
    )
    from redforge.application.rbac import EffectiveAccessService


class CredentialVaultContainer:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        encryption_adapter: IEncryptionPort | None = None,
        kms_adapter: IKeyManagementPort | None = None,
        permission_adapter: IPermissionPort | None = None,
        approval_adapter: IApprovalPort | None = None,
        event_publisher: IEventPublisher | None = None,
        effective_access_svc: EffectiveAccessService | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.encryption_adapter = encryption_adapter or AesGcmEncryptionAdapter()
        self.kms_adapter = kms_adapter or LocalAesKwKmsAdapter.from_env()
        self.event_publisher = event_publisher or StructlogEventPublisher()

        if permission_adapter is not None:
            self.permission_adapter = permission_adapter
        elif effective_access_svc is not None:
            self.permission_adapter = RbacPermissionAdapter(effective_access_svc)
        else:
            self.permission_adapter = _OpenPermissionAdapter()

        self.approval_adapter = approval_adapter or ApprovalWorkflowAdapter(session_factory)

        uow_factory = make_credential_vault_uow_factory(
            session_factory,
            self.encryption_adapter,
            self.kms_adapter,
        )

        access_control = AccessControlPolicyService(self.permission_adapter)
        break_glass = BreakGlassService(self.approval_adapter)
        recovery = RecoveryService(self.approval_adapter)
        resolver = CredentialResolverService(
            self.encryption_adapter,
            self.kms_adapter,
            self.permission_adapter,
            access_control,
            break_glass,
        )

        inner_credential_service = CredentialApplicationService(
            uow_factory,
            self.event_publisher,
            self.kms_adapter,
            self.encryption_adapter,
            self.permission_adapter,
            self.approval_adapter,
            access_control,
            break_glass,
            recovery,
            resolver,
        )
        self.credential_service = MetricsCredentialApplicationService(inner_credential_service)
        self._inner_credential_service = inner_credential_service

        self.rotation_policy_service = RotationPolicyApplicationService(
            uow_factory, self.event_publisher, self.permission_adapter
        )
        self.expiration_policy_service = ExpirationPolicyApplicationService(
            uow_factory, self.event_publisher, self.permission_adapter
        )
        self.vault_backend_service = VaultBackendApplicationService(
            uow_factory, self.event_publisher, self.permission_adapter
        )

    def make_credential_query_service(self, session: AsyncSession) -> CredentialQueryService:
        return CredentialQueryService(
            PgCredentialRepository(session),
            PgCredentialVersionRepository(session),
            self.permission_adapter,
        )

    def make_audit_query_service(self, session: AsyncSession) -> AuditQueryService:
        return AuditQueryService(
            PgAuditLogRepository(session),
            PgCredentialRepository(session),
            self.permission_adapter,
        )


class _OpenPermissionAdapter(IPermissionPort):
    async def has_permission(
        self,
        principal_id: PrincipalId,
        credential_id: CredentialId,
        permission: str,
        tenant_id: TenantId,
    ) -> bool:
        _ = principal_id, credential_id, permission, tenant_id
        return True
