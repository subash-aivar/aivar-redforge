"""CredentialIntegrationService — the canonical entrypoint for every
Cloud Security Credential Integration operation (M45D).

Associates `CloudAccount` → `CloudProviderRegistration` →
`CloudCredentialReference` — never storing, encrypting, or resolving
secret material. `CredentialAssociation` remains the single aggregate;
this service only validates input, delegates to the aggregate's own
lifecycle methods, and returns immutable DTOs carrying reference
metadata only. `attach`/`replace`/`detach` operate on
caller-supplied `CloudAccount`/`CloudProviderRegistration` instances
(no persistence for either — the same "no repository in this
milestone" discipline every prior `cloud_security` service follows);
`validate_credential_reference` delegates to an optional, still-
unimplemented `ICredentialReferenceProvider` — this milestone never
assumes a reference is valid by default. This service holds no state
between calls beyond its injected `ICredentialReferenceRegistry` (and
optional validation provider), so it stays stateless."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from cloud_security.application.dtos.credential_outcomes import (
    BatchCredentialFailure,
    BatchCredentialResult,
    BatchCredentialStatus,
    CredentialAttached,
    CredentialDetached,
    CredentialReplaced,
    CredentialValidated,
    CredentialValidationStatus,
)
from cloud_security.application.dtos.credential_reference_record import (
    CredentialReferenceRecord,
)
from cloud_security.application.exceptions import (
    AccountMismatchError,
    CredentialAssociationNotFoundError,
    ProviderMismatchError,
)
from cloud_security.application.services import credential_validation
from cloud_security.domain.aggregates.credential_association import CredentialAssociation
from cloud_security.domain.value_objects.enums import CredentialAssociationStatus
from cloud_security.domain.value_objects.identifiers import CredentialAssociationId

if TYPE_CHECKING:
    from cloud_security.application.commands.credential_commands import (
        AttachCredentialCommand,
        BatchCredentialCommand,
        DetachCredentialCommand,
        ReplaceCredentialCommand,
        RotateCredentialReferenceCommand,
        ValidateCredentialReferenceCommand,
    )
    from cloud_security.application.ports.i_credential_reference_provider import (
        ICredentialReferenceProvider,
    )
    from cloud_security.application.ports.i_credential_reference_registry import (
        ICredentialReferenceRegistry,
    )
    from cloud_security.application.queries.credential_queries import (
        GetCredentialReferenceQuery,
        ListAccountsWithoutCredentialsQuery,
        ListCredentialReferencesQuery,
    )
    from cloud_security.domain.aggregates.cloud_account import CloudAccount
    from cloud_security.domain.aggregates.cloud_provider_registration import (
        CloudProviderRegistration,
    )
    from cloud_security.domain.value_objects.identifiers import AccountId, TenantId


def _to_record(association: CredentialAssociation) -> CredentialReferenceRecord:
    previous = association.previous_reference
    return CredentialReferenceRecord(
        association_id=str(association.association_id),
        tenant_id=str(association.tenant_id),
        account_id=str(association.account_id),
        provider_id=str(association.provider_id),
        active_credential_id=association.active_reference.credential_id,
        active_credential_type=association.active_reference.credential_type,
        previous_credential_id=previous.credential_id if previous is not None else None,
        previous_credential_type=previous.credential_type if previous is not None else None,
        status=association.status,
        attached_at=association.attached_at,
        rotated_at=association.rotated_at,
    )


class CredentialIntegrationService:
    def __init__(
        self,
        registry: ICredentialReferenceRegistry,
        credential_provider: ICredentialReferenceProvider | None = None,
    ) -> None:
        self._registry = registry
        self._credential_provider = credential_provider

    # -- commands ------------------------------------------------------

    def attach_credential(
        self,
        cmd: AttachCredentialCommand,
        account: CloudAccount,
        provider: CloudProviderRegistration,
    ) -> CredentialAttached:
        credential_validation.validate_account_reference(cmd.account_id)
        credential_validation.validate_provider_reference(cmd.provider_id)
        if account.account_id != cmd.account_id:
            raise AccountMismatchError("attach cmd.account_id does not match the given account")
        if provider.provider_id != cmd.provider_id:
            raise ProviderMismatchError("attach cmd.provider_id does not match the given provider")

        association = CredentialAssociation.attach(
            association_id=CredentialAssociationId.generate(),
            tenant_id=cmd.tenant_id,
            account_id=cmd.account_id,
            provider_id=cmd.provider_id,
            reference=cmd.reference,
            now=datetime.now(UTC),
        )
        self._registry.register(association)
        return CredentialAttached(record=_to_record(association))

    def register_batch(
        self,
        cmd: BatchCredentialCommand,
        accounts: dict[str, CloudAccount],
        providers: dict[str, CloudProviderRegistration],
    ) -> BatchCredentialResult:
        credential_validation.validate_batch_not_empty(cmd.commands)

        attached: list[CredentialAttached] = []
        failures: list[BatchCredentialFailure] = []
        for index, attach_cmd in enumerate(cmd.commands):
            try:
                account = accounts[str(attach_cmd.account_id)]
                provider = providers[str(attach_cmd.provider_id)]
                attached.append(self.attach_credential(attach_cmd, account, provider))
            except Exception as exc:
                failures.append(
                    BatchCredentialFailure(
                        index=index, error_type=type(exc).__name__, message=str(exc)
                    )
                )

        if not failures:
            status = BatchCredentialStatus.SUCCEEDED
        elif not attached:
            status = BatchCredentialStatus.FAILED
        else:
            status = BatchCredentialStatus.PARTIALLY_SUCCEEDED

        return BatchCredentialResult(
            status=status, attached=tuple(attached), failures=tuple(failures)
        )

    def replace_credential(
        self,
        tenant_id: TenantId,
        association_id: CredentialAssociationId,
        cmd: ReplaceCredentialCommand,
    ) -> CredentialReplaced:
        association = self._require(tenant_id, association_id)
        association.replace(cmd.tenant_id, cmd.reference, datetime.now(UTC))
        return CredentialReplaced(record=_to_record(association))

    def rotate_credential_reference(
        self,
        tenant_id: TenantId,
        association_id: CredentialAssociationId,
        cmd: RotateCredentialReferenceCommand,
    ) -> CredentialReplaced:
        association = self._require(tenant_id, association_id)
        association.replace(cmd.tenant_id, cmd.reference, datetime.now(UTC))
        return CredentialReplaced(record=_to_record(association))

    def detach_credential(
        self,
        tenant_id: TenantId,
        association_id: CredentialAssociationId,
        cmd: DetachCredentialCommand,
    ) -> CredentialDetached:
        association = self._require(tenant_id, association_id)
        association.detach(cmd.tenant_id, datetime.now(UTC))
        self._registry.release(association)
        return CredentialDetached(
            association_id=str(association.association_id), tenant_id=str(association.tenant_id)
        )

    def validate_credential_reference(
        self,
        tenant_id: TenantId,
        association_id: CredentialAssociationId,
        cmd: ValidateCredentialReferenceCommand,
    ) -> CredentialValidated:
        association = self._require(cmd.tenant_id, association_id)
        if self._credential_provider is None:
            return CredentialValidated(
                association_id=str(association_id),
                status=CredentialValidationStatus.UNVERIFIABLE,
                reason="no ICredentialReferenceProvider is registered",
            )
        try:
            is_valid = self._credential_provider.validate(association.active_reference)
        except Exception as exc:
            return CredentialValidated(
                association_id=str(association_id),
                status=CredentialValidationStatus.INVALID,
                reason=str(exc),
            )
        status = (
            CredentialValidationStatus.VALID if is_valid else CredentialValidationStatus.INVALID
        )
        return CredentialValidated(association_id=str(association_id), status=status)

    def _require(
        self, tenant_id: TenantId, association_id: CredentialAssociationId
    ) -> CredentialAssociation:
        association = self._registry.get(tenant_id, association_id)
        if association is None:
            raise CredentialAssociationNotFoundError(association_id)
        return association

    # -- queries ---------------------------------------------------------

    def get_credential_reference(
        self, query: GetCredentialReferenceQuery
    ) -> CredentialReferenceRecord | None:
        association = self._registry.get(query.tenant_id, query.association_id)
        return _to_record(association) if association is not None else None

    def list_credential_references(
        self, query: ListCredentialReferencesQuery
    ) -> tuple[CredentialReferenceRecord, ...]:
        return tuple(
            _to_record(a) for a in self._registry.list(query.tenant_id, account_id=query.account_id)
        )

    def list_accounts_without_credentials(
        self, query: ListAccountsWithoutCredentialsQuery
    ) -> tuple[AccountId, ...]:
        without: list[AccountId] = []
        for account_id in query.account_ids:
            associations = self._registry.list(query.tenant_id, account_id=account_id)
            has_active = any(a.status == CredentialAssociationStatus.ACTIVE for a in associations)
            if not has_active:
                without.append(account_id)
        return tuple(without)
