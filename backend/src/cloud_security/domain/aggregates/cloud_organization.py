"""CloudOrganization aggregate — a provider-level grouping of
`CloudAccount`s (an AWS Organization, an Azure management group, a GCP
resource-manager organization) (M45A).

Consistency boundary: an organization owns *membership* (which
accounts belong to it), never the member accounts' own connection or
discovery state — those remain each `CloudAccount`'s own aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import (
    DuplicateAccountMembershipError,
    EmptyDisplayNameError,
    TenantMismatch,
)

if TYPE_CHECKING:
    from cloud_security.domain.value_objects.enums import CloudPlatformType
    from cloud_security.domain.value_objects.identifiers import AccountId, OrganizationId, TenantId


class CloudOrganization:
    __slots__ = (
        "display_name",
        "member_account_ids",
        "organization_id",
        "platform_type",
        "tenant_id",
    )

    def __init__(
        self,
        organization_id: OrganizationId,
        tenant_id: TenantId,
        platform_type: CloudPlatformType,
        display_name: str,
        member_account_ids: tuple[AccountId, ...] = (),
    ) -> None:
        self.organization_id = organization_id
        self.tenant_id = tenant_id
        self.platform_type = platform_type
        self.display_name = display_name
        self.member_account_ids = member_account_ids

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        organization_id: OrganizationId,
        tenant_id: TenantId,
        platform_type: CloudPlatformType,
        display_name: str,
    ) -> CloudOrganization:
        if not display_name.strip():
            raise EmptyDisplayNameError()
        return cls(
            organization_id=organization_id,
            tenant_id=tenant_id,
            platform_type=platform_type,
            display_name=display_name,
        )

    def add_account(self, tenant_id: TenantId, account_id: AccountId) -> None:
        self._assert_tenant(tenant_id)
        if account_id in self.member_account_ids:
            raise DuplicateAccountMembershipError(account_id)
        self.member_account_ids = (*self.member_account_ids, account_id)
