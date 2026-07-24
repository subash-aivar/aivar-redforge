from __future__ import annotations

import pytest

from cloud_security.domain.aggregates.cloud_organization import CloudOrganization
from cloud_security.domain.exceptions.domain_exceptions import (
    DuplicateAccountMembershipError,
    EmptyDisplayNameError,
    TenantMismatch,
)
from cloud_security.domain.value_objects.enums import CloudPlatformType
from cloud_security.domain.value_objects.identifiers import AccountId, OrganizationId, TenantId


def _create(**overrides) -> CloudOrganization:
    defaults = {
        "organization_id": OrganizationId.generate(),
        "tenant_id": TenantId.generate(),
        "platform_type": CloudPlatformType.AWS,
        "display_name": "root-org",
    }
    defaults.update(overrides)
    return CloudOrganization.create(**defaults)


def test_create_rejects_empty_display_name() -> None:
    with pytest.raises(EmptyDisplayNameError):
        _create(display_name="")


def test_add_account_appends_member() -> None:
    org = _create()
    account_id = AccountId.generate()

    org.add_account(org.tenant_id, account_id)

    assert org.member_account_ids == (account_id,)


def test_add_duplicate_account_raises() -> None:
    org = _create()
    account_id = AccountId.generate()
    org.add_account(org.tenant_id, account_id)

    with pytest.raises(DuplicateAccountMembershipError):
        org.add_account(org.tenant_id, account_id)


def test_add_account_wrong_tenant_raises() -> None:
    org = _create()
    with pytest.raises(TenantMismatch):
        org.add_account(TenantId.generate(), AccountId.generate())
