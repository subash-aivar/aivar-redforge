"""Tests for query dataclasses."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from uuid import uuid4

import pytest

from credential_vault.application.queries.audit_queries import ListAuditEntriesQuery
from credential_vault.application.queries.backend_queries import (
    GetVaultBackendQuery,
    ListVaultBackendsQuery,
)
from credential_vault.application.queries.credential_queries import (
    GetCredentialQuery,
    GetVersionQuery,
    ListCredentialsQuery,
    ListVersionsQuery,
)
from credential_vault.application.queries.policy_queries import (
    GetExpirationPolicyQuery,
    GetRotationPolicyQuery,
    ListExpirationPoliciesQuery,
    ListRotationPoliciesQuery,
)


def test_list_credentials_query_defaults() -> None:
    qry = ListCredentialsQuery(tenant_id=uuid4(), principal_id=uuid4())
    assert qry.limit == 100
    assert qry.offset == 0
    assert qry.states is None
    with pytest.raises(FrozenInstanceError):
        qry.limit = 1  # type: ignore[misc]
    assert not hasattr(qry, "__dict__")


def test_list_audit_entries_query_defaults() -> None:
    qry = ListAuditEntriesQuery(
        tenant_id=uuid4(),
        credential_id=uuid4(),
        principal_id=uuid4(),
    )
    assert qry.limit == 100
    assert qry.offset == 0
    assert qry.since is None
    assert qry.operations is None


@pytest.mark.parametrize(
    "cls",
    [
        GetCredentialQuery,
        ListCredentialsQuery,
        GetVersionQuery,
        ListVersionsQuery,
        GetRotationPolicyQuery,
        ListRotationPoliciesQuery,
        GetExpirationPolicyQuery,
        ListExpirationPoliciesQuery,
        GetVaultBackendQuery,
        ListVaultBackendsQuery,
        ListAuditEntriesQuery,
    ],
)
def test_query_classes_frozen_and_slotted(cls: type) -> None:
    assert cls.__dataclass_params__.frozen  # type: ignore[attr-defined]
    assert cls.__slots__
