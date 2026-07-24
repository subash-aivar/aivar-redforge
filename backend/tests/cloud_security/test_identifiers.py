from __future__ import annotations

import pytest

from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    AssetId,
    OrganizationId,
    ProjectId,
    ProviderId,
    RegionId,
    ResourceId,
    SubscriptionId,
    TenantId,
)


def test_tenant_id_is_entity_id_reused() -> None:
    from redforge.shared.identifiers import EntityId

    assert TenantId is EntityId


@pytest.mark.parametrize("cls", [AccountId, AssetId, OrganizationId, ProviderId])
def test_uuid_backed_ids_generate_unique(cls) -> None:
    a, b = cls.generate(), cls.generate()
    assert a != b
    assert str(a) != str(b)


@pytest.mark.parametrize("cls", [SubscriptionId, ProjectId, ResourceId, RegionId])
def test_string_backed_ids_reject_empty(cls) -> None:
    with pytest.raises(EmptyIdentifierError):
        cls("")
    with pytest.raises(EmptyIdentifierError):
        cls("   ")


def test_string_backed_id_str_roundtrip() -> None:
    assert str(SubscriptionId("sub-123")) == "sub-123"
    assert str(ProjectId("my-project")) == "my-project"
    assert str(ResourceId("res-1")) == "res-1"
    assert str(RegionId("us-east-1")) == "us-east-1"
