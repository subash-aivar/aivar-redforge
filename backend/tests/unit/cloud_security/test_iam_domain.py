"""Unit tests for M26 Phase 3 CloudIAMPrincipal domain, normalizer, and adapters."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from ulid import ULID

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import PolicyAttachment, TrustRelationship
from redforge.domain.cloud_security.events import (
    CrossAccountTrustDiscovered,
    IAMPrincipalDeleted,
    IAMPrincipalDisabled,
    IAMPrincipalDiscovered,
    IAMPrincipalUpdated,
)
from redforge.domain.cloud_security.ports import RawIAMPrincipal
from redforge.domain.cloud_security.value_objects import (
    CloudAccountType,
    CloudProviderType,
    CredentialRef,
    IAMPrincipalType,
    OrganizationId,
    PolicyAttachmentType,
    PrivilegeLevel,
)
from redforge.infrastructure.cloud_security.adapters.aws import (
    AWSCloudProviderAdapter,
    StaticAwsDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.azure import (
    AzureCloudProviderAdapter,
    StaticAzureDiscoveryClient,
)
from redforge.infrastructure.cloud_security.adapters.gcp import (
    GCPCloudProviderAdapter,
    StaticGcpDiscoveryClient,
)
from redforge.infrastructure.cloud_security.normalizers import normalize_raw_iam_principal


def _org() -> OrganizationId:
    return OrganizationId(str(ULID()))


def _account(org: OrganizationId) -> CloudAccount:
    provider = CloudProvider.register(
        organization_id=org,
        provider_type=CloudProviderType.AWS,
        display_name="AWS",
    )
    return CloudAccount.register(
        cloud_provider_id=provider.id,
        organization_id=org,
        external_id="111122223333",
        display_name="Acct",
        account_type=CloudAccountType.STANDALONE,
        credential_ref=CredentialRef(reference_id="cred-1"),
    )


def test_discover_emits_discovered_and_cross_account_trust() -> None:
    org = _org()
    account = _account(org)
    trust = TrustRelationship.create(
        trusted_principal_provider_id="arn:aws:iam::999999999999:root",
        trust_type="AssumeRole",
        is_cross_account=True,
    )
    principal = CloudIAMPrincipal.discover(
        cloud_account_id=account.id,
        organization_id=org,
        principal_type=IAMPrincipalType.ROLE,
        provider_id="arn:aws:iam::111122223333:role/cross",
        display_name="cross",
        trust_relationships=[trust],
    )
    events = principal.pop_events()
    assert any(isinstance(e, IAMPrincipalDiscovered) for e in events)
    assert any(isinstance(e, CrossAccountTrustDiscovered) for e in events)
    assert principal.privilege_level is PrivilegeLevel.NONE


def test_apply_discovery_update_and_new_cross_account() -> None:
    org = _org()
    account = _account(org)
    principal = CloudIAMPrincipal.discover(
        cloud_account_id=account.id,
        organization_id=org,
        principal_type=IAMPrincipalType.USER,
        provider_id="arn:aws:iam::111122223333:user/alice",
        display_name="alice",
    )
    principal.pop_events()
    trust = TrustRelationship.create(
        trusted_principal_provider_id="arn:aws:iam::444455556666:user/bob",
        trust_type="AssumeRole",
        is_cross_account=True,
    )
    principal.apply_discovery(
        display_name="alice-updated",
        attached_policies=[
            PolicyAttachment.create(
                policy_provider_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
                policy_name="ReadOnlyAccess",
                attachment_type=PolicyAttachmentType.MANAGED,
            )
        ],
        trust_relationships=[trust],
        is_federated=False,
        is_human=True,
        last_activity_at=datetime.now(UTC),
    )
    events = principal.pop_events()
    assert any(isinstance(e, IAMPrincipalUpdated) for e in events)
    assert any(isinstance(e, CrossAccountTrustDiscovered) for e in events)
    assert principal.display_name == "alice-updated"


def test_disable_and_delete() -> None:
    org = _org()
    account = _account(org)
    principal = CloudIAMPrincipal.discover(
        cloud_account_id=account.id,
        organization_id=org,
        principal_type=IAMPrincipalType.GROUP,
        provider_id="arn:aws:iam::111122223333:group/devs",
        display_name="devs",
    )
    principal.pop_events()
    principal.disable()
    assert any(isinstance(e, IAMPrincipalDisabled) for e in principal.pop_events())
    principal.mark_deleted()
    assert any(isinstance(e, IAMPrincipalDeleted) for e in principal.pop_events())
    assert principal.is_deleted is True


def test_normalize_aws_role_cross_account_trust() -> None:
    raw = RawIAMPrincipal(
        provider_id="arn:aws:iam::111122223333:role/admin",
        principal_type="ROLE",
        display_name="admin",
        payload={
            "provider_id": "arn:aws:iam::111122223333:role/admin",
            "account_id": "111122223333",
            "attached_policies": [
                {
                    "arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "name": "AdministratorAccess",
                    "attachment_type": "MANAGED",
                }
            ],
            "trust_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
        },
    )
    draft = normalize_raw_iam_principal(raw)
    assert draft.principal_type is IAMPrincipalType.ROLE
    assert len(draft.attached_policies) == 1
    assert draft.trust_relationships[0].is_cross_account is True


def test_normalize_azure_role_assignments() -> None:
    raw = RawIAMPrincipal(
        provider_id=str(uuid4()),
        principal_type="USER",
        display_name="user@contoso.com",
        payload={
            "account_id": "sub-1",
            "role_assignments": [
                {
                    "role_definition_id": "/providers/Microsoft.Authorization/roleDefinitions/reader",
                    "role_name": "Reader",
                }
            ],
            "is_human": True,
        },
    )
    draft = normalize_raw_iam_principal(raw)
    assert draft.is_human is True
    assert draft.attached_policies[0].attachment_type is PolicyAttachmentType.ROLE_ASSIGNMENT


def test_normalize_gcp_iam_bindings() -> None:
    raw = RawIAMPrincipal(
        provider_id="projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com",
        principal_type="SERVICE_ACCOUNT",
        display_name="sa",
        payload={
            "account_id": "demo",
            "iam_bindings": [{"role": "roles/viewer", "members": ["serviceAccount:sa@demo.iam.gserviceaccount.com"]}],
        },
    )
    draft = normalize_raw_iam_principal(raw)
    assert draft.principal_type is IAMPrincipalType.SERVICE_ACCOUNT
    assert draft.attached_policies[0].attachment_type is PolicyAttachmentType.PREDEFINED_ROLE


@pytest.mark.asyncio
async def test_static_aws_adapter_yields_iam() -> None:
    org = _org()
    account = _account(org)
    client = StaticAwsDiscoveryClient(
        identity={"Account": "111122223333", "Arn": "", "UserId": ""},
        iam_users=[
            {
                "provider_id": "arn:aws:iam::111122223333:user/alice",
                "display_name": "alice",
                "account_id": "111122223333",
                "attached_policies": [],
                "is_human": True,
            }
        ],
        iam_roles=[
            {
                "provider_id": "arn:aws:iam::111122223333:role/app",
                "display_name": "app",
                "account_id": "111122223333",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            }
        ],
        managed_policies=[
            {
                "provider_id": "arn:aws:iam::111122223333:policy/Custom",
                "display_name": "Custom",
                "account_id": "111122223333",
            }
        ],
    )
    adapter = AWSCloudProviderAdapter(client)
    items = [p async for p in adapter.list_iam_principals(account)]
    types = {p.principal_type for p in items}
    assert types == {"USER", "ROLE", "POLICY"}
    assert all("provider_id" in p.payload for p in items)


@pytest.mark.asyncio
async def test_static_azure_and_gcp_adapters_yield_iam() -> None:
    org = _org()
    azure_account = CloudAccount.register(
        cloud_provider_id=CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.AZURE,
            display_name="Azure",
        ).id,
        organization_id=org,
        external_id="sub-1",
        display_name="Sub",
        account_type=CloudAccountType.STANDALONE,
        credential_ref=CredentialRef(reference_id="az"),
    )
    user_id = str(uuid4())
    azure = AzureCloudProviderAdapter(
        StaticAzureDiscoveryClient(
            iam_users=[{"provider_id": user_id, "display_name": "alice"}],
            role_assignments=[
                {
                    "principal_id": user_id,
                    "role_definition_id": "/roles/reader",
                    "role_name": "Reader",
                }
            ],
        )
    )
    azure_items = [p async for p in azure.list_iam_principals(azure_account)]
    assert len(azure_items) == 1
    assert azure_items[0].payload["role_assignments"]

    gcp_account = CloudAccount.register(
        cloud_provider_id=CloudProvider.register(
            organization_id=org,
            provider_type=CloudProviderType.GCP,
            display_name="GCP",
        ).id,
        organization_id=org,
        external_id="demo",
        display_name="Demo",
        account_type=CloudAccountType.STANDALONE,
        credential_ref=CredentialRef(reference_id="gcp"),
    )
    gcp = GCPCloudProviderAdapter(
        StaticGcpDiscoveryClient(
            service_accounts=[
                {
                    "provider_id": "projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com",
                    "display_name": "sa",
                    "email": "sa@demo.iam.gserviceaccount.com",
                }
            ],
            iam_bindings=[
                {
                    "role": "roles/viewer",
                    "members": ["serviceAccount:sa@demo.iam.gserviceaccount.com"],
                }
            ],
            iam_roles=[{"provider_id": "roles/custom.viewer", "display_name": "custom.viewer"}],
        )
    )
    gcp_items = [p async for p in gcp.list_iam_principals(gcp_account)]
    assert {p.principal_type for p in gcp_items} == {"SERVICE_ACCOUNT", "POLICY"}
