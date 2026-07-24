from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from integration_hub.application.commands.connector_commands import RegisterConnector
from integration_hub.application.commands.discovery_commands import RunDiscovery
from integration_hub.application.exceptions import ApplicationValidationError
from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.value_objects.discovery import (
    AssetCategory,
    AssetIdentity,
    AssetRelationship,
    ChangeType,
    DiscoveryPage,
    RelationshipType,
    VendorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId
from integration_hub.infrastructure.container import IntegrationHubContainer
from integration_hub.infrastructure.normalizers.anthropic_normalizer import (
    AnthropicModelNormalizer,
)
from integration_hub.infrastructure.normalizers.azure_openai_normalizer import (
    AzureOpenAIModelNormalizer,
)
from integration_hub.infrastructure.normalizers.openai_normalizer import OpenAIModelNormalizer


def _tenant() -> EntityId:
    return EntityId.generate()


def _connector() -> ConnectorId:
    return ConnectorId.generate()


class _FakeCredentialService:
    async def resolve_credential(self, cmd):
        class _R:
            plaintext_secret = b"sk-test-123"

        return _R()


def test_fingerprint_idempotent() -> None:
    tenant = _tenant()
    identity1 = AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant))
    identity2 = AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant))
    assert identity1.fingerprint == identity2.fingerprint
    identity3 = AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-3.5", tenant_id=str(tenant))
    assert identity1.fingerprint != identity3.fingerprint


def test_openai_normalizer() -> None:
    tenant = _tenant()
    connector_id = _connector()
    normalizer = OpenAIModelNormalizer()
    asset = normalizer.normalize(
        {"id": "gpt-4", "object": "model", "owned_by": "openai", "created": 123},
        tenant_id=tenant,
        connector_id=connector_id,
    )
    assert asset.name == "gpt-4"
    assert asset.vendor == VendorType.OPENAI
    assert asset.category == AssetCategory.AI_MODEL
    assert asset.owner == "openai"


def test_anthropic_normalizer() -> None:
    tenant = _tenant()
    connector_id = _connector()
    normalizer = AnthropicModelNormalizer()
    asset = normalizer.normalize(
        {"id": "claude-opus-4", "display_name": "Claude Opus 4", "type": "model"},
        tenant_id=tenant,
        connector_id=connector_id,
    )
    assert asset.name == "Claude Opus 4"
    assert asset.vendor == VendorType.ANTHROPIC


def test_azure_openai_normalizer() -> None:
    tenant = _tenant()
    connector_id = _connector()
    normalizer = AzureOpenAIModelNormalizer()
    asset = normalizer.normalize(
        {"id": "gpt-4-deployment", "capabilities": {"chat_completion": True}},
        tenant_id=tenant,
        connector_id=connector_id,
        region="eastus",
    )
    assert asset.category == AssetCategory.AI_DEPLOYMENT
    assert asset.region == "eastus"


def test_relationship_add_remove() -> None:
    tenant = _tenant()
    connector_id = _connector()
    asset = DiscoveredAsset.discover(
        tenant,
        connector_id,
        AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant)),
        name="gpt-4",
        category=AssetCategory.AI_MODEL,
        vendor=VendorType.OPENAI,
    )
    asset.pop_events()
    rel = AssetRelationship(relationship_type=RelationshipType.MEMBER_OF, target_external_id="org-1")
    asset.add_relationship(rel)
    assert len(asset.relationships) == 1
    events = asset.pop_events()
    assert any(e.__class__.__name__ == "AssetRelationshipAdded" for e in events)
    asset.remove_relationship(RelationshipType.MEMBER_OF, "org-1")
    assert len(asset.relationships) == 0
    events = asset.pop_events()
    assert any(e.__class__.__name__ == "AssetRelationshipRemoved" for e in events)


def test_change_classification_modified() -> None:
    tenant = _tenant()
    connector_id = _connector()
    asset = DiscoveredAsset.discover(
        tenant,
        connector_id,
        AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant)),
        name="gpt-4",
        category=AssetCategory.AI_MODEL,
        vendor=VendorType.OPENAI,
        configuration={"created": 1},
    )
    asset.pop_events()
    change = asset.apply_sync(
        name="gpt-4",
        region=None,
        owner=None,
        tags={},
        metadata={},
        configuration={"created": 2},
    )
    assert change == ChangeType.CONFIGURATION_DRIFT
    events = asset.pop_events()
    assert any(e.__class__.__name__ == "AssetModified" for e in events)
    assert any(e.__class__.__name__ == "AssetDriftDetected" for e in events)


def test_change_classification_moved() -> None:
    tenant = _tenant()
    connector_id = _connector()
    asset = DiscoveredAsset.discover(
        tenant,
        connector_id,
        AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant)),
        name="gpt-4",
        category=AssetCategory.AI_MODEL,
        vendor=VendorType.OPENAI,
        owner="openai",
    )
    asset.pop_events()
    change = asset.apply_sync(
        name="gpt-4", region=None, owner="new-owner", tags={}, metadata={}, configuration={}
    )
    assert change == ChangeType.MOVED


@pytest.mark.asyncio
async def test_repository_round_trip() -> None:
    from integration_hub.infrastructure.persistence.discovery_in_memory_repositories import (
        InMemoryDiscoveredAssetRepository,
    )

    tenant = _tenant()
    connector_id = _connector()
    repo = InMemoryDiscoveredAssetRepository()
    asset = DiscoveredAsset.discover(
        tenant,
        connector_id,
        AssetIdentity(vendor=VendorType.OPENAI, external_id="gpt-4", tenant_id=str(tenant)),
        name="gpt-4",
        category=AssetCategory.AI_MODEL,
        vendor=VendorType.OPENAI,
    )
    await repo.save(asset, tenant)
    fetched = await repo.get(asset.asset_id, tenant)
    assert fetched is not None
    assert fetched.name == "gpt-4"
    by_fp = await repo.get_by_fingerprint(asset.identity.fingerprint, tenant)
    assert by_fp is not None
    all_for_tenant = await repo.find_all_for_tenant(tenant, vendor="OPENAI")
    assert len(all_for_tenant) == 1
    await repo.delete(asset.asset_id, tenant)
    assert await repo.get(asset.asset_id, tenant) is None


@pytest.mark.asyncio
async def test_run_discovery_creates_and_updates_assets() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id: UUID = uuid4()
    reg_dto = await container.app.register(
        RegisterConnector(
            tenant_id,
            "openai",
            "my-openai",
            str(uuid4()),
            "API_KEY",
            "tester",
            ("integration:admin",),
        )
    )
    connector_id = UUID(reg_dto.connector_id)

    plugin = container.catalog.get("openai")
    object.__setattr__(
        plugin,
        "discover",
        AsyncMock(
            return_value=DiscoveryPage(
                items=[{"id": "gpt-4", "object": "model", "owned_by": "openai"}],
                next_cursor=None,
                has_more=False,
            )
        ),
    )

    run_dto = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert run_dto.status == "COMPLETED"
    assert run_dto.items_created == 1
    assert run_dto.items_discovered == 1

    assets = await container.discovery.list_assets(tenant_id, ("integration:admin",))
    assert len(assets) == 1
    assert assets[0].name == "gpt-4"

    # Second run with same payload -> no changes classified as created/updated.
    run_dto_2 = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert run_dto_2.items_created == 0
    assert run_dto_2.items_updated == 0

    # Third run with modified payload -> updated.
    plugin.discover.return_value = DiscoveryPage(
        items=[{"id": "gpt-4", "object": "model", "owned_by": "openai-v2"}],
        next_cursor=None,
        has_more=False,
    )
    run_dto_3 = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert run_dto_3.items_updated == 1

    # Fourth run with no items -> asset deleted.
    plugin.discover.return_value = DiscoveryPage(items=[], next_cursor=None, has_more=False)
    run_dto_4 = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert run_dto_4.items_deleted == 1
    assets_after = await container.discovery.list_assets(tenant_id, ("integration:admin",))
    assert len(assets_after) == 0

    history = await container.discovery.list_sync_runs(
        tenant_id, connector_id, ("integration:admin",)
    )
    assert len(history) == 4


@pytest.mark.asyncio
async def test_run_discovery_rejects_non_discoverable_connector() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id: UUID = uuid4()
    reg_dto = await container.app.register(
        RegisterConnector(
            tenant_id,
            "ITSM_JIRA",
            "jira",
            str(uuid4()),
            "API_KEY",
            "tester",
            ("integration:admin",),
        )
    )
    connector_id = UUID(reg_dto.connector_id)
    with pytest.raises(ApplicationValidationError):
        await container.discovery.run_discovery(
            RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
        )
