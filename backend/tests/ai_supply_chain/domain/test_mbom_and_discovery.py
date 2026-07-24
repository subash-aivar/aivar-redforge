from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ai_supply_chain.domain.exceptions.domain_exceptions import MBOMIncomplete
from ai_supply_chain.domain.repositories.i_tenant_verification_settings_repository import (
    TenantVerificationSettings,
)
from ai_supply_chain.domain.services.ai_discovery_scan_coordinator import (
    AIDiscoveryScanCoordinator,
)
from ai_supply_chain.domain.services.mbom_builder_service import ModelBillOfMaterialsBuilder
from ai_supply_chain.domain.value_objects.enums import (
    DiscoverySourceType,
    MBOMComponentType,
)
from ai_supply_chain.domain.value_objects.identifiers import ModelProvenanceId, TenantId
from ai_supply_chain.domain.value_objects.supply_chain_vos import (
    DiscoveredAIService,
    MBOMComponent,
)
from ai_supply_chain.infrastructure.acl.degraded_adapters import (
    RecordingInventoryMatchAdapter,
    RecordingShadowAlertRaiseAdapter,
    StubVulnerabilityQueryAdapter,
)
from ai_supply_chain.infrastructure.providers.discovery_providers import (
    CloudAuditLogKubernetesAdmissionAdapter,
    InMemoryCloudAIServiceProvider,
    InMemoryHuggingFaceHubProvider,
    InMemoryModelRegistryProvider,
    ThinMCPServerDiscoveryAdapter,
)


@pytest.mark.asyncio
async def test_mbom_requires_base_model() -> None:
    vuln = StubVulnerabilityQueryAdapter()
    builder = ModelBillOfMaterialsBuilder(vuln)
    tenant = TenantId.generate()
    now = datetime.now(UTC)
    with pytest.raises(MBOMIncomplete):
        await builder.build(
            tenant,
            ModelProvenanceId.generate(),
            [MBOMComponent(MBOMComponentType.TOKENIZER, "tok", "1", "src", "x")],
            now,
        )


@pytest.mark.asyncio
async def test_discovery_partial_failure_isolated() -> None:
    hf = InMemoryHuggingFaceHubProvider()
    cloud = InMemoryCloudAIServiceProvider()
    cloud.fail_accounts.add("bad-acct")
    cloud.by_account["good-acct"] = [
        DiscoveredAIService(
            DiscoverySourceType.CLOUD_PROVIDER_SCAN,
            "good-acct",
            "ep-1",
            "bedrock",
            "us-east-1",
            {},
        )
    ]
    hf.models[str(TenantId.generate())] = []  # unused
    tenant = TenantId.generate()
    inventory = RecordingInventoryMatchAdapter()
    shadow = RecordingShadowAlertRaiseAdapter()
    coord = AIDiscoveryScanCoordinator(
        hf,
        cloud,
        InMemoryModelRegistryProvider(),
        ThinMCPServerDiscoveryAdapter(),
        CloudAuditLogKubernetesAdmissionAdapter(),
        inventory,
        shadow,
    )
    run = await coord.run_scan(
        tenant,
        [DiscoverySourceType.CLOUD_PROVIDER_SCAN],
        ["bad-acct", "good-acct"],
        TenantVerificationSettings(),
        datetime.now(UTC),
    )
    assert run.partial is True
    assert run.unmatched
    assert len(shadow.raised) >= 1
