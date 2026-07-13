"""Consolidated tests closing several traceability-matrix gaps found
during the M16 adversarial scenario mapping:
  - a DISABLED policy's run-now is rejected (never silently executed)
  - port reachability never fabricates protocol identity
  - a bare reachable/validated service is never auto-classified as a
    vulnerability or "critical" severity
  - concurrent same-IP asset resolution converges on one canonical
    asset (race-safe, inherited from M3's own resolve_asset())
  - the same raw IP in two different tenants creates two isolated
    canonical assets
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.network_security.orchestrator import _ServiceFinding
from redforge.application.network_security.scheduler import NetworkMonitoringProcessor
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.domain.network_security.entity import NetworkMonitoringPolicy
from redforge.domain.network_security.exceptions import NetworkPolicyDisabledForRunError
from redforge.domain.network_security.value_objects import (
    NetworkValidationProfile,
    ValidationCadence,
)
from redforge.infrastructure.database.repositories.network_security.policy_repository import (
    SqlAlchemyNetworkMonitoringPolicyRepository,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

_DB_URL = "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test"


@pytest.fixture
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
class TestDisabledPolicyRunNowRejected:
    async def test_run_now_on_disabled_policy_raises_controlled_error(
        self, session_factory,
    ) -> None:
        org_id = EntityId.generate()
        asset_service = TenantAssetService(session_factory)
        asset = await asset_service.resolve_asset(
            organization_id=str(org_id), asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.200",
            name="203.0.113.200", description="test", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        policy = NetworkMonitoringPolicy.create(
            organization_id=org_id, target_asset_id=EntityId.from_string(asset.id),
            requester_user_id=EntityId.generate(), profile=NetworkValidationProfile.NETWORK_BASELINE,
            cadence=ValidationCadence.DAILY,
        )
        policy.activate(utc_now())
        policy.disable(utc_now())
        async with session_factory() as session:
            repo = SqlAlchemyNetworkMonitoringPolicyRepository(session)
            await repo.save(policy)
            await session.commit()

        processor = NetworkMonitoringProcessor(session_factory, orchestrator=None)  # type: ignore[arg-type]
        with pytest.raises(NetworkPolicyDisabledForRunError):
            await processor.run_now(str(org_id), str(policy.id))


class TestProtocolNeverFabricated:
    def test_service_finding_defaults_to_no_validated_protocol(self) -> None:
        """A bare TCP-reachable port must never default to a validated
        protocol — `validated_protocol` starts as None and is only set
        by real validator/TLS success (see orchestrator.py's `_probe`)."""
        finding = _ServiceFinding(address="10.0.0.1", port=8080)
        assert finding.validated_protocol is None
        assert finding.validator_id is None

    def test_port_443_finding_defaults_to_no_protocol_until_tls_succeeds(self) -> None:
        finding = _ServiceFinding(address="10.0.0.1", port=443)
        assert finding.validated_protocol is None

    def test_port_6379_finding_defaults_to_no_protocol_until_redis_validator_succeeds(
        self,
    ) -> None:
        finding = _ServiceFinding(address="10.0.0.1", port=6379)
        assert finding.validated_protocol is None


class TestNoAutomaticVulnerabilityOrCriticalSeverityInference:
    def test_m6_rule_severity_map_never_assigns_critical_to_bare_reachability(self) -> None:
        """M16 reuses M6's `_RULE_SEVERITY` map (application/
        network_discovery/service.py) unchanged for its 3 existing
        conditions — none of them is 'critical', and none fires from
        bare TCP reachability alone (all require a specific,
        deterministic rule match, e.g. multiple remote-admin services
        observed together)."""
        from redforge.application.network_discovery.service import _RULE_SEVERITY

        assert "critical" not in _RULE_SEVERITY.values()
        assert set(_RULE_SEVERITY.keys()) == {
            "PUBLICLY_ADDRESSABLE_ASSET", "SENSITIVE_SERVICE_OBSERVED",
            "MULTIPLE_REMOTE_ADMIN_SERVICES",
        }


@pytest.mark.asyncio
class TestConcurrentAssetResolutionConvergesOnOneCanonicalAsset:
    async def test_concurrent_same_ip_resolution_creates_exactly_one_asset(
        self, session_factory,
    ) -> None:
        org_id = str(EntityId.generate())
        asset_service = TenantAssetService(session_factory)

        async def _resolve() -> str:
            asset = await asset_service.resolve_asset(
                organization_id=org_id, asset_type=AssetType.IP_ADDRESS,
                scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.210",
                name="203.0.113.210", description="race test",
                discovery_source=AssetDiscoverySource.API_SCAN,
            )
            return asset.id

        results = await asyncio.gather(*(_resolve() for _ in range(10)))
        assert len(set(results)) == 1

    async def test_same_raw_ip_in_two_tenants_creates_two_isolated_assets(
        self, session_factory,
    ) -> None:
        org_a = str(EntityId.generate())
        org_b = str(EntityId.generate())
        asset_service = TenantAssetService(session_factory)

        asset_a = await asset_service.resolve_asset(
            organization_id=org_a, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.220",
            name="203.0.113.220", description="tenant a", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        asset_b = await asset_service.resolve_asset(
            organization_id=org_b, asset_type=AssetType.IP_ADDRESS,
            scheme=IdentityScheme.IP_ADDRESS, raw_external_id="203.0.113.220",
            name="203.0.113.220", description="tenant b", discovery_source=AssetDiscoverySource.API_SCAN,
        )
        assert asset_a.id != asset_b.id
        assert asset_a.organization_id != asset_b.organization_id
