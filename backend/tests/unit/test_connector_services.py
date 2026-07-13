"""Unit tests for connector application services and registry (Sprint 23).

Covers:
- ConnectorRegistry: register, conflict, overwrite, unregister
- ConnectorService: full lifecycle via service layer
- Stub connectors: synthetic resource generation
- Protocol conformance: all stubs satisfy ConnectorProvider + InventoryMapperPort
- ConnectorKnowledgeGraphProjector: node/edge projection
"""

from __future__ import annotations

import pytest

from redforge.application.connectors.connector_service import ConnectorService
from redforge.application.connectors.contracts import (
    ConnectorProvider,
    ConnectorRegistrationInput,
    InventoryMapperPort,
)
from redforge.application.connectors.knowledge_projector import (
    ConnectorKnowledgeGraphProjector,
)
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.application.connectors.stub_connectors import build_default_registry
from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.domain.connectors.exceptions import (
    ConnectorNotFoundError,
    ConnectorRegistryConflictError,
)
from redforge.domain.connectors.value_objects import (
    ConnectorStatus,
    ConnectorType,
    SynchronizationPolicy,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_service(registry: ConnectorRegistry | None = None) -> ConnectorService:
    if registry is None:
        registry = build_default_registry()
    return ConnectorService(registry=registry)


# Pre-generated org IDs used across tests (valid ULID strings).
_ORG_A = "01KX3FWDMBVJTKGWNE273CN45D"
_ORG_B = "01KX3FWDMBVJTKGWNE273CN45E"
_ORG_TEST = "01KX3FWDMBVJTKGWNE273CN45F"


def _register_connector(
    service: ConnectorService,
    connector_type: str = "openai",
    org_id: str = _ORG_TEST,
) -> str:
    inp = ConnectorRegistrationInput(
        connector_type=connector_type,
        name=f"{connector_type.upper()} Test",
        description="unit test connector",
        organization_id=org_id,
    )
    connector = service.register(inp)
    return str(connector.id)


# ─── ConnectorRegistry ────────────────────────────────────────────────────────


class TestConnectorRegistry:
    def test_register_provider_and_mapper(self) -> None:
        registry = build_default_registry()
        assert registry.provider_count() == 11

    def test_has_type_true_for_registered(self) -> None:
        registry = build_default_registry()
        assert registry.has_type(ConnectorType.OPENAI)

    def test_has_type_false_for_missing(self) -> None:
        registry = ConnectorRegistry()
        assert not registry.has_type(ConnectorType.OPENAI)

    def test_get_provider_returns_none_for_missing(self) -> None:
        registry = ConnectorRegistry()
        assert registry.get_provider(ConnectorType.OPENAI) is None

    def test_re_register_raises_conflict(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        mapper = registry.get_mapper(ConnectorType.OPENAI)
        assert provider is not None and mapper is not None
        with pytest.raises(ConnectorRegistryConflictError):
            registry.register(provider, mapper)

    def test_re_register_with_overwrite_succeeds(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        mapper = registry.get_mapper(ConnectorType.OPENAI)
        assert provider is not None and mapper is not None
        registry.register(provider, mapper, overwrite=True)  # no exception

    def test_unregister_removes_entry(self) -> None:
        registry = build_default_registry()
        registry.unregister(ConnectorType.OPENAI)
        assert not registry.has_type(ConnectorType.OPENAI)

    def test_registered_types_returns_frozenset(self) -> None:
        registry = build_default_registry()
        types = registry.registered_types()
        assert isinstance(types, frozenset)
        assert ConnectorType.ANTHROPIC in types

    def test_empty_registry_provider_count_zero(self) -> None:
        registry = ConnectorRegistry()
        assert registry.provider_count() == 0


# ─── ConnectorService: registration ──────────────────────────────────────────


class TestConnectorServiceRegister:
    def test_register_returns_connector(self) -> None:
        svc = _make_service()
        inp = ConnectorRegistrationInput(
            connector_type="openai",
            name="My Connector",
            description="desc",
            organization_id="org-001",
        )
        connector = svc.register(inp)
        assert connector.status == ConnectorStatus.REGISTERED
        assert connector.name == "My Connector"

    def test_get_returns_registered_connector(self) -> None:
        svc = _make_service()
        cid = _register_connector(svc)
        assert svc.get(cid) is not None

    def test_get_unknown_id_returns_none(self) -> None:
        svc = _make_service()
        assert svc.get("unknown-id") is None

    def test_list_for_org_filters_by_org(self) -> None:
        svc = _make_service()
        _register_connector(svc, org_id=_ORG_A)
        _register_connector(svc, org_id=_ORG_A)
        _register_connector(svc, org_id=_ORG_B)
        assert len(svc.list_for_org(_ORG_A)) == 2
        assert len(svc.list_for_org(_ORG_B)) == 1

    def test_unknown_connector_type_defaults_to_generic(self) -> None:
        svc = _make_service()
        inp = ConnectorRegistrationInput(
            connector_type="unknown_platform_xyz",
            name="Generic",
            description="",
            organization_id="org-001",
        )
        connector = svc.register(inp)
        assert connector.connector_type == ConnectorType.GENERIC


# ─── ConnectorService: full lifecycle ────────────────────────────────────────


class TestConnectorServiceLifecycle:
    def _enable(self, svc: ConnectorService, cid: str) -> None:
        svc.configure(cid, credential_reference_id="test-ref-001")
        svc.validate(cid)
        svc.enable(cid)

    def test_full_lifecycle_to_enabled(self) -> None:
        svc = _make_service()
        cid = _register_connector(svc, connector_type="openai")
        self._enable(svc, cid)
        connector = svc.get(cid)
        assert connector is not None
        assert connector.is_enabled

    def test_disable_after_enable(self) -> None:
        svc = _make_service()
        cid = _register_connector(svc, connector_type="openai")
        self._enable(svc, cid)
        svc.disable(cid, reason="paused")
        connector = svc.get(cid)
        assert connector is not None
        assert connector.status == ConnectorStatus.DISABLED

    def test_archive(self) -> None:
        svc = _make_service()
        cid = _register_connector(svc, connector_type="anthropic")
        self._enable(svc, cid)
        svc.archive(cid, reason="decommissioned")
        connector = svc.get(cid)
        assert connector is not None
        assert connector.status == ConnectorStatus.ARCHIVED

    def test_configure_unknown_id_raises(self) -> None:
        svc = _make_service()
        with pytest.raises(ConnectorNotFoundError):
            svc.configure("no-such-id")

    def test_enable_unknown_id_raises(self) -> None:
        svc = _make_service()
        with pytest.raises(ConnectorNotFoundError):
            svc.enable("no-such-id")

    def test_list_enabled_returns_only_enabled(self) -> None:
        svc = _make_service()
        cid1 = _register_connector(svc, connector_type="openai", org_id=_ORG_A)
        _register_connector(svc, connector_type="anthropic", org_id=_ORG_A)
        self._enable(svc, cid1)
        enabled = svc.list_enabled()
        assert len(enabled) == 1
        assert str(enabled[0].id) == cid1

    def test_sync_policy_update(self) -> None:
        svc = _make_service()
        cid = _register_connector(svc, connector_type="langsmith")
        self._enable(svc, cid)
        policy = SynchronizationPolicy(cron_expression="0 */6 * * *")
        svc.update_sync_policy(cid, policy)
        connector = svc.get(cid)
        assert connector is not None
        assert connector.sync_policy.cron_expression == "0 */6 * * *"


# ─── Stub Providers: protocol conformance ────────────────────────────────────


class TestStubProviderProtocolConformance:
    def test_all_providers_implement_protocol(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            provider = registry.get_provider(ct)
            assert isinstance(provider, ConnectorProvider), f"{ct} provider not conformant"

    def test_all_mappers_implement_protocol(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            mapper = registry.get_mapper(ct)
            assert isinstance(mapper, InventoryMapperPort), f"{ct} mapper not conformant"

    def test_provider_connector_type_matches_registry(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            provider = registry.get_provider(ct)
            assert provider is not None
            assert provider.connector_type == ct

    def test_mapper_connector_type_matches_registry(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            mapper = registry.get_mapper(ct)
            assert mapper is not None
            assert mapper.connector_type == ct


# ─── Stub Providers: discovery output ────────────────────────────────────────


def _enabled_connector(connector_type: ConnectorType) -> object:
    from redforge.domain.connectors.entity import Connector
    from redforge.domain.connectors.value_objects import (
        ConnectorCapability,
        ConnectorCapabilityType,
        ConnectorConfiguration,
        ConnectorVersion,
    )
    from redforge.shared.identifiers import EntityId

    org_id = EntityId.generate()
    c = Connector.register(
        organization_id=org_id,
        connector_type=connector_type,
        name="stub-test",
        description="",
        version=ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0"),
        capabilities=(ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),),
    )
    c.configure(ConnectorConfiguration(base_url=""), None)
    c.mark_validated(latency_ms=1.0)
    c.enable()
    return c


class TestStubProviderDiscovery:
    def test_openai_discovers_resources(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.OPENAI)
        result = provider.discover(connector, "test-key", {})  # type: ignore[arg-type]
        assert result.resource_count > 0

    def test_anthropic_discovers_resources(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.ANTHROPIC)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.ANTHROPIC)
        result = provider.discover(connector, "test-key", {})  # type: ignore[arg-type]
        assert result.resource_count > 0

    def test_discovery_result_is_deterministic(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.OPENAI)
        r1 = provider.discover(connector, "key", {})  # type: ignore[arg-type]
        r2 = provider.discover(connector, "key", {})  # type: ignore[arg-type]
        # External IDs should be stable across calls
        ids1 = {r.external_id for r in r1.raw_resources}
        ids2 = {r.external_id for r in r2.raw_resources}
        assert ids1 == ids2

    def test_all_stubs_discover_without_error(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            provider = registry.get_provider(ct)
            assert provider is not None
            connector = _enabled_connector(ct)
            result = provider.discover(connector, "cred", {})  # type: ignore[arg-type]
            assert result.connector_type == ct.value

    def test_all_stubs_map_resources(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            provider = registry.get_provider(ct)
            mapper = registry.get_mapper(ct)
            assert provider is not None and mapper is not None
            connector = _enabled_connector(ct)
            result = provider.discover(connector, "cred", {})  # type: ignore[arg-type]
            org_id = str(connector.organization_id)  # type: ignore[union-attr]
            mapped = mapper.map_batch(result.raw_resources, org_id)
            assert isinstance(mapped, tuple)

    def test_check_health_returns_healthy_with_credential(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.OPENAI)
        health = provider.check_health(connector, "test-key")  # type: ignore[arg-type]
        from redforge.domain.connectors.value_objects import ConnectorHealthStatus
        assert health.status == ConnectorHealthStatus.HEALTHY

    def test_check_health_unreachable_without_credential(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.OPENAI)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.OPENAI)
        health = provider.check_health(connector, "")  # type: ignore[arg-type]
        from redforge.domain.connectors.value_objects import ConnectorHealthStatus
        assert health.status == ConnectorHealthStatus.UNREACHABLE

    def test_validate_credential_true_with_non_empty(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.ANTHROPIC)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.ANTHROPIC)
        assert provider.validate_credential(connector, "some-key")  # type: ignore[arg-type]

    def test_validate_credential_false_for_empty(self) -> None:
        registry = build_default_registry()
        provider = registry.get_provider(ConnectorType.ANTHROPIC)
        assert provider is not None
        connector = _enabled_connector(ConnectorType.ANTHROPIC)
        assert not provider.validate_credential(connector, "")  # type: ignore[arg-type]


# ─── ConnectorKnowledgeGraphProjector ────────────────────────────────────────


class TestConnectorKnowledgeGraphProjector:
    def _make_enabled_connector(self, connector_type: ConnectorType = ConnectorType.OPENAI) -> object:
        return _enabled_connector(connector_type)

    def test_project_adds_connector_node(self) -> None:
        connector = _enabled_connector(ConnectorType.OPENAI)
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        node = graph.get_node(str(connector.id))  # type: ignore[union-attr]
        assert node is not None
        assert node.node_type == NodeType.CONNECTOR

    def test_project_adds_platform_node(self) -> None:
        connector = _enabled_connector(ConnectorType.OPENAI)
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        platform_node = graph.get_node("platform:openai")
        assert platform_node is not None
        assert platform_node.node_type == NodeType.EXTERNAL_PLATFORM

    def test_project_with_health_snapshot(self) -> None:
        from redforge.domain.connectors.value_objects import ConnectorHealth
        connector = _enabled_connector(ConnectorType.ANTHROPIC)
        connector.update_health(ConnectorHealth.healthy(latency_ms=5.0))  # type: ignore[union-attr]
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        health_node = graph.get_node(f"health:{connector.id}")  # type: ignore[union-attr]
        assert health_node is not None
        assert health_node.node_type == NodeType.CONNECTOR_HEALTH

    def test_project_discovery_job_node(self) -> None:
        connector = _enabled_connector(ConnectorType.OPENAI)
        connector.start_discovery_job("test-job-1")  # type: ignore[union-attr]
        connector.complete_discovery_job(  # type: ignore[union-attr]
            "test-job-1", assets_discovered=3, assets_normalized=3, assets_failed=0
        )
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        job_node = graph.get_node("discovery_job:test-job-1")
        assert job_node is not None
        assert job_node.node_type == NodeType.DISCOVERY_JOB

    def test_project_sync_job_node(self) -> None:
        connector = _enabled_connector(ConnectorType.OPENAI)
        connector.start_sync_job("test-sync-1")  # type: ignore[union-attr]
        connector.complete_sync_job(  # type: ignore[union-attr]
            "test-sync-1", assets_added=5, assets_updated=2, assets_unchanged=10
        )
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        job_node = graph.get_node("sync_job:test-sync-1")
        assert job_node is not None
        assert job_node.node_type == NodeType.SYNC_JOB

    def test_project_multiple_connectors(self) -> None:
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        connectors = [
            _enabled_connector(ConnectorType.OPENAI),
            _enabled_connector(ConnectorType.ANTHROPIC),
            _enabled_connector(ConnectorType.LANGSMITH),
        ]
        projector.project_connectors(connectors, graph)  # type: ignore[arg-type]
        connector_nodes = [
            n for n in graph._store.all_nodes() if n.node_type == NodeType.CONNECTOR
        ]
        assert len(connector_nodes) == 3

    def test_idempotent_projection(self) -> None:
        connector = _enabled_connector(ConnectorType.OPENAI)
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        node_count_1 = graph.node_count
        projector.project_connector(connector, graph)  # type: ignore[arg-type]
        node_count_2 = graph.node_count
        assert node_count_1 == node_count_2
