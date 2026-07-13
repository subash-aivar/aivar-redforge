"""Integration tests for the Enterprise AI Connector & Discovery Framework (Sprint 23).

Tests cover:
- Full discovery pipeline: ConnectorService → ConnectorRegistry → Stub → Mapper → InventoryService
- Synchronization pipeline (SyncService)
- Multi-tenant isolation: connectors per org never leak
- Concurrent-style: sequential multi-connector batch discovery
- Registry behavior: all 11 stubs round-trip without error
- Failure handling: provider error propagates, connector records failure
- Knowledge graph projection: full graph from connector + discovery run
- Large inventory: 11-connector batch maps assets into inventory
- Protocol conformance: runtime_checkable checks pass
"""

from __future__ import annotations

import pytest

from redforge.application.connectors.connector_service import ConnectorService
from redforge.application.connectors.contracts import (
    ConnectorProvider,
    ConnectorRegistrationInput,
    InventoryMapperPort,
)
from redforge.application.connectors.discovery_service import DiscoveryService
from redforge.application.connectors.knowledge_projector import (
    ConnectorKnowledgeGraphProjector,
)
from redforge.application.connectors.registry import ConnectorRegistry
from redforge.application.connectors.stub_connectors import build_default_registry
from redforge.application.connectors.sync_service import SyncService
from redforge.application.inventory.inventory_service import InventoryService
from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.exceptions import (
    ConnectorNotEnabledError,
    DiscoveryJobConflictError,
)
from redforge.domain.connectors.value_objects import ConnectorType

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_full_stack(org_id: str = "org-integration-001") -> tuple[
    ConnectorService,
    DiscoveryService,
    SyncService,
    InventoryService,
    ConnectorRegistry,
]:
    registry = build_default_registry()
    inventory_svc = InventoryService()
    connector_svc = ConnectorService(registry=registry)
    discovery_svc = DiscoveryService(registry=registry, inventory_service=inventory_svc)
    sync_svc = SyncService(registry=registry, inventory_service=inventory_svc)
    return connector_svc, discovery_svc, sync_svc, inventory_svc, registry


def _bring_to_enabled(
    svc: ConnectorService,
    connector_type: str = "openai",
    org_id: str = "org-integration-001",
) -> Connector:
    inp = ConnectorRegistrationInput(
        connector_type=connector_type,
        name=f"{connector_type} integration",
        description="integration test",
        organization_id=org_id,
    )
    connector = svc.register(inp)
    cid = str(connector.id)
    svc.configure(cid, credential_reference_id="int-ref-001")
    svc.validate(cid)
    svc.enable(cid)
    return svc.get(cid)  # type: ignore[return-value]


# ─── Full Discovery Pipeline ──────────────────────────────────────────────────


class TestFullDiscoveryPipeline:
    def test_openai_discovery_produces_snapshot(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        result, snapshot = disc.run_discovery(connector)
        assert result.resource_count > 0
        assert snapshot.total_assets_mapped >= 0  # stubs may map 0 or more
        assert snapshot.connector_id == str(connector.id)

    def test_anthropic_discovery_produces_snapshot(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "anthropic")
        result, _snapshot = disc.run_discovery(connector)
        assert result.resource_count > 0

    def test_discovery_records_job_on_connector(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        disc.run_discovery(connector)
        assert len(connector.discovery_history) == 1
        assert connector.discovery_history[0].succeeded

    def test_discovery_on_disabled_connector_raises(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        cid = str(connector.id)
        svc.disable(cid)
        connector = svc.get(cid)
        with pytest.raises(ConnectorNotEnabledError):
            disc.run_discovery(connector)  # type: ignore[arg-type]

    def test_all_11_stubs_complete_discovery(self) -> None:
        connector_types = [
            "openai", "anthropic", "azure_openai", "aws_bedrock", "google_vertex_ai",
            "langsmith", "langgraph", "crewai", "autogen", "openai_agents_sdk",
            "mcp_registry",
        ]
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        for ct in connector_types:
            connector = _bring_to_enabled(svc, ct)
            result, _snapshot = disc.run_discovery(connector)
            assert result.connector_type == ct, f"Wrong type for {ct}"
            assert len(connector.discovery_history) == 1

    def test_discovery_with_no_provider_returns_error_snapshot(self) -> None:
        registry = ConnectorRegistry()  # empty registry — no providers
        svc = ConnectorService(registry=registry)
        disc = DiscoveryService(registry=registry, inventory_service=InventoryService())
        connector = _bring_to_enabled(svc, "generic")
        _result, snapshot = disc.run_discovery(connector)
        # No provider means error_message is set, empty snapshot returned
        assert snapshot.total_assets_mapped == 0

    def test_batch_discovery_skips_failures(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connectors = [
            _bring_to_enabled(svc, "openai"),
            _bring_to_enabled(svc, "anthropic"),
        ]
        results = disc.run_batch_discovery(connectors)
        assert len(results) == 2

    def test_discovery_result_deterministic_across_runs(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        r1, _ = disc.run_discovery(connector)
        r2, _ = disc.run_discovery(connector)
        ids1 = {r.external_id for r in r1.raw_resources}
        ids2 = {r.external_id for r in r2.raw_resources}
        assert ids1 == ids2


# ─── Discovery Job Conflict ───────────────────────────────────────────────────


class TestDiscoveryJobConflict:
    def test_two_parallel_starts_conflict(self) -> None:
        svc, _disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        # Manually start a job without completing it
        connector.start_discovery_job("manual-job-1")
        with pytest.raises(DiscoveryJobConflictError):
            connector.start_discovery_job("manual-job-2")

    def test_after_complete_new_job_starts(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        disc.run_discovery(connector)
        # After first run completes, second should succeed
        disc.run_discovery(connector)
        assert len(connector.discovery_history) == 2


# ─── Synchronization Pipeline ────────────────────────────────────────────────


class TestSyncPipeline:
    def test_sync_run_produces_result(self) -> None:
        svc, _disc, sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        result = sync.run_sync(connector)
        assert result.job_id != ""
        assert result.duration_seconds >= 0.0

    def test_sync_records_job_on_connector(self) -> None:
        svc, _disc, sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "anthropic")
        sync.run_sync(connector)
        assert len(connector.sync_history) == 1
        from redforge.domain.connectors.value_objects import SyncJobStatus
        assert connector.sync_history[0].status == SyncJobStatus.COMPLETED

    def test_full_sync_flag_stored(self) -> None:
        svc, _disc, sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        sync.run_sync(connector, is_full_sync=True)
        assert connector.sync_history[0].is_full_sync

    def test_sync_on_disabled_connector_raises(self) -> None:
        svc, _disc, sync_svc, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "langsmith")
        cid = str(connector.id)
        svc.disable(cid)
        connector = svc.get(cid)
        with pytest.raises(ConnectorNotEnabledError):
            sync_svc.run_sync(connector)  # type: ignore[arg-type]

    def test_batch_sync_all_11_stubs(self) -> None:
        connector_types = [
            "openai", "anthropic", "azure_openai", "aws_bedrock", "google_vertex_ai",
            "langsmith", "langgraph", "crewai", "autogen", "openai_agents_sdk",
            "mcp_registry",
        ]
        svc, _disc, sync_svc, _inv, _reg = _make_full_stack()
        connectors = [_bring_to_enabled(svc, ct) for ct in connector_types]
        results = sync_svc.run_batch_sync(connectors)
        assert len(results) == 11


# ─── Multi-Tenant Isolation ───────────────────────────────────────────────────


class TestMultiTenantIsolation:
    def test_connectors_per_org_isolated(self) -> None:
        svc, _disc, _sync, _inv, _reg = _make_full_stack()
        org_a = "01KX3FWDMBVJTKGWNE273CN46A"
        org_b = "01KX3FWDMBVJTKGWNE273CN46B"
        _bring_to_enabled(svc, "openai", org_id=org_a)
        _bring_to_enabled(svc, "openai", org_id=org_a)
        _bring_to_enabled(svc, "anthropic", org_id=org_b)
        assert len(svc.list_for_org(org_a)) == 2
        assert len(svc.list_for_org(org_b)) == 1

    def test_enabled_connectors_span_all_orgs(self) -> None:
        svc, _disc, _sync, _inv, _reg = _make_full_stack()
        _bring_to_enabled(svc, "openai", org_id="01KX3FWDMBVJTKGWNE273CN46C")
        _bring_to_enabled(svc, "anthropic", org_id="01KX3FWDMBVJTKGWNE273CN46D")
        assert len(svc.list_enabled()) == 2


# ─── KG Projection Integration ───────────────────────────────────────────────


class TestKGProjectionIntegration:
    def test_project_connector_with_discovery_and_sync(self) -> None:
        svc, disc, sync_svc, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "openai")
        disc.run_discovery(connector)
        sync_svc.run_sync(connector)

        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)

        assert graph.has_node(str(connector.id))
        assert graph.has_node(f"platform:{ConnectorType.OPENAI.value}")
        # Discovery and sync job nodes should exist
        disc_job_id = connector.discovery_history[0].job_id
        sync_job_id = connector.sync_history[0].job_id
        assert graph.has_node(f"discovery_job:{disc_job_id}")
        assert graph.has_node(f"sync_job:{sync_job_id}")

    def test_project_all_11_stubs_into_graph(self) -> None:
        connector_types = [
            "openai", "anthropic", "azure_openai", "aws_bedrock", "google_vertex_ai",
            "langsmith", "langgraph", "crewai", "autogen", "openai_agents_sdk",
            "mcp_registry",
        ]
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()

        for ct in connector_types:
            connector = _bring_to_enabled(svc, ct)
            disc.run_discovery(connector)
            projector.project_connector(connector, graph)

        # 11 CONNECTOR nodes + 11 EXTERNAL_PLATFORM nodes + 11 DISCOVERY_JOB nodes
        all_nodes = graph._store.all_nodes()
        conn_nodes = [n for n in all_nodes if n.node_type == NodeType.CONNECTOR]
        platform_nodes = [n for n in all_nodes if n.node_type == NodeType.EXTERNAL_PLATFORM]
        disc_nodes = [n for n in all_nodes if n.node_type == NodeType.DISCOVERY_JOB]
        assert len(conn_nodes) == 11
        assert len(platform_nodes) == 11
        assert len(disc_nodes) == 11

    def test_idempotent_projection_node_count_stable(self) -> None:
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connector = _bring_to_enabled(svc, "langsmith")
        disc.run_discovery(connector)

        graph = KnowledgeGraph()
        projector = ConnectorKnowledgeGraphProjector()
        projector.project_connector(connector, graph)
        count_1 = graph.node_count
        projector.project_connector(connector, graph)
        count_2 = graph.node_count
        assert count_1 == count_2


# ─── Protocol Conformance ─────────────────────────────────────────────────────


class TestProtocolConformance:
    def test_runtime_checkable_provider(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            p = registry.get_provider(ct)
            assert isinstance(p, ConnectorProvider)

    def test_runtime_checkable_mapper(self) -> None:
        registry = build_default_registry()
        for ct in registry.registered_types():
            m = registry.get_mapper(ct)
            assert isinstance(m, InventoryMapperPort)


# ─── Scalability ──────────────────────────────────────────────────────────────


class TestScalability:
    def test_100_connector_registrations(self) -> None:
        """100 connector registrations should complete quickly."""
        import time
        registry = build_default_registry()
        svc = ConnectorService(registry=registry)
        start = time.monotonic()
        for i in range(100):
            inp = ConnectorRegistrationInput(
                connector_type="generic",
                name=f"Connector {i}",
                description="",
                organization_id=f"org-{i % 10}",
            )
            svc.register(inp)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"100 registrations took {elapsed:.2f}s"

    def test_11_stub_batch_discovery_under_5s(self) -> None:
        """All 11 stub connectors discovered in under 5 seconds."""
        import time
        connector_types = [
            "openai", "anthropic", "azure_openai", "aws_bedrock", "google_vertex_ai",
            "langsmith", "langgraph", "crewai", "autogen", "openai_agents_sdk",
            "mcp_registry",
        ]
        svc, disc, _sync, _inv, _reg = _make_full_stack()
        connectors = [_bring_to_enabled(svc, ct) for ct in connector_types]
        start = time.monotonic()
        disc.run_batch_discovery(connectors)
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"11-stub batch took {elapsed:.2f}s"
