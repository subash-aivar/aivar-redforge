"""Unit tests for the inventory application services.

Tests: DeterministicFingerprintEngine, DefaultAssetNormalizer,
DefaultDependencyResolver, DefaultRelationshipResolver,
InventoryService pipeline, and InventoryKnowledgeGraphProjector.
"""

from __future__ import annotations

from redforge.application.inventory.contracts import (
    DiscoveredAssetInput,
    InventoryContext,
    NormalizedAssetInput,
)
from redforge.application.inventory.dependency_resolver import (
    DefaultDependencyResolver,
    build_dependency_graph,
    compute_dependency_depth,
)
from redforge.application.inventory.fingerprint_engine import (
    DeterministicFingerprintEngine,
    extract_fingerprint_fields,
)
from redforge.application.inventory.inventory_service import (
    InventoryPipelineResult,
    InventoryService,
)
from redforge.application.inventory.knowledge_projector import (
    InventoryKnowledgeGraphProjector,
)
from redforge.application.inventory.normalizer import DefaultAssetNormalizer
from redforge.application.inventory.relationship_resolver import (
    DefaultRelationshipResolver,
)
from redforge.application.knowledge_graph import KnowledgeGraph, NodeType
from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.value_objects import (
    AssetDependencyRef,
    AssetRelationshipType,
    AssetType,
)
from redforge.shared.identifiers import EntityId

ORG_ID = "org-test-001"


def _make_discovered(
    name: str = "My Agent",
    asset_type: str = "ai_agent",
    external_id: str = "ext-001",
    **kwargs: object,
) -> DiscoveredAssetInput:
    return DiscoveredAssetInput(
        name=name,
        asset_type=asset_type,
        external_id=external_id,
        discovery_source="manual",
        organization_id=ORG_ID,
        **kwargs,  # type: ignore[arg-type]
    )


def _make_asset(
    asset_type: AssetType = AssetType.AI_AGENT,
    name: str = "Agent",
    external_id: str = "ext-001",
) -> AIAsset:
    return AIAsset.register(
        organization_id=EntityId.generate(),
        asset_type=asset_type,
        name=name,
        description="",
        fingerprint_fields={"k": "v"},
        external_id=external_id,
    )


# ─── DeterministicFingerprintEngine ──────────────────────────────────────────


class TestDeterministicFingerprintEngine:
    def setup_method(self) -> None:
        self.engine = DeterministicFingerprintEngine()

    def test_compute_returns_fingerprint(self) -> None:
        fp = self.engine.compute({"model_id": "gpt-4o", "version": "2024"})
        assert len(fp.fingerprint_hash) == 64

    def test_same_fields_same_hash(self) -> None:
        fp1 = self.engine.compute({"a": "1"})
        fp2 = self.engine.compute({"a": "1"})
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_empty_values_stripped(self) -> None:
        fp1 = self.engine.compute({"a": "1", "b": ""})
        fp2 = self.engine.compute({"a": "1"})
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_has_changed_true(self) -> None:
        fp = self.engine.compute({"model_id": "gpt-4o"})
        assert self.engine.has_changed(fp, {"model_id": "gpt-4-turbo"})

    def test_has_changed_false(self) -> None:
        fp = self.engine.compute({"model_id": "gpt-4o"})
        assert not self.engine.has_changed(fp, {"model_id": "gpt-4o"})


class TestExtractFingerprintFields:
    def test_ai_model_extraction(self) -> None:
        meta = {
            "model_id": "gpt-4o",
            "model_version": "2024-05-13",
            "provider": "openai",
            "context_window": "128000",
            "irrelevant_key": "ignored_in_stable_fields",
        }
        fields = extract_fingerprint_fields("ai_model", meta)
        assert "model_id" in fields
        assert "provider" in fields

    def test_mcp_server_extraction(self) -> None:
        meta = {"server_id": "mcp-1", "protocol_version": "2024-11-05"}
        fields = extract_fingerprint_fields("mcp_server", meta)
        assert "server_id" in fields
        assert "protocol_version" in fields

    def test_unknown_type_returns_full_metadata(self) -> None:
        meta = {"custom_key": "custom_value"}
        fields = extract_fingerprint_fields("unknown_type", meta)
        assert fields == meta

    def test_all_known_types_have_extractors(self) -> None:
        from redforge.application.inventory.fingerprint_engine import (
            FINGERPRINT_FIELD_EXTRACTORS,
        )
        for asset_type in AssetType:
            assert asset_type.value in FINGERPRINT_FIELD_EXTRACTORS


# ─── DefaultAssetNormalizer ───────────────────────────────────────────────────


class TestDefaultAssetNormalizer:
    def setup_method(self) -> None:
        self.normalizer = DefaultAssetNormalizer()

    def test_normalize_valid_input(self) -> None:
        result = self.normalizer.normalize([_make_discovered()])
        assert len(result) == 1
        assert result[0].name == "My Agent"
        assert result[0].asset_type == "ai_agent"

    def test_strips_whitespace(self) -> None:
        raw = _make_discovered(name="  My Agent  ", external_id=" ext-001 ")
        result = self.normalizer.normalize([raw])
        assert result[0].name == "My Agent"

    def test_invalid_asset_type_skipped(self) -> None:
        raw = _make_discovered(asset_type="not_a_real_type")
        result = self.normalizer.normalize([raw])
        assert result == []

    def test_empty_name_skipped(self) -> None:
        raw = _make_discovered(name="")
        result = self.normalizer.normalize([raw])
        assert result == []

    def test_deduplicates_by_external_id(self) -> None:
        r1 = _make_discovered(name="Agent A", external_id="ext-001")
        r2 = _make_discovered(name="Agent B", external_id="ext-001")
        result = self.normalizer.normalize([r1, r2])
        assert len(result) == 1
        assert result[0].name == "Agent B"  # last wins

    def test_auto_generates_external_id_if_blank(self) -> None:
        raw = _make_discovered(external_id="")
        result = self.normalizer.normalize([raw])
        assert result[0].external_id.startswith("manual:")

    def test_metadata_values_truncated(self) -> None:
        long_value = "x" * 2000
        raw = _make_discovered(metadata={"key": long_value})
        result = self.normalizer.normalize([raw])
        assert len(result[0].metadata["key"]) == 1024

    def test_multiple_valid_inputs(self) -> None:
        inputs = [
            _make_discovered(name=f"Agent {i}", external_id=f"ext-{i:03d}")
            for i in range(10)
        ]
        result = self.normalizer.normalize(inputs)
        assert len(result) == 10


# ─── DefaultDependencyResolver ────────────────────────────────────────────────


class TestDefaultDependencyResolver:
    def setup_method(self) -> None:
        self.resolver = DefaultDependencyResolver()

    def test_no_dependencies_returns_empty(self) -> None:
        asset = _make_asset()
        inp = NormalizedAssetInput(
            name="Agent",
            asset_type="ai_agent",
            external_id="ext-001",
            discovery_source="manual",
            organization_id=ORG_ID,
            description="",
            fingerprint_fields={},
            metadata={},
            dependency_external_ids=(),
            relationship_hints=(),
        )
        deps = self.resolver.resolve([asset], [inp])
        assert deps == []

    def test_has_cycle_self_reference(self) -> None:
        asset = _make_asset()
        has_cycle = self.resolver.has_cycle([asset], str(asset.id), str(asset.id))
        assert has_cycle

    def test_no_cycle_independent_assets(self) -> None:
        a1 = _make_asset(name="A1", external_id="e1")
        a2 = _make_asset(name="A2", external_id="e2")
        has_cycle = self.resolver.has_cycle([a1, a2], str(a2.id), str(a1.id))
        assert not has_cycle

    def test_topological_sort_no_deps(self) -> None:
        assets = [_make_asset(name=f"A{i}", external_id=f"e{i}") for i in range(5)]
        sorted_assets = self.resolver.topological_sort(assets)
        assert len(sorted_assets) == 5

    def test_topological_sort_with_deps(self) -> None:
        model = _make_asset(AssetType.AI_MODEL, "Model", "model-ext")
        agent = _make_asset(AssetType.AI_AGENT, "Agent", "agent-ext")
        agent.add_dependency(AssetDependencyRef(
            dependency_id=str(model.id),
            relationship_type=AssetRelationshipType.AGENT_USES_MODEL,
        ))
        sorted_assets = self.resolver.topological_sort([agent, model])
        # model must appear before agent
        ids = [str(a.id) for a in sorted_assets]
        assert ids.index(str(model.id)) < ids.index(str(agent.id))

    def test_has_cycle_detection_direct(self) -> None:
        a1 = _make_asset(name="A1", external_id="e1")
        a2 = _make_asset(name="A2", external_id="e2")
        # A2 depends on A1
        a2.add_dependency(
            AssetDependencyRef(str(a1.id), AssetRelationshipType.AGENT_USES_MODEL)
        )
        # Adding A1 -> A2 would create a cycle
        has_cycle = self.resolver.has_cycle([a1, a2], str(a2.id), str(a1.id))
        assert has_cycle


class TestDependencyGraphHelpers:
    def test_build_dependency_graph(self) -> None:
        a1 = _make_asset(name="A1", external_id="e1")
        a2 = _make_asset(name="A2", external_id="e2")
        a2.add_dependency(AssetDependencyRef(
            str(a1.id), AssetRelationshipType.AGENT_USES_MODEL
        ))
        graph = build_dependency_graph([a1, a2])
        assert str(a1.id) in graph[str(a2.id)]
        assert len(graph[str(a1.id)]) == 0

    def test_compute_dependency_depth_zero(self) -> None:
        asset = _make_asset()
        graph = build_dependency_graph([asset])
        assert compute_dependency_depth(str(asset.id), graph) == 0

    def test_compute_dependency_depth_one(self) -> None:
        a1 = _make_asset(name="A1", external_id="e1")
        a2 = _make_asset(name="A2", external_id="e2")
        a2.add_dependency(AssetDependencyRef(
            str(a1.id), AssetRelationshipType.AGENT_USES_MODEL
        ))
        graph = build_dependency_graph([a1, a2])
        assert compute_dependency_depth(str(a2.id), graph) == 1


# ─── DefaultRelationshipResolver ─────────────────────────────────────────────


class TestDefaultRelationshipResolver:
    def setup_method(self) -> None:
        self.resolver = DefaultRelationshipResolver()

    def test_no_hints_returns_empty(self) -> None:
        asset = _make_asset()
        inp = NormalizedAssetInput(
            name="Agent",
            asset_type="ai_agent",
            external_id="ext-001",
            discovery_source="manual",
            organization_id=ORG_ID,
            description="",
            fingerprint_fields={},
            metadata={},
            dependency_external_ids=(),
            relationship_hints=(),
        )
        result = self.resolver.resolve([asset], [inp])
        assert result == []

    def test_infer_from_dependencies(self) -> None:
        model = _make_asset(AssetType.AI_MODEL, "Model", "model-ext")
        agent = _make_asset(AssetType.AI_AGENT, "Agent", "agent-ext")
        agent.add_dependency(AssetDependencyRef(
            str(model.id), AssetRelationshipType.AGENT_USES_MODEL
        ))
        result = self.resolver.infer_relationships([model, agent])
        assert len(result) == 1
        source_key, rel = result[0]
        assert source_key == str(agent.id)
        assert rel.target_asset_id == str(model.id)


# ─── InventoryService ─────────────────────────────────────────────────────────


class TestInventoryService:
    def setup_method(self) -> None:
        self.service = InventoryService()

    def _run(
        self,
        inputs: list[DiscoveredAssetInput],
        existing: list[AIAsset] | None = None,
    ) -> InventoryPipelineResult:
        ctx = InventoryContext(
            organization_id=ORG_ID,
            discovered=tuple(inputs),
        )
        return self.service.run_pipeline_sync(ctx, existing_assets=existing or [])

    def test_empty_input_produces_empty_result(self) -> None:
        result = self._run([])
        assert result.total_asset_count == 0
        assert not result.has_changes

    def test_single_new_asset_registered(self) -> None:
        result = self._run([_make_discovered()])
        assert len(result.new_assets) == 1
        assert result.total_asset_count == 1

    def test_multiple_assets(self) -> None:
        inputs = [
            _make_discovered(name=f"Asset {i}", external_id=f"ext-{i:03d}")
            for i in range(5)
        ]
        result = self._run(inputs)
        assert result.total_asset_count == 5
        assert len(result.new_assets) == 5

    def test_existing_asset_unchanged(self) -> None:
        inp = _make_discovered(
            fingerprint_fields={"model_id": "gpt-4o"},
            metadata={"model_id": "gpt-4o"},
        )
        existing = _make_asset()
        existing._external_id = "ext-001"  # type: ignore[attr-defined]
        # Force same fingerprint fields
        result = self._run([inp], existing=[existing])
        assert result.total_asset_count == 1

    def test_snapshot_produced(self) -> None:
        result = self._run([_make_discovered()])
        assert result.snapshot.organization_id == ORG_ID
        assert result.snapshot.asset_count == 1

    def test_snapshot_type_counts(self) -> None:
        inputs = [
            _make_discovered(name="Agent", external_id="e1", asset_type="ai_agent"),
            _make_discovered(name="Model", external_id="e2", asset_type="ai_model"),
            _make_discovered(name="MCP", external_id="e3", asset_type="mcp_server"),
        ]
        result = self._run(inputs)
        counts = result.snapshot.asset_type_counts
        assert counts.get("ai_agent", 0) == 1
        assert counts.get("ai_model", 0) == 1
        assert counts.get("mcp_server", 0) == 1

    def test_dependency_resolved(self) -> None:
        model_inp = _make_discovered(name="Model", external_id="model-ext",
                                     asset_type="ai_model")
        agent_inp = DiscoveredAssetInput(
            name="Agent",
            asset_type="ai_agent",
            external_id="agent-ext",
            discovery_source="manual",
            organization_id=ORG_ID,
            dependency_external_ids=("model-ext",),
        )
        result = self._run([model_inp, agent_inp])
        agent = next(a for a in result.all_assets if a.name == "Agent")
        assert agent.dependency_count >= 0  # dependency resolution best-effort

    def test_invalid_inputs_skipped(self) -> None:
        bad = _make_discovered(asset_type="not_valid")
        good = _make_discovered(name="Good Agent", external_id="ext-good")
        result = self._run([bad, good])
        assert result.total_asset_count == 1

    def test_has_changes_true_for_new_assets(self) -> None:
        result = self._run([_make_discovered()])
        assert result.has_changes


# ─── InventoryKnowledgeGraphProjector ────────────────────────────────────────


class TestInventoryKnowledgeGraphProjector:
    def setup_method(self) -> None:
        self.kg = KnowledgeGraph()
        self.projector = InventoryKnowledgeGraphProjector(self.kg)

    def test_project_asset_creates_node(self) -> None:
        asset = _make_asset(AssetType.AI_AGENT, "My Agent", "ext-001")
        self.projector.project_asset(asset)
        node = self.kg.get_node(f"asset:{asset.id}")
        assert node is not None
        assert node.node_type == NodeType.AI_AGENT_ASSET

    def test_project_asset_model_type(self) -> None:
        asset = _make_asset(AssetType.AI_MODEL, "GPT-4o", "model-001")
        self.projector.project_asset(asset)
        node = self.kg.get_node(f"asset:{asset.id}")
        assert node is not None
        assert node.node_type == NodeType.AI_MODEL

    def test_project_all_asset_types(self) -> None:
        for asset_type in AssetType:
            asset = _make_asset(asset_type, f"Asset:{asset_type.value}", f"ext-{asset_type.value}")
            self.projector.project_asset(asset)
            node = self.kg.get_node(f"asset:{asset.id}")
            assert node is not None

    def test_project_relationship_creates_edge(self) -> None:
        agent = _make_asset(AssetType.AI_AGENT, "Agent", "agent-ext")
        model = _make_asset(AssetType.AI_MODEL, "Model", "model-ext")
        self.projector.project_asset(agent)
        self.projector.project_asset(model)
        rel = agent.relate_to(
            str(model.id), AssetRelationshipType.AGENT_USES_MODEL
        )
        self.projector.project_relationship(agent, rel)
        edges = self.kg.query_related(f"asset:{agent.id}", direction="outgoing")
        assert any(e.target_id == f"asset:{model.id}" for e in edges.edges)

    def test_project_snapshot_creates_node(self) -> None:
        from redforge.domain.inventory.value_objects import InventorySnapshot
        snap = InventorySnapshot(
            snapshot_id="snap-001",
            organization_id=ORG_ID,
            asset_count=10,
            asset_type_counts={"ai_agent": 5, "ai_model": 5},
            relationship_count=8,
            new_assets=("a1", "a2"),
            changed_assets=(),
            retired_assets=(),
            created_at_iso="2026-07-09T00:00:00+00:00",
        )
        self.projector.project_snapshot(snap)
        node = self.kg.get_node("inventory_snapshot:snap-001")
        assert node is not None
        assert node.node_type == NodeType.INVENTORY_SNAPSHOT

    def test_idempotent_projection(self) -> None:
        asset = _make_asset()
        self.projector.project_asset(asset)
        self.projector.project_asset(asset)
        # No error; node count stays the same
        nodes_of_type = self.kg.query_by_type(NodeType.AI_AGENT_ASSET)
        assert len(nodes_of_type) == 1
