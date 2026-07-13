"""Unit tests for the Enterprise AI Asset & Inventory domain layer.

Tests value objects, AIAsset entity lifecycle, fingerprinting, events,
exceptions, and relationship/dependency management.
"""

from __future__ import annotations

import pytest

from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.events import (
    AssetDependencyAdded,
    AssetDependencyRemoved,
    AssetFingerprintChanged,
    AssetHealthUpdated,
    AssetLifecycleChanged,
    AssetOwnerChanged,
    AssetRegistered,
    AssetRelationshipAdded,
    AssetRelationshipRemoved,
)
from redforge.domain.inventory.exceptions import (
    AssetAlreadyRetiredError,
    DuplicateRelationshipError,
    InvalidLifecycleTransitionError,
    RelationshipNotFoundError,
)
from redforge.domain.inventory.value_objects import (
    AssetDependencyRef,
    AssetDiscoverySource,
    AssetFingerprint,
    AssetHealthMetrics,
    AssetHealthStatus,
    AssetLifecycleStage,
    AssetMetadata,
    AssetOwner,
    AssetRelationshipType,
    AssetType,
    AssetVersion,
    InventorySnapshot,
)
from redforge.shared.identifiers import EntityId

# ─── Helpers ──────────────────────────────────────────────────────────────────

ORG = EntityId.generate()


def _make_asset(**kwargs: object) -> AIAsset:
    defaults: dict[str, object] = dict(
        organization_id=ORG,
        asset_type=AssetType.AI_AGENT,
        name="Test Agent",
        description="A test AI agent",
        fingerprint_fields={"model_id": "gpt-4o", "version": "2024-05-13"},
        discovery_source=AssetDiscoverySource.MANUAL,
        external_id="agent-001",
    )
    defaults.update(kwargs)
    return AIAsset.register(**defaults)  # type: ignore[arg-type]


# ─── AssetType ────────────────────────────────────────────────────────────────


class TestAssetType:
    def test_all_thirteen_types(self) -> None:
        # M3 added 5 generic non-AI types (APPLICATION, URL, HOST,
        # IP_ADDRESS, CLOUD_RESOURCE) to prove the aggregate generalizes
        # beyond AI-only inventory — 13 original AI types + 5 = 18.
        # M6 added 3 more (NETWORK, DEVICE, SERVICE) — 18 + 3 = 21.
        # M7 added 1 more (CLOUD_ACCOUNT) — 21 + 1 = 22.
        assert len(AssetType) == 22

    def test_key_values(self) -> None:
        assert AssetType.AI_APPLICATION == "ai_application"
        assert AssetType.AI_AGENT == "ai_agent"
        assert AssetType.MCP_SERVER == "mcp_server"
        assert AssetType.RAG_SYSTEM == "rag_system"
        assert AssetType.VECTOR_DATABASE == "vector_database"
        assert AssetType.EMBEDDING_MODEL == "embedding_model"


# ─── AssetLifecycleStage ──────────────────────────────────────────────────────


class TestAssetLifecycleStage:
    def test_four_stages(self) -> None:
        assert len(AssetLifecycleStage) == 4

    def test_values(self) -> None:
        assert AssetLifecycleStage.DISCOVERY == "discovery"
        assert AssetLifecycleStage.ACTIVE == "active"
        assert AssetLifecycleStage.DEPRECATED == "deprecated"
        assert AssetLifecycleStage.RETIRED == "retired"


# ─── AssetRelationshipType ────────────────────────────────────────────────────


class TestAssetRelationshipType:
    def test_fifteen_types(self) -> None:
        # M6 added 4 network relationship types (IP_ASSIGNED_TO_HOST,
        # HOST_EXPOSES_SERVICE, DEVICE_CONNECTED_TO_NETWORK,
        # IP_MEMBER_OF_NETWORK) — 15 + 4 = 19.
        # M7 added 1 more (CLOUD_ACCOUNT_CONTAINS_RESOURCE) — 19 + 1 = 20.
        # M12 added 1 more (TARGET_RESOLVES_TO_IP) — 20 + 1 = 21.
        assert len(AssetRelationshipType) == 21

    def test_key_values(self) -> None:
        assert AssetRelationshipType.APP_OWNS_AGENT == "app_owns_agent"
        assert AssetRelationshipType.AGENT_USES_MODEL == "agent_uses_model"
        assert AssetRelationshipType.RAG_USES_VECTOR_DB == "rag_uses_vector_db"
        assert AssetRelationshipType.PROVIDER_HOSTS_MODEL == "provider_hosts_model"


# ─── AssetFingerprint ─────────────────────────────────────────────────────────


class TestAssetFingerprint:
    def test_deterministic(self) -> None:
        fields = {"model": "gpt-4o", "version": "2024"}
        fp1 = AssetFingerprint.compute(fields)
        fp2 = AssetFingerprint.compute(fields)
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_order_independent(self) -> None:
        fp1 = AssetFingerprint.compute({"a": "1", "b": "2"})
        fp2 = AssetFingerprint.compute({"b": "2", "a": "1"})
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_different_inputs_different_hash(self) -> None:
        fp1 = AssetFingerprint.compute({"model": "gpt-4o"})
        fp2 = AssetFingerprint.compute({"model": "gpt-4-turbo"})
        assert fp1.fingerprint_hash != fp2.fingerprint_hash

    def test_differs_from(self) -> None:
        fp1 = AssetFingerprint.compute({"x": "1"})
        fp2 = AssetFingerprint.compute({"x": "2"})
        assert fp1.differs_from(fp2)
        assert not fp1.differs_from(fp1)

    def test_algorithm_field(self) -> None:
        fp = AssetFingerprint.compute({"k": "v"})
        assert fp.algorithm == "sha256"
        assert len(fp.fingerprint_hash) == 64

    def test_empty_fields_stable(self) -> None:
        fp1 = AssetFingerprint.compute({})
        fp2 = AssetFingerprint.compute({})
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_fingerprint_data_is_canonical_json(self) -> None:
        fp = AssetFingerprint.compute({"b": "2", "a": "1"})
        assert fp.fingerprint_data.index('"a"') < fp.fingerprint_data.index('"b"')


# ─── AssetVersion ─────────────────────────────────────────────────────────────


class TestAssetVersion:
    def test_frozen(self) -> None:
        v = AssetVersion(
            version_tag="1.0.0",
            fingerprint_hash="abc123",
            recorded_at_iso="2026-07-09T00:00:00+00:00",
        )
        with pytest.raises(AttributeError):
            v.version_tag = "2.0.0"  # type: ignore[misc]

    def test_defaults(self) -> None:
        v = AssetVersion(
            version_tag="1.0.0",
            fingerprint_hash="abc",
            recorded_at_iso="2026-07-09T00:00:00+00:00",
        )
        assert v.change_summary == ""


# ─── AssetMetadata ────────────────────────────────────────────────────────────


class TestAssetMetadata:
    def test_with_entry(self) -> None:
        m = AssetMetadata()
        m2 = m.with_entry("key", "value")
        assert m2.get("key") == "value"
        assert m.is_empty  # original unchanged

    def test_without_entry(self) -> None:
        m = AssetMetadata(entries={"a": "1", "b": "2"})
        m2 = m.without_entry("a")
        assert m2.get("a") == ""
        assert m2.get("b") == "2"

    def test_get_default(self) -> None:
        m = AssetMetadata()
        assert m.get("missing", "fallback") == "fallback"


# ─── AssetOwner ───────────────────────────────────────────────────────────────


class TestAssetOwner:
    def test_frozen(self) -> None:
        o = AssetOwner(owner_id="u-1", owner_name="Alice")
        with pytest.raises(AttributeError):
            o.owner_id = "u-2"  # type: ignore[misc]

    def test_defaults(self) -> None:
        o = AssetOwner(owner_id="u-1", owner_name="Alice")
        assert o.owner_type == "team"
        assert o.contact_email == ""


# ─── InventorySnapshot ────────────────────────────────────────────────────────


class TestInventorySnapshot:
    def test_has_changes_true(self) -> None:
        snap = InventorySnapshot(
            snapshot_id="snap-1",
            organization_id="org-1",
            asset_count=5,
            asset_type_counts={"ai_agent": 5},
            relationship_count=3,
            new_assets=("a1",),
            changed_assets=(),
            retired_assets=(),
            created_at_iso="2026-07-09T00:00:00+00:00",
        )
        assert snap.has_changes

    def test_has_changes_false(self) -> None:
        snap = InventorySnapshot(
            snapshot_id="snap-2",
            organization_id="org-1",
            asset_count=5,
            asset_type_counts={"ai_agent": 5},
            relationship_count=3,
            new_assets=(),
            changed_assets=(),
            retired_assets=(),
            created_at_iso="2026-07-09T00:00:00+00:00",
        )
        assert not snap.has_changes


# ─── AIAsset entity ───────────────────────────────────────────────────────────


class TestAIAssetRegister:
    def test_register_creates_asset(self) -> None:
        asset = _make_asset()
        assert asset.name == "Test Agent"
        assert asset.asset_type == AssetType.AI_AGENT
        assert asset.lifecycle_stage == AssetLifecycleStage.DISCOVERY
        assert asset.health_status == AssetHealthStatus.UNKNOWN

    def test_register_emits_event(self) -> None:
        asset = _make_asset()
        events = asset.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], AssetRegistered)

    def test_event_cleared_after_collect(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        assert asset.collect_events() == []

    def test_initial_version_history_has_one_entry(self) -> None:
        asset = _make_asset()
        assert len(asset.version_history) == 1
        assert asset.current_version.version_tag == "1.0.0"

    def test_id_is_entity_id(self) -> None:
        asset = _make_asset()
        assert isinstance(asset.id, EntityId)

    def test_organization_id_preserved(self) -> None:
        asset = _make_asset()
        assert asset.organization_id == ORG

    def test_discover_factory(self) -> None:
        asset = AIAsset.discover(
            organization_id=ORG,
            asset_type=AssetType.MCP_SERVER,
            name="Prod MCP",
            description="MCP server",
            fingerprint_fields={"server_id": "mcp-prod"},
            external_id="mcp-prod-001",
            discovery_source=AssetDiscoverySource.API_SCAN,
        )
        assert asset.discovery_source == AssetDiscoverySource.API_SCAN
        assert asset.external_id == "mcp-prod-001"
        assert asset.lifecycle_stage == AssetLifecycleStage.DISCOVERY


# ─── Lifecycle ────────────────────────────────────────────────────────────────


class TestAIAssetLifecycle:
    def test_discovery_to_active(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)
        assert asset.lifecycle_stage == AssetLifecycleStage.ACTIVE

    def test_active_to_deprecated(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)
        asset.advance_lifecycle(AssetLifecycleStage.DEPRECATED)
        assert asset.lifecycle_stage == AssetLifecycleStage.DEPRECATED

    def test_deprecated_to_active(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)
        asset.advance_lifecycle(AssetLifecycleStage.DEPRECATED)
        asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)
        assert asset.lifecycle_stage == AssetLifecycleStage.ACTIVE

    def test_discovery_to_retired(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.RETIRED)
        assert asset.is_retired

    def test_retired_is_terminal(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.RETIRED)
        with pytest.raises(AssetAlreadyRetiredError):
            asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)

    def test_invalid_transition_raises(self) -> None:
        asset = _make_asset()  # DISCOVERY
        with pytest.raises(InvalidLifecycleTransitionError):
            asset.advance_lifecycle(AssetLifecycleStage.DEPRECATED)

    def test_lifecycle_event_emitted(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.advance_lifecycle(AssetLifecycleStage.ACTIVE)
        events = asset.collect_events()
        assert any(isinstance(e, AssetLifecycleChanged) for e in events)
        lc_event = next(e for e in events if isinstance(e, AssetLifecycleChanged))
        assert lc_event.from_stage == "discovery"
        assert lc_event.to_stage == "active"


# ─── Fingerprint ──────────────────────────────────────────────────────────────


class TestAIAssetFingerprint:
    def test_update_fingerprint_detects_change(self) -> None:
        asset = _make_asset()
        changed = asset.update_fingerprint(
            new_fingerprint_fields={"model_id": "gpt-4-turbo", "version": "2024"},
            version_tag="1.1.0",
        )
        assert changed

    def test_update_fingerprint_no_change(self) -> None:
        asset = _make_asset()
        changed = asset.update_fingerprint(
            new_fingerprint_fields={"model_id": "gpt-4o", "version": "2024-05-13"},
            version_tag="1.1.0",
        )
        assert not changed

    def test_version_history_grows_on_change(self) -> None:
        asset = _make_asset()
        asset.update_fingerprint({"model_id": "gpt-4-turbo"}, "1.1.0")
        assert len(asset.version_history) == 2

    def test_fingerprint_changed_event_emitted(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.update_fingerprint({"model_id": "new-model"}, "1.1.0")
        events = asset.collect_events()
        assert any(isinstance(e, AssetFingerprintChanged) for e in events)

    def test_no_event_when_unchanged(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.update_fingerprint(
            {"model_id": "gpt-4o", "version": "2024-05-13"}, "same"
        )
        assert asset.collect_events() == []

    def test_retired_asset_cannot_update_fingerprint(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.RETIRED)
        asset.collect_events()
        with pytest.raises(AssetAlreadyRetiredError):
            asset.update_fingerprint({"model_id": "new"}, "2.0.0")


# ─── Health ───────────────────────────────────────────────────────────────────


class TestAIAssetHealth:
    def test_update_health(self) -> None:
        asset = _make_asset()
        asset.update_health(AssetHealthStatus.HEALTHY)
        assert asset.health_status == AssetHealthStatus.HEALTHY

    def test_health_event_emitted(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.update_health(AssetHealthStatus.DEGRADED)
        events = asset.collect_events()
        assert any(isinstance(e, AssetHealthUpdated) for e in events)
        hev = next(e for e in events if isinstance(e, AssetHealthUpdated))
        assert hev.old_health == "unknown"
        assert hev.new_health == "degraded"

    def test_update_health_with_metrics(self) -> None:
        asset = _make_asset()
        metrics = AssetHealthMetrics(
            last_checked_at_iso="2026-07-09T00:00:00+00:00",
            latency_ms=120,
            error_rate=0.01,
        )
        asset.update_health(AssetHealthStatus.HEALTHY, metrics)
        assert asset.health_metrics is not None
        assert asset.health_metrics.latency_ms == 120


# ─── Ownership ────────────────────────────────────────────────────────────────


class TestAIAssetOwnership:
    def test_assign_owner(self) -> None:
        asset = _make_asset()
        owner = AssetOwner(owner_id="team-42", owner_name="AI Platform Team")
        asset.assign_owner(owner)
        assert asset.owner is not None
        assert asset.owner.owner_id == "team-42"

    def test_owner_change_emits_event(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.assign_owner(AssetOwner(owner_id="u-1", owner_name="Alice"))
        events = asset.collect_events()
        assert any(isinstance(e, AssetOwnerChanged) for e in events)
        oc = next(e for e in events if isinstance(e, AssetOwnerChanged))
        assert oc.old_owner_id is None
        assert oc.new_owner_id == "u-1"


# ─── Dependencies ─────────────────────────────────────────────────────────────


class TestAIAssetDependencies:
    def test_add_dependency(self) -> None:
        asset = _make_asset()
        dep = AssetDependencyRef(
            dependency_id="model-asset-id",
            relationship_type=AssetRelationshipType.AGENT_USES_MODEL,
        )
        asset.add_dependency(dep)
        assert asset.dependency_count == 1
        assert asset.has_dependency_on("model-asset-id")

    def test_add_duplicate_dependency_is_idempotent(self) -> None:
        asset = _make_asset()
        dep = AssetDependencyRef("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        asset.add_dependency(dep)
        asset.add_dependency(dep)
        assert asset.dependency_count == 1

    def test_remove_dependency(self) -> None:
        asset = _make_asset()
        dep = AssetDependencyRef("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        asset.add_dependency(dep)
        asset.remove_dependency("model-id")
        assert asset.dependency_count == 0

    def test_dependency_event_emitted(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.add_dependency(
            AssetDependencyRef("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        )
        events = asset.collect_events()
        assert any(isinstance(e, AssetDependencyAdded) for e in events)

    def test_remove_dependency_event_emitted(self) -> None:
        asset = _make_asset()
        asset.add_dependency(
            AssetDependencyRef("m-id", AssetRelationshipType.AGENT_USES_MODEL)
        )
        asset.collect_events()
        asset.remove_dependency("m-id")
        events = asset.collect_events()
        assert any(isinstance(e, AssetDependencyRemoved) for e in events)

    def test_retired_asset_cannot_add_dependency(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.RETIRED)
        asset.collect_events()
        with pytest.raises(AssetAlreadyRetiredError):
            asset.add_dependency(
                AssetDependencyRef("m", AssetRelationshipType.AGENT_USES_MODEL)
            )


# ─── Relationships ────────────────────────────────────────────────────────────


class TestAIAssetRelationships:
    def test_relate_to(self) -> None:
        asset = _make_asset()
        rel = asset.relate_to("model-asset-id", AssetRelationshipType.AGENT_USES_MODEL)
        assert asset.relationship_count == 1
        assert rel.target_asset_id == "model-asset-id"

    def test_duplicate_relationship_raises(self) -> None:
        asset = _make_asset()
        asset.relate_to("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        with pytest.raises(DuplicateRelationshipError):
            asset.relate_to("model-id", AssetRelationshipType.AGENT_USES_MODEL)

    def test_remove_relationship(self) -> None:
        asset = _make_asset()
        rel = asset.relate_to("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        asset.remove_relationship(rel.relationship_id)
        assert asset.relationship_count == 0

    def test_remove_nonexistent_raises(self) -> None:
        asset = _make_asset()
        with pytest.raises(RelationshipNotFoundError):
            asset.remove_relationship("nonexistent-rel-id")

    def test_relationship_event_emitted(self) -> None:
        asset = _make_asset()
        asset.collect_events()
        asset.relate_to("other-id", AssetRelationshipType.AGENT_USES_TOOL)
        events = asset.collect_events()
        assert any(isinstance(e, AssetRelationshipAdded) for e in events)

    def test_remove_relationship_event_emitted(self) -> None:
        asset = _make_asset()
        rel = asset.relate_to("other-id", AssetRelationshipType.AGENT_USES_TOOL)
        asset.collect_events()
        asset.remove_relationship(rel.relationship_id)
        events = asset.collect_events()
        assert any(isinstance(e, AssetRelationshipRemoved) for e in events)

    def test_get_relationships_by_type(self) -> None:
        asset = _make_asset()
        asset.relate_to("model-id", AssetRelationshipType.AGENT_USES_MODEL)
        asset.relate_to("mcp-id", AssetRelationshipType.AGENT_USES_MCP)
        model_rels = asset.get_relationships_by_type(AssetRelationshipType.AGENT_USES_MODEL)
        assert len(model_rels) == 1
        assert model_rels[0].target_asset_id == "model-id"

    def test_retired_asset_cannot_relate(self) -> None:
        asset = _make_asset()
        asset.advance_lifecycle(AssetLifecycleStage.RETIRED)
        asset.collect_events()
        with pytest.raises(AssetAlreadyRetiredError):
            asset.relate_to("other", AssetRelationshipType.AGENT_USES_MODEL)


# ─── Equality & repr ──────────────────────────────────────────────────────────


class TestAIAssetEquality:
    def test_equal_by_id(self) -> None:
        asset1 = _make_asset()
        asset2 = _make_asset()
        assert asset1 != asset2

    def test_hash_by_id(self) -> None:
        asset = _make_asset()
        s: set[AIAsset] = {asset}
        assert asset in s

    def test_repr(self) -> None:
        asset = _make_asset()
        r = repr(asset)
        assert "AIAsset" in r
        assert "ai_agent" in r
