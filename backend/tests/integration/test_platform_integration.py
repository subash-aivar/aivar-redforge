"""Platform integration tests — Sprint 24.

Tests the full event → store → projection → read model pipeline,
replay engine across all 8 dimensions, timeline service, multi-tenant
isolation, and projection correctness.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.application.knowledge_graph import KnowledgeGraph
from redforge.application.platform.event_store import InMemoryEventStore
from redforge.application.platform.projection_engine import (
    InMemoryReadModelRepository,
    ProjectionEngine,
)
from redforge.application.platform.projections.campaign_projection import CampaignProjection
from redforge.application.platform.projections.connector_activity_projection import (
    ConnectorActivityProjection,
)
from redforge.application.platform.projections.intelligence_projection import IntelligenceProjection
from redforge.application.platform.projections.inventory_projection import InventoryProjection
from redforge.application.platform.projections.kg_projection import KGProjection
from redforge.application.platform.projections.organization_activity_projection import (
    OrganizationActivityProjection,
)
from redforge.application.platform.projections.risk_projection import RiskProjection
from redforge.application.platform.projections.validation_projection import ValidationProjection
from redforge.application.platform.replay_engine import ReplayEngine
from redforge.application.platform.timeline_service import TimelineService
from redforge.domain.platform.events import EventBatch, EventEnvelope, make_envelope
from redforge.domain.platform.value_objects import ReplayCursor

_ORG_A = "01KX3FWDMBVJTKGWNE273CN46A"
_ORG_B = "01KX3FWDMBVJTKGWNE273CN46B"
_NOW = datetime.now(UTC)


def _env(
    event_type: str,
    agg_id: str = "agg-1",
    org: str = _ORG_A,
    stream_prefix: str | None = None,
    correlation_id: str | None = None,
    occurred_at: datetime | None = None,
) -> EventEnvelope:
    prefix = stream_prefix or event_type.split(".")[0]
    return make_envelope(
        payload={},
        event_type=event_type,
        aggregate_type=event_type.split(".")[0],
        aggregate_id=agg_id,
        stream_id=f"{prefix}:{agg_id}",
        organization_id=org,
        correlation_id=correlation_id,
        occurred_at=occurred_at,
    )


async def _append(store: InMemoryEventStore, envelope: EventEnvelope) -> EventEnvelope:
    batch = EventBatch(
        stream_id=envelope.stream_id,
        organization_id=envelope.organization_id,
        events=(envelope,),
    )
    stored = await store.append(batch)
    return stored[0]


# ── Full pipeline: Store → Projection → ReadModel ─────────────────────────

class TestCampaignProjectionPipeline:
    @pytest.mark.asyncio
    async def test_campaign_lifecycle(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = CampaignProjection(repo)
        proj.register_with(engine)

        await _append(store, _env("campaign.CampaignCreated", "c1"))
        await _append(store, _env("campaign.CampaignStarted", "c1"))
        await _append(store, _env("campaign.CampaignCreated", "c2"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_campaigns == 2
        assert model.campaigns_by_status.get("running", 0) == 1
        assert "c1" in model.active_campaign_ids

    @pytest.mark.asyncio
    async def test_campaign_completed_removed_from_active(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = CampaignProjection(repo)
        proj.register_with(engine)

        await _append(store, _env("campaign.CampaignCreated", "c1"))
        await _append(store, _env("campaign.CampaignStarted", "c1"))
        await _append(store, _env("campaign.CampaignCompleted", "c1"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert "c1" not in model.active_campaign_ids


class TestInventoryProjectionPipeline:
    @pytest.mark.asyncio
    async def test_asset_creation_tracked(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = InventoryProjection(repo)
        proj.register_with(engine)

        for i in range(5):
            await _append(store, _env("inventory.AIAssetCreated", f"asset-{i}"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_assets == 5


class TestValidationProjectionPipeline:
    @pytest.mark.asyncio
    async def test_pass_rate_calculated(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = ValidationProjection(repo)
        proj.register_with(engine)

        # 3 started, 2 passed
        for i in range(3):
            await _append(store, _env("validation.ValidationRunStarted", f"v{i}"))
        for i in range(2):
            await _append(store, _env("validation.ValidationPassed", f"v{i}"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_validations == 3
        assert abs(model.pass_rate - (2 / 3)) < 0.01


class TestOrganizationActivityProjection:
    @pytest.mark.asyncio
    async def test_counts_all_events(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = OrganizationActivityProjection(repo)
        proj.register_with(engine)

        for et in ["campaign.Created", "evidence.Collected", "findings.Created"]:
            await _append(store, _env(et))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_events == 3

    @pytest.mark.asyncio
    async def test_bounded_context_breakdown(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = OrganizationActivityProjection(repo)
        proj.register_with(engine)

        await _append(store, _env("campaign.Created"))
        await _append(store, _env("campaign.Started"))
        await _append(store, _env("evidence.Collected"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.events_by_bounded_context.get("campaign", 0) == 2
        assert model.events_by_bounded_context.get("evidence", 0) == 1


# ── Multi-tenant isolation ────────────────────────────────────────────────

class TestMultiTenantIsolation:
    @pytest.mark.asyncio
    async def test_projections_scoped_per_org(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = OrganizationActivityProjection(repo)
        proj.register_with(engine)

        for _ in range(3):
            await _append(store, _env("campaign.Created", org=_ORG_A))
        for _ in range(5):
            await _append(store, _env("campaign.Created", org=_ORG_B))

        await engine.catch_up(store, _ORG_A)
        await engine.catch_up(store, _ORG_B)

        model_a = await proj.get(_ORG_A)
        model_b = await proj.get(_ORG_B)
        assert model_a is not None and model_a.total_events == 3
        assert model_b is not None and model_b.total_events == 5

    @pytest.mark.asyncio
    async def test_read_all_isolated_per_org(self) -> None:
        store = InMemoryEventStore()
        for _ in range(3):
            await _append(store, _env("t.T", org=_ORG_A))
        for _ in range(7):
            await _append(store, _env("t.T", org=_ORG_B))

        events_a = await store.read_all(_ORG_A)
        events_b = await store.read_all(_ORG_B)
        assert len(events_a) == 3
        assert len(events_b) == 7


# ── Replay Engine ─────────────────────────────────────────────────────────

class TestReplayEngine:
    @pytest.mark.asyncio
    async def test_replay_organization(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for _ in range(5):
            await _append(store, _env("t.T"))

        results = await engine.collect(engine.replay_organization(_ORG_A))
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_replay_stream(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for _ in range(3):
            await _append(store, _env("campaign.Created", "c1"))
        for _ in range(2):
            await _append(store, _env("campaign.Created", "c2"))

        results = await engine.collect(engine.replay_stream("campaign:c1", _ORG_A))
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_replay_aggregate(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for _ in range(4):
            await _append(store, _env("campaign.Created", "target-agg"))
        for _ in range(2):
            await _append(store, _env("campaign.Created", "other-agg"))

        results = await engine.collect(
            engine.replay_aggregate("campaign", "target-agg", _ORG_A)
        )
        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_replay_by_correlation_id(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for i in range(3):
            await _append(store, _env("t.T", f"a{i}", correlation_id="my-corr"))
        for i in range(2):
            await _append(store, _env("t.T", f"b{i}", correlation_id="other-corr"))

        results = await engine.collect(
            engine.replay_by_correlation_id("my-corr", _ORG_A)
        )
        assert len(results) == 3
        assert all(e.correlation_id == "my-corr" for e in results)

    @pytest.mark.asyncio
    async def test_replay_by_event_type(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for _ in range(3):
            await _append(store, _env("campaign.Created"))
        for _ in range(4):
            await _append(store, _env("campaign.Started"))

        results = await engine.collect(
            engine.replay_by_event_type("campaign.Created", _ORG_A)
        )
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_replay_by_time_range(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        past = _NOW - timedelta(hours=5)
        recent = _NOW - timedelta(minutes=30)

        await _append(store, _env("t.T", occurred_at=past))
        await _append(store, _env("t.T", occurred_at=recent))
        await _append(store, _env("t.T", occurred_at=_NOW))

        from_dt = _NOW - timedelta(hours=1)
        results = await engine.collect(
            engine.replay_by_time_range(_ORG_A, from_dt, _NOW)
        )
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_replay_from_cursor_paginates(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for _ in range(20):
            await _append(store, _env("t.T"))

        cursor = ReplayCursor.beginning()
        page1, cursor2 = await engine.replay_from_cursor(cursor, _ORG_A, max_events=10)
        page2, cursor3 = await engine.replay_from_cursor(cursor2, _ORG_A, max_events=10)
        _, final = await engine.replay_from_cursor(cursor3, _ORG_A, max_events=10)

        assert len(page1) == 10
        assert len(page2) == 10
        assert final.is_exhausted

    @pytest.mark.asyncio
    async def test_replay_aggregate_type(self) -> None:
        store = InMemoryEventStore()
        engine = ReplayEngine(store)
        for i in range(3):
            await _append(store, _env("Campaign.Created", f"c{i}", stream_prefix="Campaign"))
        for i in range(2):
            await _append(store, _env("Evidence.Collected", f"e{i}", stream_prefix="Evidence"))

        results = await engine.collect(
            engine.replay_aggregate_type("Campaign", _ORG_A)
        )
        assert len(results) == 3


# ── Timeline Service ───────────────────────────────────────────────────────

class TestTimelineService:
    @pytest.mark.asyncio
    async def test_get_timeline_for_subject(self) -> None:
        store = InMemoryEventStore()
        svc = TimelineService(store)

        for _ in range(3):
            await _append(store, _env("campaign.Updated", "c1", stream_prefix="campaign"))

        timeline = await svc.get_timeline("campaign", "c1", _ORG_A)
        assert not timeline.is_empty
        assert timeline.total_events == 3
        assert timeline.subject_type == "campaign"

    @pytest.mark.asyncio
    async def test_get_audit_timeline_with_actor_summary(self) -> None:
        store = InMemoryEventStore()
        svc = TimelineService(store)

        ev1 = make_envelope(
            payload={}, event_type="campaign.Updated",
            aggregate_type="campaign", aggregate_id="c1",
            stream_id="campaign:c1", organization_id=_ORG_A,
            actor_id="user-1",
        )
        ev2 = make_envelope(
            payload={}, event_type="campaign.Updated",
            aggregate_type="campaign", aggregate_id="c1",
            stream_id="campaign:c1", organization_id=_ORG_A,
            actor_id="user-2",
        )
        await _append(store, ev1)
        await _append(store, ev2)

        audit = await svc.get_audit_timeline("campaign", "c1", _ORG_A)
        assert "user-1" in audit.actor_summary
        assert "user-2" in audit.actor_summary

    @pytest.mark.asyncio
    async def test_empty_timeline_for_missing_subject(self) -> None:
        store = InMemoryEventStore()
        svc = TimelineService(store)
        timeline = await svc.get_timeline("campaign", "nonexistent", _ORG_A)
        assert timeline.is_empty


# ── KG Projection as consumer ─────────────────────────────────────────────

class TestKGProjection:
    @pytest.mark.asyncio
    async def test_asset_events_populate_kg(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        graph = KnowledgeGraph()
        engine = ProjectionEngine()
        proj = KGProjection(graph, repo)
        proj.register_with(engine)

        for i in range(3):
            await _append(store, _env("inventory.AIAssetCreated", f"asset-{i}"))

        await engine.catch_up(store, _ORG_A)
        assert graph.node_count >= 3

    @pytest.mark.asyncio
    async def test_connector_events_add_nodes(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        graph = KnowledgeGraph()
        engine = ProjectionEngine()
        proj = KGProjection(graph, repo)
        proj.register_with(engine)

        await _append(store, _env("connector.ConnectorRegistered", "conn-1"))
        await engine.catch_up(store, _ORG_A)
        assert graph.has_node("connector:conn-1")


# ── Connector Activity Projection ─────────────────────────────────────────

class TestConnectorActivityProjection:
    @pytest.mark.asyncio
    async def test_discovery_tracked(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = ConnectorActivityProjection(repo)
        proj.register_with(engine)

        await _append(store, _env("connector.ConnectorEnabled", "conn-1"))
        await _append(store, _env("connector.DiscoveryJobCompleted", "conn-1"))
        await _append(store, _env("connector.SyncJobCompleted", "conn-1"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.active_connectors == 1
        assert model.total_discoveries == 1
        assert model.total_syncs == 1


# ── Risk and Intelligence ─────────────────────────────────────────────────

class TestRiskProjection:
    @pytest.mark.asyncio
    async def test_finding_severity_counted(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = RiskProjection(repo)
        proj.register_with(engine)

        ev = make_envelope(
            payload={}, event_type="findings.FindingCreated",
            aggregate_type="findings", aggregate_id="f1",
            stream_id="findings:f1", organization_id=_ORG_A,
        )
        ev2 = ev.with_metadata("severity", "critical")
        await _append(store, ev2)

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.critical_findings == 1


class TestIntelligenceProjection:
    @pytest.mark.asyncio
    async def test_insights_counted(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = IntelligenceProjection(repo)
        proj.register_with(engine)

        for _ in range(4):
            await _append(store, _env("intelligence.InsightGenerated", "ins-1"))

        await engine.catch_up(store, _ORG_A)
        model = await proj.get(_ORG_A)
        assert model is not None
        assert model.total_insights == 4


# ── Checkpoint recovery ───────────────────────────────────────────────────

class TestCheckpointRecovery:
    @pytest.mark.asyncio
    async def test_catch_up_from_checkpoint_skips_already_processed(self) -> None:
        store = InMemoryEventStore()
        repo = InMemoryReadModelRepository()
        engine = ProjectionEngine()
        proj = OrganizationActivityProjection(repo)
        proj.register_with(engine)

        # Write 10 events
        for _ in range(10):
            await _append(store, _env("t.T"))

        # First catch-up processes all 10
        count1 = await engine.catch_up(store, _ORG_A, from_position=0)
        assert count1 == 10

        # Write 5 more
        for _ in range(5):
            await _append(store, _env("t.T"))

        # Second catch-up from position 10 processes only 5 new events
        count2 = await engine.catch_up(store, _ORG_A, from_position=10)
        assert count2 == 5
