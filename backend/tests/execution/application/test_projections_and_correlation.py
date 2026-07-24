"""M29 Phase 6 — projections, detection correlation, replay, ontology."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4, uuid7

import pytest

from engagement.domain.events.engagement_events import EngagementCreated
from engagement.domain.value_objects.identifiers import TenantId as EngagementTenantId
from engagement.infrastructure.graph import (
    InMemorySecurityGraphWriteAdapter as EngagementGraphAdapter,
)
from execution.application.projections.projection_coordinator import ProjectionCoordinator
from execution.application.projections.projection_publisher import ProjectionPublisher
from execution.application.projections.read_model_store import InMemoryReadModelStore
from execution.application.projections.red_team_projection_service import (
    RedTeamProjectionService,
)
from execution.application.services.detection_correlation_service import (
    CorrelateDetectionFinding,
    DetectionCorrelationService,
    DetectionFindingProducedDTO,
)
from execution.application.services.projection_application_service import (
    ProjectionApplicationService,
)
from execution.application.services.replay_application_service import (
    ReplayApplicationService,
    ReplayAttackActionExecution,
)
from execution.domain.events.pipeline_events import (
    AttackActionAuthorized,
    AttackActionCompleted,
    AttackActionStarted,
)
from execution.domain.value_objects.identifiers import TenantId
from execution.infrastructure.graph import InMemorySecurityGraphWriteAdapter
from operation.domain.events.operation_events import OperationCreated
from operation.domain.value_objects.identifiers import TenantId as OperationTenantId
from operation.infrastructure.graph import (
    InMemorySecurityGraphWriteAdapter as OperationGraphAdapter,
)
from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)
from redforge.shared.identifiers import EntityId


def _tenant() -> TenantId:
    return TenantId(uuid7())


def _now() -> datetime:
    return datetime.now(UTC)


def _build_stack():
    store = InMemoryReadModelStore()
    graph = InMemorySecurityGraphWriteAdapter()
    eng_graph = EngagementGraphAdapter()
    op_graph = OperationGraphAdapter()
    publisher = ProjectionPublisher()
    projections = RedTeamProjectionService(store)
    coordinator = ProjectionCoordinator(
        publisher,
        projections,
        graph,
        engagement_graph=eng_graph,
        operation_graph=op_graph,
    )
    correlation = DetectionCorrelationService(coordinator, graph)
    facade = ProjectionApplicationService(
        coordinator, store, correlation=correlation
    )
    return facade, coordinator, store, graph, correlation


@pytest.mark.asyncio
async def test_graph_node_on_attack_action_started() -> None:
    facade, _coord, _store, graph, _corr = _build_stack()
    tenant = _tenant()
    now = _now()
    action_id = str(uuid7())
    engagement_id = str(uuid7())
    operation_id = str(uuid7())
    events = [
        AttackActionAuthorized(
            event_id=str(uuid7()),
            occurred_at=now,
            tenant_id=tenant,
            aggregate_id=action_id,
            aggregate_type="AttackAction",
            engagement_id=engagement_id,
            operation_id=operation_id,
            step_id=str(uuid7()),
            target_id=str(uuid7()),
            technique_id="T1059",
            operator_id=str(uuid7()),
            action_hash="a" * 64,
        ),
        AttackActionStarted(
            event_id=str(uuid7()),
            occurred_at=now,
            tenant_id=tenant,
            aggregate_id=action_id,
            aggregate_type="AttackAction",
            engagement_id=engagement_id,
            operation_id=operation_id,
            worker_id=str(uuid7()),
            execution_timestamp=now,
        ),
    ]
    await facade.handle_batch(events)
    key = (str(tenant.value), "attack_action", action_id)
    assert key in graph.nodes
    assert graph.nodes[key].node_kind == "attack_action"
    assert any(e.relationship_kind == "executed_action" for e in graph.edges.values())


@pytest.mark.asyncio
async def test_detection_correlation_within_30_min_caught() -> None:
    facade, _coord, store, graph, correlation = _build_stack()
    tenant = _tenant()
    now = _now()
    action_id = str(uuid7())
    engagement_id = str(uuid7())
    operation_id = str(uuid7())
    completed_at = now
    await facade.handle_batch(
        [
            AttackActionAuthorized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                step_id=str(uuid7()),
                target_id=str(uuid7()),
                technique_id="T1003",
                operator_id=str(uuid7()),
                action_hash="b" * 64,
            ),
            AttackActionStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                worker_id=None,
                execution_timestamp=now,
            ),
            AttackActionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                completion_timestamp=completed_at,
                output_hash="c" * 64,
            ),
        ]
    )
    correlation.register_action_completed(action_id, completed_at)
    result = await correlation.correlate_command(
        CorrelateDetectionFinding(
            tenant_id=str(tenant.value),
            action_id=action_id,
            finding_id=str(uuid7()),
            rule_id="rule-1",
            detected_at=completed_at + timedelta(minutes=10),
        )
    )
    assert result.outcome == "caught"
    assert any(
        e.relationship_kind == "caught_by_detection" for e in graph.edges.values()
    )
    coverage = await store.load_detection_coverage(str(tenant.value))
    assert coverage is not None
    assert coverage.detected_count == 1
    assert coverage.total_actions == 1
    assert coverage.coverage_pct == 100.0


@pytest.mark.asyncio
async def test_detection_coverage_zero_of_hundred() -> None:
    facade, _coord, store, _graph, _corr = _build_stack()
    tenant = _tenant()
    now = _now()
    engagement_id = str(uuid7())
    operation_id = str(uuid7())
    events = []
    for _ in range(100):
        action_id = str(uuid7())
        events.extend(
            [
                AttackActionAuthorized(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant,
                    aggregate_id=action_id,
                    aggregate_type="AttackAction",
                    engagement_id=engagement_id,
                    operation_id=operation_id,
                    step_id=str(uuid7()),
                    target_id=str(uuid7()),
                    technique_id="T1059",
                    operator_id=str(uuid7()),
                    action_hash="d" * 64,
                ),
                AttackActionStarted(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant,
                    aggregate_id=action_id,
                    aggregate_type="AttackAction",
                    engagement_id=engagement_id,
                    operation_id=operation_id,
                    worker_id=None,
                    execution_timestamp=now,
                ),
                AttackActionCompleted(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=tenant,
                    aggregate_id=action_id,
                    aggregate_type="AttackAction",
                    engagement_id=engagement_id,
                    operation_id=operation_id,
                    completion_timestamp=now,
                    output_hash=None,
                ),
            ]
        )
    await facade.handle_batch(events)
    coverage = await store.load_detection_coverage(str(tenant.value))
    assert coverage is not None
    assert coverage.total_actions == 100
    assert coverage.detected_count == 0
    assert coverage.coverage_pct == 0.0


@pytest.mark.asyncio
async def test_projection_replay_rebuilds_read_models() -> None:
    facade, coordinator, store, graph, _corr = _build_stack()
    tenant = _tenant()
    now = _now()
    engagement_id = str(uuid7())
    operation_id = str(uuid7())
    action_id = str(uuid7())
    await facade.handle_batch(
        [
            EngagementCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=EngagementTenantId(tenant.value),
                aggregate_id=engagement_id,
                aggregate_type="Engagement",
                classification="Internal",
                owner_id=str(uuid7()),
            ),
            OperationCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=OperationTenantId(tenant.value),
                aggregate_id=operation_id,
                aggregate_type="Operation",
                engagement_id=engagement_id,
                classification="Internal",
                name="op-1",
            ),
            AttackActionAuthorized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                step_id=str(uuid7()),
                target_id=str(uuid7()),
                technique_id="T1059",
                operator_id=str(uuid7()),
                action_hash="e" * 64,
            ),
            AttackActionStarted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                worker_id=str(uuid7()),
                execution_timestamp=now,
            ),
            AttackActionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                completion_timestamp=now,
                output_hash="f" * 64,
            ),
        ]
    )
    tech = await store.load_action_by_technique(str(tenant.value))
    assert tech is not None
    assert tech.total_actions == 1
    assert tech.by_technique.get("T1059") == 1

    await store.clear_all()
    graph.clear()
    assert await store.load_action_by_technique(str(tenant.value)) is None

    result = await coordinator.replay(organization_id=str(tenant.value))
    assert result.events_replayed >= 5
    tech2 = await store.load_action_by_technique(str(tenant.value))
    assert tech2 is not None
    assert tech2.total_actions == 1
    assert (str(tenant.value), "attack_action", action_id) in graph.nodes
    assert any(e.relationship_kind == "used_technique" for e in graph.edges.values())


@pytest.mark.asyncio
async def test_journal_replay_creates_no_side_effects() -> None:
    created_actions: list[str] = []
    evidence: list[str] = []
    journal_appends: list[str] = []

    async def loader(_cmd: ReplayAttackActionExecution):
        return {
            "journal_id": str(uuid7()),
            "engagement_id": str(uuid7()),
            "entries": [
                {
                    "sequence_number": 1,
                    "entry_type": "ActionStarted",
                    "content": "start",
                    "occurred_at": _now().isoformat(),
                    "entry_hash": "1" * 64,
                },
                {
                    "sequence_number": 2,
                    "entry_type": "ActionCompleted",
                    "content": "done",
                    "occurred_at": _now().isoformat(),
                    "entry_hash": "2" * 64,
                },
            ],
        }

    svc = ReplayApplicationService(journal_loader=loader)
    report = await svc.replay(
        ReplayAttackActionExecution(tenant_id=EntityId.generate(), engagement_id=uuid4())
    )
    assert report.attack_actions_created is False
    assert report.evidence_touched is False
    assert report.journal_appended is False
    assert report.actions_simulated == 2
    assert len(report.steps) == 2
    assert created_actions == []
    assert evidence == []
    assert journal_appends == []
    assert svc.side_effect_counters == {
        "attack_actions_created": 0,
        "evidence_collected": 0,
        "journal_appends": 0,
    }


@pytest.mark.asyncio
async def test_dto_correlation_within_window() -> None:
    facade, _coord, _store, graph, correlation = _build_stack()
    tenant = _tenant()
    now = _now()
    action_id = str(uuid7())
    engagement_id = str(uuid7())
    operation_id = str(uuid7())
    target_id = str(uuid7())
    await facade.handle_batch(
        [
            AttackActionAuthorized(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                step_id=str(uuid7()),
                target_id=target_id,
                technique_id="T1059",
                operator_id=str(uuid7()),
                action_hash="g" * 64,
            ),
            AttackActionCompleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant,
                aggregate_id=action_id,
                aggregate_type="AttackAction",
                engagement_id=engagement_id,
                operation_id=operation_id,
                completion_timestamp=now,
                output_hash=None,
            ),
        ]
    )
    correlation.register_action_completed(action_id, now)
    result = await correlation.correlate_finding(
        DetectionFindingProducedDTO(
            finding_id=str(uuid7()),
            rule_id="rule-dto",
            asset_id=target_id,
            detected_at=now + timedelta(minutes=5),
            tenant_id=str(tenant.value),
            related_technique="T1059",
            action_id=None,
        )
    )
    assert result is not None
    assert result.outcome == "caught"
    assert any(
        e.relationship_kind == "caught_by_detection" for e in graph.edges.values()
    )


def test_ontology_version_is_v15() -> None:
    assert ONTOLOGY_VERSION == 15


def test_ontology_validate_edge_new_pairs() -> None:
    validate_edge(EdgeKind.CONTAINS_OPERATION, NodeKind.ENGAGEMENT, NodeKind.OPERATION)
    validate_edge(EdgeKind.EXECUTED_ACTION, NodeKind.OPERATION, NodeKind.ATTACK_ACTION)
    validate_edge(EdgeKind.TARGETED, NodeKind.ATTACK_ACTION, NodeKind.ASSET)
    validate_edge(
        EdgeKind.USED_TECHNIQUE, NodeKind.ATTACK_ACTION, NodeKind.ATTACK_TECHNIQUE
    )
    validate_edge(
        EdgeKind.EXECUTED_BY, NodeKind.ATTACK_ACTION, NodeKind.EXECUTION_WORKER
    )
    validate_edge(EdgeKind.USED_PAYLOAD, NodeKind.ATTACK_ACTION, NodeKind.PAYLOAD)
    validate_edge(
        EdgeKind.PRODUCED_FINDING, NodeKind.ATTACK_ACTION, NodeKind.DETECTION_FINDING
    )
    validate_edge(
        EdgeKind.EVADED_DETECTION, NodeKind.ATTACK_ACTION, NodeKind.DETECTION_RULE
    )
    validate_edge(
        EdgeKind.CAUGHT_BY_DETECTION, NodeKind.ATTACK_ACTION, NodeKind.DETECTION_RULE
    )
    # USES_TECHNIQUE remains threat-actor only.
    with pytest.raises(InvalidRelationshipError):
        validate_edge(
            EdgeKind.USES_TECHNIQUE, NodeKind.ATTACK_ACTION, NodeKind.ATTACK_TECHNIQUE
        )


@pytest.mark.asyncio
async def test_graph_writes_idempotent() -> None:
    graph = InMemorySecurityGraphWriteAdapter()
    org = str(uuid4())
    for _ in range(3):
        await graph.project_attack_action_node(
            organization_id=org,
            action_id="a1",
            technique_ref="T1059",
            state="Executing",
        )
        await graph.project_used_technique(
            organization_id=org, action_id="a1", technique_id="T1059", success=True
        )
    assert len(graph.nodes) == 2  # attack_action + technique
    assert len(graph.edges) == 1
