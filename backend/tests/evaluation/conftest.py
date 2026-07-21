"""Shared fixtures for evaluation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from evaluation.domain.value_objects.evaluation_vos import (
    AttackActionRecord,
    DetectionFindingRecord,
    EvidenceRecord,
    ObjectiveSpec,
)
from evaluation.domain.value_objects.identifiers import TenantId
from evaluation.infrastructure.acl.degraded_adapters import (
    StubAttackActionQueryAdapter,
    StubDetectionFindingQueryAdapter,
    StubEvidenceQueryAdapter,
    StubSecurityGraphWriteAdapter,
)
from tests.evaluation.fakes.repos import (
    FakeEvaluationRepository,
    FakeEventPublisher,
    FakeMetricsSnapshotRepository,
    FakeUnitOfWork,
)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def instance_id() -> object:
    return uuid4()


@pytest.fixture
def campaign_id() -> object:
    return uuid4()


@pytest.fixture
def objective_specs() -> list[ObjectiveSpec]:
    return [
        ObjectiveSpec(
            objective_id=str(uuid4()),
            objective_type="AccessAchieved",
            is_required=True,
            condition_type="AttackActionCompleted",
            parameters={"technique_id": "T1078"},
        ),
        ObjectiveSpec(
            objective_id=str(uuid4()),
            objective_type="DetectionEvaded",
            is_required=True,
            condition_type="DetectionAbsent",
            parameters={"technique_id": "T1078"},
        ),
    ]


@pytest.fixture
def sample_actions(now: datetime) -> list[AttackActionRecord]:
    return [
        AttackActionRecord(
            action_id="act-1",
            operation_id="op-1",
            technique_id="T1078",
            asset_ref="host-1",
            started_at=now.isoformat(),
            completed_at=(now + timedelta(minutes=1)).isoformat(),
            outcome="Success",
        ),
        AttackActionRecord(
            action_id="act-2",
            operation_id="op-2",
            technique_id="T1059",
            asset_ref="host-1",
            started_at=now.isoformat(),
            completed_at=(now + timedelta(minutes=2)).isoformat(),
            outcome="Success",
        ),
    ]


@pytest.fixture
def uow() -> FakeUnitOfWork:
    return FakeUnitOfWork(
        FakeEvaluationRepository(), FakeMetricsSnapshotRepository()
    )


@pytest.fixture
def publisher() -> FakeEventPublisher:
    return FakeEventPublisher()


@pytest.fixture
def graph_port() -> StubSecurityGraphWriteAdapter:
    return StubSecurityGraphWriteAdapter()


def make_service(
    uow: FakeUnitOfWork,
    publisher: FakeEventPublisher,
    actions: list[AttackActionRecord] | None = None,
    findings: list[DetectionFindingRecord] | None = None,
    evidence: list[EvidenceRecord] | None = None,
    graph: StubSecurityGraphWriteAdapter | None = None,
):
    from evaluation.application.services.evaluation_application_service import (
        EvaluationApplicationService,
    )

    return EvaluationApplicationService(
        uow_factory=lambda: uow,
        event_publisher=publisher,
        attack_action_port=StubAttackActionQueryAdapter(actions),
        detection_finding_port=StubDetectionFindingQueryAdapter(findings),
        evidence_port=StubEvidenceQueryAdapter(evidence),
        graph_write_port=graph,
    )
