"""ExecutionPlanVersion immutability after signing and plan hash."""

from __future__ import annotations

from uuid import uuid4

import pytest
from tests.operation.conftest import advance

from operation.domain.aggregates.execution_plan_version import ExecutionPlanVersion
from operation.domain.events.plan_version_events import (
    ExecutionPlanVersionCreated,
    ExecutionPlanVersionSigned,
)
from operation.domain.exceptions.domain_exceptions import (
    InvalidStateTransition,
    PlanImmutabilityViolation,
)
from operation.domain.value_objects.enums import ExecutionPlanVersionState
from operation.domain.value_objects.identifiers import OperationId
from operation.domain.value_objects.plan_vos import PlanHash, PlanSnapshot


def _draft(*, tenant_id, now, snapshot: str = '{"steps":[]}') -> ExecutionPlanVersion:
    return ExecutionPlanVersion.create_draft(
        tenant_id=tenant_id,
        operation_id=OperationId.generate(),
        version_number=1,
        snapshot=PlanSnapshot(snapshot),
        now=now,
    )


class TestPlanHash:
    def test_plan_hash_computed_from_snapshot_and_matches(self, tenant_id, now) -> None:
        snap = PlanSnapshot('{"operation_id":"x","steps":[],"dependencies":[]}')
        expected = PlanHash.from_snapshot(snap)
        pv = _draft(tenant_id=tenant_id, now=now, snapshot=snap.value)
        pv.pop_events()
        pv.sign(
            tenant_id=tenant_id,
            operator_id=uuid4(),
            signature="plan-sig",
            now=advance(now, minutes=1),
        )
        assert pv.plan_hash is not None
        assert pv.plan_hash.value == expected.value
        assert pv.state == ExecutionPlanVersionState.SIGNED
        events = pv.pop_events()
        assert isinstance(events[0], ExecutionPlanVersionSigned)
        assert events[0].plan_hash == expected.value


class TestImmutability:
    def test_replace_snapshot_blocked_after_sign(self, tenant_id, now) -> None:
        pv = _draft(tenant_id=tenant_id, now=now)
        assert isinstance(pv.pop_events()[0], ExecutionPlanVersionCreated)
        pv.sign(
            tenant_id=tenant_id,
            operator_id=uuid4(),
            signature="sig",
            now=now,
        )
        with pytest.raises(PlanImmutabilityViolation):
            pv.replace_snapshot(
                tenant_id=tenant_id,
                snapshot=PlanSnapshot('{"steps":[{"id":"1"}]}'),
                now=advance(now, minutes=1),
            )

    def test_cannot_sign_twice(self, tenant_id, now) -> None:
        pv = _draft(tenant_id=tenant_id, now=now)
        pv.pop_events()
        pv.sign(tenant_id=tenant_id, operator_id=uuid4(), signature="sig", now=now)
        with pytest.raises(InvalidStateTransition):
            pv.sign(
                tenant_id=tenant_id,
                operator_id=uuid4(),
                signature="sig2",
                now=advance(now, minutes=1),
            )

    def test_draft_can_replace_snapshot(self, tenant_id, now) -> None:
        pv = _draft(tenant_id=tenant_id, now=now)
        pv.pop_events()
        new_snap = PlanSnapshot('{"steps":[{"name":"updated"}]}')
        pv.replace_snapshot(tenant_id=tenant_id, snapshot=new_snap, now=now)
        assert pv.snapshot.value == new_snap.value
        assert pv.plan_hash is None
