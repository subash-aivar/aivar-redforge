"""DAG construction — cyclic step dependencies rejected."""

from __future__ import annotations

import pytest
from tests.operation.conftest import (
    add_attack_step,
    add_gate_step,
    add_verification_step,
    advance,
    make_operation,
)

from operation.domain.exceptions.domain_exceptions import CyclicDependencyError


class TestCyclicDependency:
    def test_direct_cycle_rejected(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        a = add_attack_step(op, tenant_id=tenant_id, now=now, name="a", technique_id=None)
        b = add_attack_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=1), name="b", technique_id=None
        )
        op.add_dependency(
            tenant_id=tenant_id, from_step_id=a, to_step_id=b, now=advance(now, seconds=2)
        )
        with pytest.raises(CyclicDependencyError):
            op.add_dependency(
                tenant_id=tenant_id, from_step_id=b, to_step_id=a, now=advance(now, seconds=3)
            )

    def test_indirect_cycle_rejected(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        a = add_gate_step(op, tenant_id=tenant_id, now=now, name="a")
        b = add_attack_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=1), name="b", technique_id=None
        )
        c = add_verification_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=2), name="c"
        )
        op.add_dependency(tenant_id=tenant_id, from_step_id=a, to_step_id=b, now=now)
        op.add_dependency(
            tenant_id=tenant_id, from_step_id=b, to_step_id=c, now=advance(now, seconds=1)
        )
        with pytest.raises(CyclicDependencyError):
            op.add_dependency(
                tenant_id=tenant_id, from_step_id=c, to_step_id=a, now=advance(now, seconds=2)
            )

    def test_self_dependency_rejected(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        a = add_attack_step(op, tenant_id=tenant_id, now=now, technique_id=None)
        with pytest.raises(Exception, match="itself"):
            op.add_dependency(tenant_id=tenant_id, from_step_id=a, to_step_id=a, now=now)

    def test_valid_dag_accepted(self, tenant_id, now) -> None:
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        gate = add_gate_step(op, tenant_id=tenant_id, now=now)
        attack = add_attack_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=1), technique_id=None
        )
        verify = add_verification_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=2)
        )
        op.add_dependency(tenant_id=tenant_id, from_step_id=gate, to_step_id=attack, now=now)
        op.add_dependency(
            tenant_id=tenant_id, from_step_id=attack, to_step_id=verify, now=now
        )
        assert len(op.dependencies) == 2
