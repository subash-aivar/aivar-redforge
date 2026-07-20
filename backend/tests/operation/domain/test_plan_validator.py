"""ExecutionPlanValidator quality gates."""

from __future__ import annotations

from uuid import uuid4

import pytest
from tests.operation.conftest import (
    add_attack_step,
    add_gate_step,
    add_verification_step,
    advance,
    make_operation,
)

from operation.domain.exceptions.domain_exceptions import PlanValidationError
from operation.domain.services.execution_plan_validator import ExecutionPlanValidator
from operation.domain.value_objects.enums import ImpactCeiling


class TestOutOfScopeTarget:
    def test_out_of_scope_target_blocks_validation(self, tenant_id, now) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            target_asset_id=asset,
            technique_id="T1059",
        )
        with pytest.raises(PlanValidationError, match="out of scope"):
            ExecutionPlanValidator.validate(
                op,
                authorized_targets={uuid4()},
                allowed_techniques={"T1059"},
            )


class TestUnauthorizedTechnique:
    def test_unauthorized_technique_rejected(self, tenant_id, now) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            target_asset_id=asset,
            technique_id="T9999",
        )
        with pytest.raises(PlanValidationError, match="not authorized"):
            ExecutionPlanValidator.validate(
                op,
                authorized_targets={asset},
                allowed_techniques={"T1059"},
            )


class TestExploitRequiresHumanGate:
    def test_exploit_without_preceding_gate_rejected(self, tenant_id, now) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            impact=ImpactCeiling.EXPLOIT,
            target_asset_id=asset,
            technique_id="T1059",
        )
        with pytest.raises(PlanValidationError, match="HumanApprovalGate"):
            ExecutionPlanValidator.validate(
                op,
                authorized_targets={asset},
                allowed_techniques={"T1059"},
            )

    def test_exploit_with_preceding_gate_passes(self, tenant_id, now) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        gate = add_gate_step(op, tenant_id=tenant_id, now=now)
        attack = add_attack_step(
            op,
            tenant_id=tenant_id,
            now=advance(now, seconds=1),
            impact=ImpactCeiling.EXPLOIT,
            target_asset_id=asset,
            technique_id="T1059",
        )
        op.add_dependency(
            tenant_id=tenant_id, from_step_id=gate, to_step_id=attack, now=now
        )
        ExecutionPlanValidator.validate(
            op,
            authorized_targets={asset},
            allowed_techniques={"T1059"},
        )


class TestVerificationAfterMutate:
    def test_mutating_attack_requires_following_verification(self, tenant_id, now) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            target_asset_id=asset,
            technique_id="T1059",
            modifies_persistent_state=True,
        )
        with pytest.raises(PlanValidationError, match="VerificationStep"):
            ExecutionPlanValidator.validate(
                op,
                authorized_targets={asset},
                allowed_techniques={"T1059"},
            )

    def test_mutating_attack_with_verification_successor_passes(
        self, tenant_id, now
    ) -> None:
        asset = uuid4()
        op = make_operation(tenant_id=tenant_id, now=now, pop_events=True)
        attack = add_attack_step(
            op,
            tenant_id=tenant_id,
            now=now,
            target_asset_id=asset,
            technique_id="T1059",
            modifies_persistent_state=True,
        )
        verify = add_verification_step(
            op, tenant_id=tenant_id, now=advance(now, seconds=1)
        )
        op.add_dependency(
            tenant_id=tenant_id, from_step_id=attack, to_step_id=verify, now=now
        )
        ExecutionPlanValidator.validate(
            op,
            authorized_targets={asset},
            allowed_techniques={"T1059"},
        )
