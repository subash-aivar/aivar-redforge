"""OperationRiskAssessor — computes OperationRisk from step impact ceilings."""

from __future__ import annotations

from typing import TYPE_CHECKING

from operation.domain.value_objects.enums import ImpactCeiling, OperationRisk

if TYPE_CHECKING:
    from operation.domain.entities.operation_entities import ExecutionStep


class OperationRiskAssessor:
    """Union of impact ceilings → OperationRisk."""

    @staticmethod
    def assess(steps: list[ExecutionStep]) -> OperationRisk:
        ceilings = {s.impact_ceiling for s in steps if s.impact_ceiling is not None}
        if ImpactCeiling.DESTRUCT in ceilings:
            return OperationRisk.CRITICAL
        if ImpactCeiling.EXPLOIT in ceilings:
            return OperationRisk.HIGH
        if ImpactCeiling.PROBE in ceilings:
            return OperationRisk.MEDIUM
        return OperationRisk.LOW
