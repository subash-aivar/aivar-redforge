"""RuleLogic and RuleCondition value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import (
    ConditionOperator,
    LogicConnector,
    RuleLogicType,
)
from detection.domain.value_objects.keys import RuleKey


@dataclass(frozen=True, slots=True)
class NormalizedFieldRef:
    """Reference to a normalized telemetry field (source-agnostic)."""

    path: str

    def __post_init__(self) -> None:
        cleaned = self.path.strip()
        if not cleaned or " " in cleaned:
            raise InvalidArgument("NormalizedFieldRef", "path required without spaces")
        object.__setattr__(self, "path", cleaned)


@dataclass(frozen=True, slots=True)
class RuleCondition:
    """Composable predicate: field, operator, value, optional connector + children."""

    field: NormalizedFieldRef
    operator: ConditionOperator
    value: str | int | float | bool | list[str] | None = None
    connector: LogicConnector | None = None
    children: tuple[RuleCondition, ...] = ()

    def __post_init__(self) -> None:
        if self.operator in {ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS}:
            if self.value is not None:
                raise InvalidArgument(
                    "RuleCondition", f"{self.operator} must not carry a value"
                )
        elif self.value is None and not self.children:
            raise InvalidArgument(
                "RuleCondition", "value required unless leaf is EXISTS/NOT_EXISTS"
            )
        if self.children and self.connector is None:
            raise InvalidArgument("RuleCondition", "connector required when children set")
        if self.connector == LogicConnector.NOT and len(self.children) != 1:
            raise InvalidArgument("RuleCondition", "NOT connector requires exactly one child")

    def collect_field_refs(self) -> list[NormalizedFieldRef]:
        refs = [self.field]
        for child in self.children:
            refs.extend(child.collect_field_refs())
        return refs


@dataclass(frozen=True, slots=True)
class RuleLogic:
    """Structured, source-agnostic detection logic. Immutable once versioned."""

    logic_type: RuleLogicType
    conditions: tuple[RuleCondition, ...]
    sequence_window: timedelta | None = None
    aggregation_field: str | None = None
    threshold_count: int | None = None
    threshold_window: timedelta | None = None
    correlation_refs: tuple[RuleKey, ...] = ()
    normalized_field_refs: tuple[NormalizedFieldRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.conditions:
            raise InvalidArgument("RuleLogic", "at least one condition required")

        seen: dict[str, NormalizedFieldRef] = {}
        for cond in self.conditions:
            for ref in cond.collect_field_refs():
                seen.setdefault(ref.path, ref)
        collected = tuple(seen.values())
        if not self.normalized_field_refs:
            object.__setattr__(self, "normalized_field_refs", collected)

        if (
            self.logic_type == RuleLogicType.SEQUENCE
            and (self.sequence_window is None or self.sequence_window.total_seconds() <= 0)
        ):
            raise InvalidArgument(
                "RuleLogic", "Sequence requires positive sequence_window"
            )
        if self.logic_type == RuleLogicType.AGGREGATION and not self.aggregation_field:
            raise InvalidArgument("RuleLogic", "Aggregation requires aggregation_field")
        if self.logic_type == RuleLogicType.THRESHOLD:
            if self.threshold_count is None or self.threshold_count <= 0:
                raise InvalidArgument(
                    "RuleLogic", "Threshold requires positive threshold_count"
                )
            if self.threshold_window is None or self.threshold_window.total_seconds() <= 0:
                raise InvalidArgument(
                    "RuleLogic", "Threshold requires positive threshold_window"
                )
            if not self.aggregation_field:
                raise InvalidArgument(
                    "RuleLogic", "Threshold requires aggregation_field"
                )
        if self.logic_type == RuleLogicType.CORRELATION and not self.correlation_refs:
            raise InvalidArgument(
                "RuleLogic", "Correlation requires correlation_refs"
            )

    def validate(self) -> None:
        """Re-run construction invariants (explicit validate port)."""
        RuleLogic(
            logic_type=self.logic_type,
            conditions=self.conditions,
            sequence_window=self.sequence_window,
            aggregation_field=self.aggregation_field,
            threshold_count=self.threshold_count,
            threshold_window=self.threshold_window,
            correlation_refs=self.correlation_refs,
            normalized_field_refs=self.normalized_field_refs,
        )
