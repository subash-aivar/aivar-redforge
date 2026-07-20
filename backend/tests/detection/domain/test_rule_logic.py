"""RuleLogic / RuleCondition / NormalizedFieldRef validation tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import (
    ConditionOperator,
    LogicConnector,
    RuleLogicType,
)
from detection.domain.value_objects.keys import RuleKey
from detection.domain.value_objects.rule_logic import (
    NormalizedFieldRef,
    RuleCondition,
    RuleLogic,
)
from tests.detection.conftest import make_logic


class TestNormalizedFieldRef:
    def test_valid_path(self) -> None:
        ref = NormalizedFieldRef("process.name")
        assert ref.path == "process.name"

    def test_strips_whitespace(self) -> None:
        ref = NormalizedFieldRef("  file.path  ")
        assert ref.path == "file.path"

    def test_rejects_empty(self) -> None:
        with pytest.raises(InvalidArgument, match="NormalizedFieldRef"):
            NormalizedFieldRef("   ")

    def test_rejects_internal_spaces(self) -> None:
        with pytest.raises(InvalidArgument, match="NormalizedFieldRef"):
            NormalizedFieldRef("process name")


class TestRuleCondition:
    def test_equals_requires_value(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleCondition"):
            RuleCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EQUALS,
                value=None,
            )

    def test_exists_rejects_value(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleCondition"):
            RuleCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EXISTS,
                value="x",
            )

    def test_exists_allows_none_value(self) -> None:
        cond = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EXISTS,
        )
        assert cond.value is None

    def test_not_exists_allows_none_value(self) -> None:
        cond = RuleCondition(
            field=NormalizedFieldRef("user.name"),
            operator=ConditionOperator.NOT_EXISTS,
        )
        assert cond.operator == ConditionOperator.NOT_EXISTS

    def test_children_require_connector(self) -> None:
        child = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EQUALS,
            value="cmd.exe",
        )
        with pytest.raises(InvalidArgument, match="connector"):
            RuleCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EQUALS,
                value="parent",
                children=(child,),
            )

    def test_not_requires_exactly_one_child(self) -> None:
        child = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EQUALS,
            value="cmd.exe",
        )
        with pytest.raises(InvalidArgument, match="NOT"):
            RuleCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EQUALS,
                value="parent",
                connector=LogicConnector.NOT,
                children=(child, child),
            )

    def test_and_tree_collects_field_refs(self) -> None:
        left = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EQUALS,
            value="cmd.exe",
        )
        right = RuleCondition(
            field=NormalizedFieldRef("user.name"),
            operator=ConditionOperator.EQUALS,
            value="admin",
        )
        root = RuleCondition(
            field=NormalizedFieldRef("host.name"),
            operator=ConditionOperator.EQUALS,
            value="ws1",
            connector=LogicConnector.AND,
            children=(left, right),
        )
        paths = {r.path for r in root.collect_field_refs()}
        assert paths == {"host.name", "process.name", "user.name"}

    def test_or_tree_valid(self) -> None:
        child = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.CONTAINS,
            value="powershell",
        )
        root = RuleCondition(
            field=NormalizedFieldRef("process.command_line"),
            operator=ConditionOperator.CONTAINS,
            value="-enc",
            connector=LogicConnector.OR,
            children=(child,),
        )
        assert root.connector == LogicConnector.OR

    def test_in_operator_with_list(self) -> None:
        cond = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.IN,
            value=["cmd.exe", "powershell.exe"],
        )
        assert isinstance(cond.value, list)

    def test_regex_operator(self) -> None:
        cond = RuleCondition(
            field=NormalizedFieldRef("process.command_line"),
            operator=ConditionOperator.REGEX,
            value=r".*-enc\s+",
        )
        assert cond.operator == ConditionOperator.REGEX


class TestRuleLogicTypes:
    def test_condition_type_minimal(self) -> None:
        logic = make_logic()
        assert logic.logic_type == RuleLogicType.CONDITION
        assert len(logic.conditions) == 1

    def test_requires_at_least_one_condition(self) -> None:
        with pytest.raises(InvalidArgument, match="at least one condition"):
            RuleLogic(logic_type=RuleLogicType.CONDITION, conditions=())

    def test_sequence_requires_positive_window(self) -> None:
        with pytest.raises(InvalidArgument, match="Sequence"):
            make_logic(
                logic_type=RuleLogicType.SEQUENCE,
                sequence_window=timedelta(seconds=0),
            )

    def test_sequence_valid(self) -> None:
        logic = make_logic(
            logic_type=RuleLogicType.SEQUENCE,
            sequence_window=timedelta(minutes=5),
        )
        assert logic.sequence_window == timedelta(minutes=5)

    def test_aggregation_requires_field(self) -> None:
        with pytest.raises(InvalidArgument, match="Aggregation"):
            make_logic(logic_type=RuleLogicType.AGGREGATION)

    def test_aggregation_valid(self) -> None:
        logic = make_logic(
            logic_type=RuleLogicType.AGGREGATION,
            aggregation_field="user.name",
        )
        assert logic.aggregation_field == "user.name"

    def test_threshold_requires_count(self) -> None:
        with pytest.raises(InvalidArgument, match="Threshold"):
            make_logic(
                logic_type=RuleLogicType.THRESHOLD,
                aggregation_field="src.ip",
                threshold_window=timedelta(minutes=10),
            )

    def test_threshold_requires_window(self) -> None:
        with pytest.raises(InvalidArgument, match="Threshold"):
            make_logic(
                logic_type=RuleLogicType.THRESHOLD,
                aggregation_field="src.ip",
                threshold_count=5,
            )

    def test_threshold_requires_aggregation_field(self) -> None:
        with pytest.raises(InvalidArgument, match="Threshold"):
            make_logic(
                logic_type=RuleLogicType.THRESHOLD,
                threshold_count=5,
                threshold_window=timedelta(minutes=10),
            )

    def test_threshold_valid(self) -> None:
        logic = make_logic(
            logic_type=RuleLogicType.THRESHOLD,
            aggregation_field="src.ip",
            threshold_count=10,
            threshold_window=timedelta(minutes=15),
        )
        assert logic.threshold_count == 10

    def test_correlation_requires_refs(self) -> None:
        with pytest.raises(InvalidArgument, match="Correlation"):
            make_logic(logic_type=RuleLogicType.CORRELATION)

    def test_correlation_valid(self) -> None:
        logic = make_logic(
            logic_type=RuleLogicType.CORRELATION,
            correlation_refs=(RuleKey("aivar.parent_rule"),),
        )
        assert len(logic.correlation_refs) == 1

    def test_auto_collects_normalized_field_refs(self) -> None:
        logic = make_logic()
        assert any(r.path == "process.name" for r in logic.normalized_field_refs)

    def test_explicit_normalized_field_refs_preserved(self) -> None:
        refs = (NormalizedFieldRef("custom.field"),)
        logic = make_logic(normalized_field_refs=refs)
        assert logic.normalized_field_refs == refs

    def test_validate_reruns_invariants(self) -> None:
        logic = make_logic()
        logic.validate()  # should not raise

    def test_nested_conditions_collect_refs(self) -> None:
        child = RuleCondition(
            field=NormalizedFieldRef("file.hash"),
            operator=ConditionOperator.EQUALS,
            value="abc",
        )
        parent = RuleCondition(
            field=NormalizedFieldRef("process.name"),
            operator=ConditionOperator.EQUALS,
            value="cmd.exe",
            connector=LogicConnector.AND,
            children=(child,),
        )
        logic = RuleLogic(logic_type=RuleLogicType.CONDITION, conditions=(parent,))
        paths = {r.path for r in logic.normalized_field_refs}
        assert "file.hash" in paths
        assert "process.name" in paths
