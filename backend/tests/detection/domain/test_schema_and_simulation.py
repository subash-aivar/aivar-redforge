"""Schema validation and rule simulation domain tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    SimulationBlocked,
)
from detection.domain.providers.normalized_models import (
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
)
from detection.domain.services.schema_validation import (
    SchemaValidator,
    validate_rule_against_schema,
)
from detection.domain.services.simulation import (
    RuleSimulationService,
    SimulationEvidenceModel,
    SimulationResult,
    SimulationValidator,
)
from detection.domain.value_objects.enums import (
    ConditionOperator,
    RuleLogicType,
)
from detection.domain.value_objects.identifiers import SimulationId
from detection.domain.value_objects.rule_logic import (
    NormalizedFieldRef,
    RuleCondition,
    RuleLogic,
)
from detection.domain.value_objects.telemetry import TimeWindow
from tests.detection.conftest import make_logic, make_rule
from tests.detection.phase2_helpers import make_schema, make_source, make_window


def test_schema_validation_passes_when_fields_present(tenant_id, now) -> None:
    logic = make_logic()
    schema = make_schema()
    result = validate_rule_against_schema(logic, schema)
    assert result.is_valid is True
    assert result.missing_fields == ()


def test_schema_validation_detects_missing_fields() -> None:
    logic = RuleLogic(
        logic_type=RuleLogicType.CONDITION,
        conditions=(
            RuleCondition(
                field=NormalizedFieldRef("file.path"),
                operator=ConditionOperator.CONTAINS,
                value="/tmp",
            ),
        ),
    )
    schema = make_schema(paths=["process.name"])
    result = SchemaValidator().validate(logic, schema)
    assert result.is_valid is False
    assert "file.path" in result.missing_fields


def test_schema_validation_detects_unsupported_taxonomy() -> None:
    logic = RuleLogic(
        logic_type=RuleLogicType.CONDITION,
        conditions=(
            RuleCondition(
                field=NormalizedFieldRef("vendor.weird"),
                operator=ConditionOperator.EQUALS,
                value="x",
            ),
        ),
    )
    schema = make_schema(paths=["vendor.weird"])
    result = SchemaValidator().validate(logic, schema, enforce_taxonomy=True)
    assert result.is_valid is False
    assert "vendor.weird" in result.unsupported_fields


def test_schema_validation_against_source(tenant_id, now) -> None:
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    logic = make_logic()
    result = SchemaValidator().validate_against_source(logic, source)
    assert result.compatible is True
    assert result.schema_version == "1.0.0"


def test_simulation_matches_condition(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    window = make_window(now)
    events = (
        NormalizedTelemetryEvent(
            fields={"process.name": "cmd.exe", "event.event_type": "ProcessCreate"}
        ),
        NormalizedTelemetryEvent(
            fields={"process.name": "notepad.exe", "event.event_type": "ProcessCreate"}
        ),
    )
    result = RuleSimulationService().simulate(
        rule=rule,
        source=source,
        window=window,
        telemetry=NormalizedTelemetryResult(events=events),
        now=now,
    )
    assert result.statistics.match_count == 1
    assert result.creates_findings is False
    assert result.evidence.evidence_type == "SimulationResult"


def test_simulation_no_match(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    events = (
        NormalizedTelemetryEvent(fields={"process.name": "explorer.exe"}),
    )
    result = RuleSimulationService().simulate(
        rule=rule,
        source=source,
        window=make_window(now),
        telemetry=NormalizedTelemetryResult(events=events),
        now=now,
    )
    assert result.statistics.match_count == 0


def test_simulation_source_unavailable(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    result = RuleSimulationService().simulate(
        rule=rule,
        source=source,
        window=make_window(now),
        telemetry=NormalizedTelemetryResult.unavailable("down"),
        now=now,
    )
    assert result.statistics.source_unavailable is True
    assert result.statistics.match_count == 0


def test_simulation_blocked_when_source_deactivated(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    source.deactivate(tenant_id=tenant_id, reason="off", now=now)
    with pytest.raises(SimulationBlocked):
        SimulationValidator().validate(
            rule=rule, source=source, window=make_window(now)
        )


def test_simulation_blocked_when_window_exceeds_retention(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    window = TimeWindow(start=now - timedelta(days=90), end=now)
    with pytest.raises(SimulationBlocked):
        SimulationValidator().validate(rule=rule, source=source, window=window)


def test_simulation_evidence_type_locked() -> None:
    with pytest.raises(InvalidArgument):
        SimulationEvidenceModel(evidence_type="Finding")


def test_simulation_result_rejects_creates_findings(tenant_id, now) -> None:
    from uuid import uuid4

    from detection.domain.services.simulation import SimulationStatistics
    from detection.domain.value_objects.identifiers import DetectionRuleId

    with pytest.raises(InvalidArgument):
        SimulationResult(
            simulation_id=SimulationId.generate(),
            tenant_id=tenant_id,
            rule_id=DetectionRuleId(uuid4()),
            rule_version=None,
            source_id="x",
            statistics=SimulationStatistics(
                events_evaluated=0, match_count=0, duration_ms=0.0
            ),
            sample_matches=(),
            evidence=SimulationEvidenceModel(),
            simulated_at=now,
            creates_findings=True,
        )


def test_build_query_from_logic(tenant_id, now) -> None:
    logic = make_logic()
    query = RuleSimulationService().build_query(logic, make_window(now))
    assert query.logic_type == RuleLogicType.CONDITION
    assert len(query.conditions) >= 1


def test_threshold_evaluation(tenant_id, now) -> None:
    logic = RuleLogic(
        logic_type=RuleLogicType.THRESHOLD,
        conditions=(
            RuleCondition(
                field=NormalizedFieldRef("process.name"),
                operator=ConditionOperator.EQUALS,
                value="cmd.exe",
            ),
        ),
        aggregation_field="actor.user_name",
        threshold_count=2,
        threshold_window=timedelta(minutes=5),
    )
    events = (
        NormalizedTelemetryEvent(
            fields={"process.name": "cmd.exe", "actor.user_name": "alice"}
        ),
        NormalizedTelemetryEvent(
            fields={"process.name": "cmd.exe", "actor.user_name": "alice"}
        ),
        NormalizedTelemetryEvent(
            fields={"process.name": "cmd.exe", "actor.user_name": "bob"}
        ),
    )
    matches = RuleSimulationService().evaluate_threshold(logic, events)
    assert len(matches) == 2


def test_operators_matrix() -> None:
    svc = RuleSimulationService()
    event = NormalizedTelemetryEvent(
        fields={
            "process.name": "cmd.exe",
            "network.src_port": 443,
            "file.path": "/tmp/evil",
        }
    )
    cases = [
        (ConditionOperator.EQUALS, "process.name", "cmd.exe", True),
        (ConditionOperator.NOT_EQUALS, "process.name", "bash", True),
        (ConditionOperator.CONTAINS, "file.path", "evil", True),
        (ConditionOperator.STARTS_WITH, "file.path", "/tmp", True),
        (ConditionOperator.ENDS_WITH, "process.name", ".exe", True),
        (ConditionOperator.GREATER_THAN, "network.src_port", 400, True),
        (ConditionOperator.LESS_THAN, "network.src_port", 500, True),
        (ConditionOperator.IN, "process.name", ["cmd.exe", "bash"], True),
        (ConditionOperator.EXISTS, "process.name", None, True),
        (ConditionOperator.NOT_EXISTS, "missing.field", None, True),
    ]
    for op, path, value, expected in cases:
        cond = RuleCondition(
            field=NormalizedFieldRef(path if path != "missing.field" else "process.name"),
            operator=op,
            value=value,
        )
        if op == ConditionOperator.NOT_EXISTS:
            cond = RuleCondition(
                field=NormalizedFieldRef("actor.geo"),
                operator=op,
                value=None,
            )
        logic = RuleLogic(logic_type=RuleLogicType.CONDITION, conditions=(cond,))
        assert svc.evaluate_event(logic, event) is expected, op


def test_sample_matches_capped(tenant_id, now) -> None:
    rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
    source = make_source(tenant_id=tenant_id, now=now, pop_events=True)
    events = tuple(
        NormalizedTelemetryEvent(fields={"process.name": "cmd.exe"})
        for _ in range(50)
    )
    result = RuleSimulationService(max_samples=5).simulate(
        rule=rule,
        source=source,
        window=make_window(now),
        telemetry=NormalizedTelemetryResult(events=events),
        now=now,
    )
    assert result.statistics.match_count == 50
    assert len(result.sample_matches) == 5
