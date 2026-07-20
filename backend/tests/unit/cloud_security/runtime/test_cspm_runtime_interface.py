"""CSPM PolicyEvaluationEngine reuse via cspm_snapshot()."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from redforge.application.cloud_security.runtime.cspm_runtime_interface import (
    CspmRuntimePolicyInterface,
    evaluate_runtime_event,
)
from redforge.domain.cloud_security.policy_engine.evaluator import PolicyEvaluationEngine
from redforge.domain.cloud_security.runtime.entities import RuntimeMetadata
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.value_objects import (
    EventOutcome,
    RuntimeEventType,
    RuntimeIdentity,
    RuntimeSource,
)
from redforge.domain.cloud_security.value_objects import CloudAccountId, OrganizationId

ORG = OrganizationId("01HXORG0000000000000000001")
ACCOUNT = CloudAccountId(uuid4())
NOW = datetime(2026, 7, 19, tzinfo=UTC)


def _event(*, outcome: EventOutcome = EventOutcome.FAILURE) -> CloudRuntimeEvent:
    return CloudRuntimeEvent.ingest(
        organization_id=ORG,
        cloud_account_id=ACCOUNT,
        event_type=RuntimeEventType.API_ACTIVITY,
        source=RuntimeSource.CLOUDTRAIL,
        event_time=NOW,
        metadata=RuntimeMetadata(provider_event_id="p1", event_name="AssumeRole"),
        identity=RuntimeIdentity(principal_id="p", principal_type="AssumedRole"),
        outcome=outcome,
        source_ip="203.0.113.9",
        now=NOW,
    )


def test_evaluate_runtime_event_with_policy_object() -> None:
    policy = SimpleNamespace(
        id="RUNTIME-FAIL-001",
        rule={"op": "eq", "path": "outcome", "value": "FAILURE"},
    )
    results = evaluate_runtime_event(_event(), [policy])
    assert len(results) == 1
    assert results[0].matched is True
    assert results[0].policy_id == "RUNTIME-FAIL-001"
    assert results[0].snapshot["asset_type"] == "RUNTIME_EVENT"


def test_evaluate_runtime_event_no_match() -> None:
    policy = {
        "id": "RUNTIME-FAIL-001",
        "rule": {"op": "eq", "path": "outcome", "value": "FAILURE"},
    }
    results = evaluate_runtime_event(_event(outcome=EventOutcome.SUCCESS), [policy])
    assert results[0].matched is False


def test_evaluate_skips_policies_without_rule() -> None:
    results = evaluate_runtime_event(_event(), [SimpleNamespace(id="x"), {"id": "y"}])
    assert results == []


def test_interface_uses_injected_engine() -> None:
    engine = PolicyEvaluationEngine()
    iface = CspmRuntimePolicyInterface(engine)
    policy = {"id": "ip", "rule": {"op": "eq", "path": "source_ip", "value": "203.0.113.9"}}
    results = iface.evaluate_runtime_event(_event(), [policy])
    assert results[0].matched is True


def test_snapshot_normalized_config_usable_by_engine() -> None:
    event = _event()
    snap = event.cspm_snapshot()
    engine = PolicyEvaluationEngine()
    outcome = engine.evaluate(
        {"op": "eq", "path": "normalized_config.event_name", "value": "AssumeRole"},
        snap,
    )
    assert outcome.matched is True


@pytest.mark.parametrize(
    "path,value",
    [
        ("asset_type", "RUNTIME_EVENT"),
        ("event_type", "API_ACTIVITY"),
        ("source", "CLOUDTRAIL"),
        ("normalized_config.principal_type", "AssumedRole"),
    ],
)
def test_engine_paths_on_runtime_snapshot(path: str, value: str) -> None:
    snap = _event().cspm_snapshot()
    outcome = PolicyEvaluationEngine().evaluate(
        {"op": "eq", "path": path, "value": value}, snap
    )
    assert outcome.matched is True
