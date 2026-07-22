from __future__ import annotations

from uuid import uuid4

from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.services.playbook_dry_run_service import PlaybookDryRunService
from playbook.domain.services.trigger_matching_service import TriggerMatchingService
from playbook.domain.value_objects.definitions import (
    ActionStepDefinition,
    TargetSelectorExpression,
    TriggerCondition,
)
from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    TriggerSourceContext,
)
from playbook.domain.value_objects.enums import (
    TestOutcome as PlaybookTestOutcome,
)
from playbook.domain.value_objects.identifiers import PlaybookId, TenantId


def test_trigger_matching() -> None:
    svc = TriggerMatchingService()
    cond = TriggerCondition(
        TriggerSourceContext.M28_FINDING,
        "DetectionFindingEscalated",
        "HIGH",
        ["prod"],
    )
    assert svc.matches(
        cond,
        source_context=TriggerSourceContext.M28_FINDING,
        trigger_type="DetectionFindingEscalated",
        severity="CRITICAL",
        asset_tags=["prod", "web"],
    )
    assert not svc.matches(
        cond,
        source_context=TriggerSourceContext.M34_INCIDENT,
        trigger_type="DetectionFindingEscalated",
        severity="CRITICAL",
        asset_tags=["prod"],
    )


def test_dry_run_rejects_secrets() -> None:
    v = PlaybookVersion.create_draft(
        TenantId(uuid4()),
        PlaybookId.generate(),
        1,
        [
            ActionStepDefinition(
                1,
                "x",
                ConnectorType.COMM_SLACK,
                TargetSelectorExpression("*"),
                {"api_key": "x"},
                ActionImpactLevel.LOW,
            )
        ],
        [],
    )
    result = PlaybookDryRunService().run(v)
    assert result.outcome == PlaybookTestOutcome.FAILED
