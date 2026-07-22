from __future__ import annotations

from uuid import uuid4

from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.services.playbook_content_hash_service import PlaybookContentHashService
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
from playbook.domain.value_objects.identifiers import PlaybookId, TenantId


def _version(params: dict[str, object]) -> PlaybookVersion:
    return PlaybookVersion.create_draft(
        TenantId(uuid4()),
        PlaybookId.generate(),
        1,
        [
            ActionStepDefinition(
                1,
                "create_ticket",
                ConnectorType.ITSM_JIRA,
                TargetSelectorExpression("*"),
                params,
                ActionImpactLevel.LOW,
            )
        ],
        [
            TriggerCondition(TriggerSourceContext.MANUAL, "manual"),
        ],
    )


def test_hash_stable_and_sensitive() -> None:
    svc = PlaybookContentHashService()
    a = _version({"project": "A"})
    b = _version({"project": "A"})
    c = _version({"project": "B"})
    assert svc.compute(a) == svc.compute(b)
    assert svc.compute(a) != svc.compute(c)


def test_publish_sets_hash() -> None:
    v = _version({"project": "A"})
    v.publish("eng")
    assert len(v.content_hash) == 64
