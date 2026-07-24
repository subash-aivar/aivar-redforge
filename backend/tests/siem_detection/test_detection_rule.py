from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_detection.domain.aggregates.detection_rule import DetectionRule
from siem_detection.domain.events.detection_events import (
    DetectionRuleActivated,
    DetectionRuleDeprecated,
    DetectionRuleVersionPublished,
)
from siem_detection.domain.exceptions.domain_exceptions import (
    EmptyRuleBodyError,
    EmptyRuleNameError,
    InvalidRuleTransition,
    TenantMismatch,
)
from siem_detection.domain.value_objects.enums import DetectionRuleShape, DetectionRuleStatus
from siem_detection.domain.value_objects.identifiers import DetectionRuleId

NOW = datetime.now(UTC)


def _tenant() -> EntityId:
    return EntityId.generate()


def _draft(tenant_id: EntityId | None = None) -> DetectionRule:
    return DetectionRule.draft(
        rule_id=DetectionRuleId.generate(),
        tenant_id=tenant_id,
        name="Suspicious login burst",
        shape=DetectionRuleShape.SIGMA,
        rule_body="detection:\n  selection:\n    EventID: 4625",
        now=NOW,
    )


def test_draft_starts_in_draft_status_v1() -> None:
    rule = _draft()
    assert rule.status == DetectionRuleStatus.DRAFT
    assert rule.version == 1
    assert rule.pop_events() == []


def test_draft_rejects_blank_name() -> None:
    with pytest.raises(EmptyRuleNameError):
        DetectionRule.draft(
            rule_id=DetectionRuleId.generate(),
            tenant_id=None,
            name="   ",
            shape=DetectionRuleShape.SIGMA,
            rule_body="body",
            now=NOW,
        )


def test_draft_rejects_blank_body() -> None:
    with pytest.raises(EmptyRuleBodyError):
        DetectionRule.draft(
            rule_id=DetectionRuleId.generate(),
            tenant_id=None,
            name="rule",
            shape=DetectionRuleShape.SIGMA,
            rule_body="  ",
            now=NOW,
        )


def test_activate_transitions_and_emits_event() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    rule.activate(tenant_id, NOW)

    assert rule.status == DetectionRuleStatus.ACTIVE
    events = rule.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], DetectionRuleActivated)


def test_activate_twice_raises() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    rule.activate(tenant_id, NOW)
    with pytest.raises(InvalidRuleTransition):
        rule.activate(tenant_id, NOW)


def test_deprecate_from_active_emits_event() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    rule.activate(tenant_id, NOW)
    rule.pop_events()
    rule.deprecate(tenant_id, "superseded by v2", NOW)

    assert rule.status == DetectionRuleStatus.DEPRECATED
    events = rule.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], DetectionRuleDeprecated)
    assert events[0].reason == "superseded by v2"


def test_deprecate_requires_reason() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    with pytest.raises(ValueError, match="reason"):
        rule.deprecate(tenant_id, "  ", NOW)


def test_publish_version_after_deprecation_raises() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    rule.deprecate(tenant_id, "retired", NOW)
    with pytest.raises(InvalidRuleTransition):
        rule.publish_version(tenant_id, "new body", NOW)


def test_publish_version_bumps_version_and_emits_event() -> None:
    tenant_id = _tenant()
    rule = _draft(tenant_id)
    rule.pop_events()
    rule.publish_version(tenant_id, "detection:\n  selection:\n    EventID: 4624", NOW)

    assert rule.version == 2
    events = rule.pop_events()
    assert isinstance(events[0], DetectionRuleVersionPublished)
    assert events[0].rule_version == 2


def test_platform_global_rule_has_no_tenant_and_any_tenant_may_operate() -> None:
    rule = _draft(tenant_id=None)
    rule.activate(_tenant(), NOW)
    assert rule.status == DetectionRuleStatus.ACTIVE


def test_tenant_owned_rule_rejects_wrong_tenant() -> None:
    rule = _draft(tenant_id=_tenant())
    with pytest.raises(TenantMismatch):
        rule.activate(_tenant(), NOW)
