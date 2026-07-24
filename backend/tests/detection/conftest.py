"""Shared fixtures for Detection Engineering domain and unit tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.value_objects.enums import (
    RuleCategory,
    RuleConfidence,
    RuleSeverity,
)
from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
from detection.domain.value_objects.keys import (
    AuthorRef,
    RuleKey,
    ThrottlePolicy,
)
from detection.domain.value_objects.rule_logic import RuleLogic


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring PostgreSQL",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip_integration = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId.generate()


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)


def make_logic(**kwargs: Any) -> RuleLogic:
    from detection.domain.value_objects.enums import ConditionOperator, RuleLogicType
    from detection.domain.value_objects.rule_logic import (
        NormalizedFieldRef,
        RuleCondition,
        RuleLogic,
    )

    cond = RuleCondition(
        field=NormalizedFieldRef("process.name"),
        operator=ConditionOperator.EQUALS,
        value="cmd.exe",
    )
    return RuleLogic(
        logic_type=kwargs.pop("logic_type", RuleLogicType.CONDITION),
        conditions=kwargs.pop("conditions", (cond,)),
        **kwargs,
    )


def make_rule(
    *,
    tenant_id: TenantId,
    now: datetime,
    rule_key: str | RuleKey = "aivar.suspicious_cmd",
    title: str = "Suspicious cmd.exe",
    description: str = "Detects suspicious cmd.exe process",
    category: RuleCategory = RuleCategory.THREAT,
    severity: RuleSeverity = RuleSeverity.HIGH,
    confidence: RuleConfidence = RuleConfidence.MEDIUM,
    author: str = "analyst@aivar.io",
    logic: RuleLogic | None = None,
    throttle_policy: ThrottlePolicy | None = None,
    rule_id: DetectionRuleId | None = None,
    pop_events: bool = False,
) -> DetectionRule:
    key = rule_key if isinstance(rule_key, RuleKey) else RuleKey(rule_key)
    rule = DetectionRule.create(
        tenant_id=tenant_id,
        rule_key=key,
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        author=AuthorRef(author),
        logic=logic or make_logic(),
        now=now,
        rule_id=rule_id,
        throttle_policy=throttle_policy,
    )
    if pop_events:
        rule.pop_events()
    return rule
