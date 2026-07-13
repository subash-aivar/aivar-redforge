import pytest

from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    DuplicateRuleRegistrationError,
    MultipleSecurityConditionsOnAssetRule,
)


class _StubRule:
    stable_rule_id = "STUB_RULE"
    rule_version = 1

    async def evaluate(self, organization_id: str) -> list:
        return []


def test_registry_rejects_duplicate_rule_id_and_version() -> None:
    registry = CorrelationRuleRegistry()
    registry.register(_StubRule())
    with pytest.raises(DuplicateRuleRegistrationError):
        registry.register(_StubRule())


def test_registry_allows_same_id_different_version() -> None:
    class _StubRuleV2:
        stable_rule_id = "STUB_RULE"
        rule_version = 2

        async def evaluate(self, organization_id: str) -> list:
            return []

    registry = CorrelationRuleRegistry()
    registry.register(_StubRule())
    registry.register(_StubRuleV2())
    assert len(registry.all_rules()) == 2


def test_unknown_rule_lookup_returns_none() -> None:
    registry = CorrelationRuleRegistry()
    assert registry.get("NOT_REGISTERED", 1) is None


def test_multiple_conditions_rule_has_stable_identity() -> None:
    rule = MultipleSecurityConditionsOnAssetRule(condition_service=None)  # type: ignore[arg-type]
    assert rule.stable_rule_id == "MULTIPLE_SECURITY_CONDITIONS_ON_ASSET"
    assert rule.rule_version == 1
