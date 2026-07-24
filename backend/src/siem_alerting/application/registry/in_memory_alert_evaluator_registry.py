"""InMemoryAlertEvaluatorRegistry — the one concrete registry this
milestone implements (M44C §4). Structurally identical to M44A/M44B's
in-memory registries: keyed by `(rule_id, exact schema_version)` for
registration, resolved by `(rule_id, major-version compatibility)` per
M37 §2.3's additive-minor-bump rule. Two registered versions both
compatible with a request is a genuine ambiguity, never silently
guessed. No persistence, no DI container wiring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_alerting.application.exceptions import (
    AmbiguousEvaluatorSelectionError,
    DuplicateEvaluatorRegistrationError,
    UnsupportedEvaluatorError,
    UnsupportedEvaluatorVersionError,
)

if TYPE_CHECKING:
    from siem_alerting.application.ports.i_alert_evaluator import IAlertEvaluator
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class InMemoryAlertEvaluatorRegistry:
    def __init__(self) -> None:
        self._by_rule: dict[str, dict[SchemaVersion, IAlertEvaluator]] = {}

    def register(self, evaluator: IAlertEvaluator) -> None:
        by_version = self._by_rule.setdefault(evaluator.rule_id, {})
        if evaluator.schema_version in by_version:
            raise DuplicateEvaluatorRegistrationError(evaluator.rule_id, evaluator.schema_version)
        by_version[evaluator.schema_version] = evaluator

    def resolve(self, rule_id: str, requested_version: SchemaVersion) -> IAlertEvaluator:
        by_version = self._by_rule.get(rule_id)
        if not by_version:
            raise UnsupportedEvaluatorError(rule_id)

        compatible = [
            (version, evaluator)
            for version, evaluator in by_version.items()
            if version.is_compatible_with(requested_version)
        ]
        if not compatible:
            raise UnsupportedEvaluatorVersionError(rule_id, requested_version)
        if len(compatible) > 1:
            raise AmbiguousEvaluatorSelectionError(
                rule_id, requested_version, tuple(version for version, _ in compatible)
            )
        return compatible[0][1]

    def is_registered(self, rule_id: str, schema_version: SchemaVersion) -> bool:
        return schema_version in self._by_rule.get(rule_id, {})
