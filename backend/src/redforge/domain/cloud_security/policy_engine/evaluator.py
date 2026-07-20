"""Reusable CSPM policy rule engine — safe, deterministic, no eval/exec."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class RuleEvaluationError(ValueError):
    """Raised when a policy rule is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class ConditionOutcome:
    matched: bool
    path: str
    expected: str
    actual: str
    message: str


def _get_path(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
            continue
        if isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
            continue
        return None
    return current


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def evaluate_condition(rule: dict[str, Any], snapshot: dict[str, Any]) -> ConditionOutcome:
    """Evaluate a single condition or composite rule against a snapshot dict.

    Supported ops:
      eq, ne, gt, gte, lt, lte, exists, not_exists, contains, not_contains,
      regex, in, not_in, empty, not_empty,
      all (AND), any (OR), not, always_true, always_false
    """
    if "all" in rule:
        children = rule["all"]
        if not isinstance(children, list) or not children:
            raise RuleEvaluationError("all requires non-empty list")
        outcomes = [evaluate_condition(child, snapshot) for child in children]
        matched = all(o.matched for o in outcomes)
        failed = next((o for o in outcomes if not o.matched), outcomes[0])
        return ConditionOutcome(
            matched=matched,
            path=failed.path,
            expected="all conditions true",
            actual=failed.actual,
            message=failed.message if not matched else "all conditions matched",
        )
    if "any" in rule:
        children = rule["any"]
        if not isinstance(children, list) or not children:
            raise RuleEvaluationError("any requires non-empty list")
        outcomes = [evaluate_condition(child, snapshot) for child in children]
        matched = any(o.matched for o in outcomes)
        best = next((o for o in outcomes if o.matched), outcomes[0])
        return ConditionOutcome(
            matched=matched,
            path=best.path,
            expected="any condition true",
            actual=best.actual,
            message=best.message if matched else "no condition matched",
        )
    if "not" in rule:
        child = rule["not"]
        if not isinstance(child, dict):
            raise RuleEvaluationError("not requires object")
        outcome = evaluate_condition(child, snapshot)
        return ConditionOutcome(
            matched=not outcome.matched,
            path=outcome.path,
            expected=f"NOT ({outcome.expected})",
            actual=outcome.actual,
            message=f"negated: {outcome.message}",
        )
    if rule.get("op") == "always_true":
        return ConditionOutcome(True, "", "true", "true", "always true")
    if rule.get("op") == "always_false":
        return ConditionOutcome(False, "", "false", "false", "always false")

    op = str(rule.get("op", "")).lower()
    path = str(rule.get("path", ""))
    if not op:
        raise RuleEvaluationError("condition requires op")
    _needs_path = {
        "eq", "ne", "gt", "gte", "lt", "lte", "contains", "not_contains", "regex", "in", "not_in"
    }
    if op in _needs_path and not path:
        raise RuleEvaluationError(f"{op} requires path")

    actual = _get_path(snapshot, path) if path else None
    expected = rule.get("value")

    if op == "exists":
        matched = actual is not None
        return ConditionOutcome(matched, path, "exists", repr(actual), "exists check")
    if op == "not_exists":
        matched = actual is None
        return ConditionOutcome(matched, path, "not_exists", repr(actual), "not_exists check")
    if op == "empty":
        matched = actual in (None, "", [], {}, ())
        return ConditionOutcome(matched, path, "empty", repr(actual), "empty check")
    if op == "not_empty":
        matched = actual not in (None, "", [], {}, ())
        return ConditionOutcome(matched, path, "not_empty", repr(actual), "not_empty check")
    if op == "eq":
        matched = actual == expected
        return ConditionOutcome(matched, path, repr(expected), repr(actual), "equality")
    if op == "ne":
        matched = actual != expected
        return ConditionOutcome(matched, path, f"!={expected!r}", repr(actual), "inequality")
    if op in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(actual)  # type: ignore[arg-type]
            right = float(expected)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise RuleEvaluationError(f"{op} requires numeric values") from exc
        matched = {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[op]
        return ConditionOutcome(matched, path, f"{op} {right}", str(left), "comparison")
    if op == "contains":
        if isinstance(actual, str):
            matched = str(expected) in actual
        else:
            matched = expected in _as_list(actual)
        return ConditionOutcome(matched, path, f"contains {expected!r}", repr(actual), "contains")
    if op == "not_contains":
        if isinstance(actual, str):
            matched = str(expected) not in actual
        else:
            matched = expected not in _as_list(actual)
        return ConditionOutcome(
            matched, path, f"not_contains {expected!r}", repr(actual), "not_contains"
        )
    if op == "regex":
        pattern = str(expected)
        try:
            matched = bool(re.search(pattern, str(actual) if actual is not None else ""))
        except re.error as exc:
            raise RuleEvaluationError(f"invalid regex: {exc}") from exc
        return ConditionOutcome(matched, path, f"regex {pattern}", repr(actual), "regex")
    if op == "in":
        matched = actual in _as_list(expected)
        return ConditionOutcome(matched, path, f"in {expected!r}", repr(actual), "in")
    if op == "not_in":
        matched = actual not in _as_list(expected)
        return ConditionOutcome(matched, path, f"not_in {expected!r}", repr(actual), "not_in")
    if op == "collection_all":
        items = _as_list(actual)
        child = rule.get("each")
        if not isinstance(child, dict):
            raise RuleEvaluationError("collection_all requires each")
        for idx, item in enumerate(items):
            scoped = {**snapshot, "_item": item, "_index": idx}
            outcome = evaluate_condition(child, scoped)
            if not outcome.matched:
                return ConditionOutcome(
                    False, f"{path}[{idx}]", outcome.expected, outcome.actual, outcome.message
                )
        return ConditionOutcome(True, path, "all items match", repr(len(items)), "collection_all")
    if op == "collection_any":
        items = _as_list(actual)
        child = rule.get("each")
        if not isinstance(child, dict):
            raise RuleEvaluationError("collection_any requires each")
        for idx, item in enumerate(items):
            scoped = {**snapshot, "_item": item, "_index": idx}
            outcome = evaluate_condition(child, scoped)
            if outcome.matched:
                return ConditionOutcome(
                    True, f"{path}[{idx}]", outcome.expected, outcome.actual, outcome.message
                )
        return ConditionOutcome(False, path, "any item match", repr(len(items)), "collection_any")

    raise RuleEvaluationError(f"unsupported op: {op}")


def evaluate_policy_rule(rule: dict[str, Any], snapshot: dict[str, Any]) -> ConditionOutcome:
    """Public entry: policy fails (finding) when condition MATCHES (violation detected).

    Convention: rules describe the *bad* state. matched=True => finding should open.
    """
    return evaluate_condition(rule, snapshot)


class PolicyEvaluationEngine:
    """Stateless reusable engine for any ResourceSnapshot-shaped dict."""

    def evaluate(self, rule: dict[str, Any], snapshot: dict[str, Any]) -> ConditionOutcome:
        return evaluate_policy_rule(rule, snapshot)
