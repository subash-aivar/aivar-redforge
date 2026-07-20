"""PolicyEvaluationEngine op coverage tests."""

from __future__ import annotations

import pytest

from redforge.domain.cloud_security.policy_engine.evaluator import (
    PolicyEvaluationEngine,
    RuleEvaluationError,
    evaluate_condition,
    evaluate_policy_rule,
)

engine = PolicyEvaluationEngine()


def _snap(**kwargs: object) -> dict[str, object]:
    base: dict[str, object] = {
        "normalized_config": {
            "network_exposure": "PUBLIC",
            "encryption_at_rest": False,
            "kms_key_id": None,
            "public_endpoints": ["https://x"],
            "attributes": {"open_cidr": "0.0.0.0/0"},
            "tags_list": ["a", "b"],
            "score": 5,
        }
    }
    base.update(kwargs)
    return base


def test_eq_match() -> None:
    out = engine.evaluate(
        {"op": "eq", "path": "normalized_config.network_exposure", "value": "PUBLIC"},
        _snap(),
    )
    assert out.matched is True


def test_eq_mismatch() -> None:
    out = engine.evaluate(
        {"op": "eq", "path": "normalized_config.network_exposure", "value": "PRIVATE"},
        _snap(),
    )
    assert out.matched is False


def test_ne() -> None:
    out = engine.evaluate(
        {"op": "ne", "path": "normalized_config.encryption_at_rest", "value": True},
        _snap(),
    )
    assert out.matched is True


def test_exists() -> None:
    out = engine.evaluate(
        {"op": "exists", "path": "normalized_config.network_exposure"}, _snap()
    )
    assert out.matched is True


def test_not_exists() -> None:
    out = engine.evaluate(
        {"op": "not_exists", "path": "normalized_config.kms_key_id"}, _snap()
    )
    assert out.matched is True


def test_empty_and_not_empty() -> None:
    snap = _snap()
    snap["normalized_config"]["kms_key_id"] = ""  # type: ignore[index]
    assert engine.evaluate(
        {"op": "empty", "path": "normalized_config.kms_key_id"}, snap
    ).matched
    assert engine.evaluate(
        {"op": "not_empty", "path": "normalized_config.public_endpoints"}, snap
    ).matched


def test_gt_gte_lt_lte() -> None:
    snap = _snap()
    assert engine.evaluate(
        {"op": "gt", "path": "normalized_config.score", "value": 3}, snap
    ).matched
    assert engine.evaluate(
        {"op": "gte", "path": "normalized_config.score", "value": 5}, snap
    ).matched
    assert engine.evaluate(
        {"op": "lt", "path": "normalized_config.score", "value": 10}, snap
    ).matched
    assert engine.evaluate(
        {"op": "lte", "path": "normalized_config.score", "value": 5}, snap
    ).matched


def test_comparison_non_numeric_raises() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate(
            {"op": "gt", "path": "normalized_config.network_exposure", "value": 1},
            _snap(),
        )


def test_contains_string_and_list() -> None:
    snap = _snap()
    assert engine.evaluate(
        {
            "op": "contains",
            "path": "normalized_config.attributes.open_cidr",
            "value": "0.0.0.0",
        },
        snap,
    ).matched
    assert engine.evaluate(
        {"op": "contains", "path": "normalized_config.tags_list", "value": "a"}, snap
    ).matched


def test_not_contains() -> None:
    assert engine.evaluate(
        {"op": "not_contains", "path": "normalized_config.tags_list", "value": "z"},
        _snap(),
    ).matched


def test_regex() -> None:
    assert engine.evaluate(
        {
            "op": "regex",
            "path": "normalized_config.network_exposure",
            "value": "^PUB",
        },
        _snap(),
    ).matched


def test_invalid_regex_raises() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate(
            {"op": "regex", "path": "normalized_config.network_exposure", "value": "["},
            _snap(),
        )


def test_in_and_not_in() -> None:
    snap = _snap()
    assert engine.evaluate(
        {
            "op": "in",
            "path": "normalized_config.network_exposure",
            "value": ["PUBLIC", "VPN_ONLY"],
        },
        snap,
    ).matched
    assert engine.evaluate(
        {
            "op": "not_in",
            "path": "normalized_config.network_exposure",
            "value": ["PRIVATE"],
        },
        snap,
    ).matched


def test_all_any_not() -> None:
    snap = _snap()
    assert engine.evaluate(
        {
            "all": [
                {"op": "eq", "path": "normalized_config.network_exposure", "value": "PUBLIC"},
                {"op": "eq", "path": "normalized_config.encryption_at_rest", "value": False},
            ]
        },
        snap,
    ).matched
    assert engine.evaluate(
        {
            "any": [
                {"op": "eq", "path": "normalized_config.network_exposure", "value": "PRIVATE"},
                {"op": "eq", "path": "normalized_config.encryption_at_rest", "value": False},
            ]
        },
        snap,
    ).matched
    assert engine.evaluate(
        {
            "not": {
                "op": "eq",
                "path": "normalized_config.network_exposure",
                "value": "PRIVATE",
            }
        },
        snap,
    ).matched


def test_always_true_false() -> None:
    assert engine.evaluate({"op": "always_true"}, {}).matched
    assert not engine.evaluate({"op": "always_false"}, {}).matched


def test_collection_all_and_any() -> None:
    snap = {
        "items": [
            {"ok": True},
            {"ok": True},
        ]
    }
    assert engine.evaluate(
        {
            "op": "collection_all",
            "path": "items",
            "each": {"op": "eq", "path": "_item.ok", "value": True},
        },
        snap,
    ).matched
    snap2 = {"items": [{"ok": False}, {"ok": True}]}
    assert engine.evaluate(
        {
            "op": "collection_any",
            "path": "items",
            "each": {"op": "eq", "path": "_item.ok", "value": True},
        },
        snap2,
    ).matched
    assert not engine.evaluate(
        {
            "op": "collection_all",
            "path": "items",
            "each": {"op": "eq", "path": "_item.ok", "value": True},
        },
        snap2,
    ).matched


def test_collection_requires_each() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate({"op": "collection_all", "path": "items"}, {"items": []})


def test_unsupported_op() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate({"op": "explode", "path": "x"}, {})


def test_missing_op() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate({"path": "x"}, {})


def test_all_requires_non_empty() -> None:
    with pytest.raises(RuleEvaluationError):
        evaluate_condition({"all": []}, {})


def test_any_requires_non_empty() -> None:
    with pytest.raises(RuleEvaluationError):
        evaluate_condition({"any": []}, {})


def test_not_requires_object() -> None:
    with pytest.raises(RuleEvaluationError):
        evaluate_condition({"not": "x"}, {})


def test_eq_requires_path() -> None:
    with pytest.raises(RuleEvaluationError):
        engine.evaluate({"op": "eq", "value": 1}, {})


def test_evaluate_policy_rule_alias() -> None:
    out = evaluate_policy_rule({"op": "always_true"}, {})
    assert out.matched is True


def test_nested_path_missing_returns_none() -> None:
    out = engine.evaluate({"op": "exists", "path": "a.b.c"}, {"a": {"b": 1}})
    assert out.matched is False
