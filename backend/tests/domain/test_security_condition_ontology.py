import pytest

from redforge.domain.security_conditions.value_objects import (
    ConditionLifecycle,
    EvidenceState,
    SecurityConditionValidationError,
    SourceCategory,
    build_condition_identity_key,
)
from redforge.domain.security_graph.ontology import (
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_asset_has_security_condition_valid() -> None:
    validate_edge(EdgeKind.HAS_SECURITY_CONDITION, NodeKind.HOST, NodeKind.SECURITY_CONDITION)
    validate_edge(
        EdgeKind.HAS_SECURITY_CONDITION, NodeKind.CLOUD_ACCOUNT, NodeKind.SECURITY_CONDITION,
    )
    validate_edge(
        EdgeKind.HAS_SECURITY_CONDITION, NodeKind.CLOUD_RESOURCE, NodeKind.SECURITY_CONDITION,
    )


def test_security_condition_cannot_be_edge_source() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HAS_SECURITY_CONDITION, NodeKind.SECURITY_CONDITION, NodeKind.HOST)


def test_finding_is_not_a_valid_has_security_condition_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HAS_SECURITY_CONDITION, NodeKind.HOST, NodeKind.FINDING)


def test_identity_key_same_rule_same_asset_same_qualifier_matches() -> None:
    key_1 = build_condition_identity_key("org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1")
    key_2 = build_condition_identity_key("org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1")
    assert key_1 == key_2


def test_identity_key_same_rule_two_assets_differs() -> None:
    key_1 = build_condition_identity_key("org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1")
    key_2 = build_condition_identity_key("org-1", "asset-2", SourceCategory.NETWORK_DISCOVERY, "R1")
    assert key_1 != key_2


def test_identity_key_different_qualifier_differs() -> None:
    key_1 = build_condition_identity_key(
        "org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1", qualifier="22",
    )
    key_2 = build_condition_identity_key(
        "org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1", qualifier="23",
    )
    assert key_1 != key_2


def test_identity_key_does_not_encode_title_summary_remediation() -> None:
    """The identity key is built purely from org/asset/source/rule/
    qualifier — title, summary, remediation text play no role, so
    editing them can never fabricate a duplicate identity."""
    key = build_condition_identity_key("org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "R1")
    assert "title" not in key.lower()
    assert "summary" not in key.lower()
    assert "remediation" not in key.lower()


def test_identity_key_rejects_empty_asset_or_rule() -> None:
    with pytest.raises(SecurityConditionValidationError):
        build_condition_identity_key("org-1", "", SourceCategory.NETWORK_DISCOVERY, "R1")
    with pytest.raises(SecurityConditionValidationError):
        build_condition_identity_key("org-1", "asset-1", SourceCategory.NETWORK_DISCOVERY, "")


def test_evidence_state_enum_is_closed() -> None:
    assert {s.value for s in EvidenceState} == {"observed", "inferred", "validated"}
    with pytest.raises(ValueError):
        EvidenceState("exploited")


def test_source_category_has_no_speculative_producers() -> None:
    """AI_RED_TEAM must not appear until a real producing source exists
    for it. ACTIVE_VALIDATION is no longer speculative as of M11 — the
    Gated Safe Active Validation engine
    (application/validation_execution/) is its real producing path."""
    values = {s.value for s in SourceCategory}
    assert "active_validation" in values
    assert "ai_red_team" not in values


def test_condition_lifecycle_is_closed() -> None:
    assert {s.value for s in ConditionLifecycle} == {"active", "resolved"}
