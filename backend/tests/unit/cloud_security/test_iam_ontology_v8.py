"""Ontology v8 IAM edge pairing tests."""

from __future__ import annotations

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ontology_version_is_at_least_v8() -> None:
    assert ONTOLOGY_VERSION >= 8


def test_assumes_role_valid_pairs() -> None:
    validate_edge(EdgeKind.ASSUMES_ROLE, NodeKind.IDENTITY, NodeKind.IAM_ROLE)
    validate_edge(EdgeKind.ASSUMES_ROLE, NodeKind.SERVICE_IDENTITY, NodeKind.IAM_ROLE)
    validate_edge(EdgeKind.ASSUMES_ROLE, NodeKind.IAM_ROLE, NodeKind.IAM_ROLE)


def test_has_policy_valid_pairs() -> None:
    validate_edge(EdgeKind.HAS_POLICY, NodeKind.IDENTITY, NodeKind.IAM_POLICY)
    validate_edge(EdgeKind.HAS_POLICY, NodeKind.SERVICE_IDENTITY, NodeKind.IAM_POLICY)
    validate_edge(EdgeKind.HAS_POLICY, NodeKind.IAM_ROLE, NodeKind.IAM_POLICY)
    validate_edge(EdgeKind.HAS_POLICY, NodeKind.GROUP, NodeKind.IAM_POLICY)


def test_trusts_valid_pairs() -> None:
    validate_edge(EdgeKind.TRUSTS, NodeKind.IAM_ROLE, NodeKind.IDENTITY)
    validate_edge(EdgeKind.TRUSTS, NodeKind.IAM_ROLE, NodeKind.SERVICE_IDENTITY)
    validate_edge(EdgeKind.TRUSTS, NodeKind.IAM_ROLE, NodeKind.IAM_ROLE)
    validate_edge(EdgeKind.TRUSTS, NodeKind.IAM_ROLE, NodeKind.GROUP)


def test_assumes_role_rejects_invalid() -> None:
    try:
        validate_edge(EdgeKind.ASSUMES_ROLE, NodeKind.GROUP, NodeKind.IAM_ROLE)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_has_policy_rejects_invalid() -> None:
    try:
        validate_edge(EdgeKind.HAS_POLICY, NodeKind.IAM_POLICY, NodeKind.IDENTITY)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_trusts_rejects_non_role_source() -> None:
    try:
        validate_edge(EdgeKind.TRUSTS, NodeKind.IDENTITY, NodeKind.IAM_ROLE)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")
