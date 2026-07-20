"""Ontology v9 CSPM edge pairing tests."""

from __future__ import annotations

import pytest

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ontology_version_is_at_least_v9() -> None:
    assert ONTOLOGY_VERSION >= 9


def test_cspm_node_kinds_exist() -> None:
    assert NodeKind.CSPM_FINDING.value == "cspm_finding"
    assert NodeKind.CONTROL.value == "control"


def test_cspm_edge_kinds_exist() -> None:
    assert EdgeKind.AFFECTS.value == "affects"
    assert EdgeKind.VIOLATES.value == "violates"
    assert EdgeKind.EVALUATED_BY.value == "evaluated_by"


def test_affects_valid_pairs() -> None:
    validate_edge(EdgeKind.AFFECTS, NodeKind.CSPM_FINDING, NodeKind.CLOUD_RESOURCE)
    validate_edge(EdgeKind.AFFECTS, NodeKind.CSPM_FINDING, NodeKind.ASSET)
    validate_edge(EdgeKind.AFFECTS, NodeKind.CSPM_FINDING, NodeKind.CLOUD_ACCOUNT)


def test_violates_valid_pair() -> None:
    validate_edge(EdgeKind.VIOLATES, NodeKind.CSPM_FINDING, NodeKind.CONTROL)


def test_evaluated_by_valid_pair() -> None:
    validate_edge(EdgeKind.EVALUATED_BY, NodeKind.CSPM_FINDING, NodeKind.CONTROL)


def test_affects_rejects_reversed() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.AFFECTS, NodeKind.CLOUD_RESOURCE, NodeKind.CSPM_FINDING)


def test_violates_rejects_wrong_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.VIOLATES, NodeKind.CSPM_FINDING, NodeKind.ASSET)


def test_evaluated_by_rejects_wrong_source() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.EVALUATED_BY, NodeKind.CONTROL, NodeKind.CSPM_FINDING)
