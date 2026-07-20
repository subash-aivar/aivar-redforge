"""Ontology v12 Cloud Risk edge pairing tests."""

from __future__ import annotations

import pytest

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ontology_version_is_at_least_v12() -> None:
    # M27 Phase 5 bumped ontology to v13; v12 risk pairings remain valid.
    assert ONTOLOGY_VERSION >= 12


def test_risk_node_kinds_exist() -> None:
    assert NodeKind.RISK.value == "risk"
    assert NodeKind.RISK_FACTOR.value == "risk_factor"
    assert NodeKind.RISK_EXPOSURE.value == "risk_exposure"


def test_risk_edge_kinds_exist() -> None:
    assert EdgeKind.HAS_RISK.value == "has_risk"
    assert EdgeKind.HAS_FACTOR.value == "has_factor"
    assert EdgeKind.HAS_EXPOSURE.value == "has_exposure"


@pytest.mark.parametrize("source", [NodeKind.CLOUD_RESOURCE, NodeKind.ASSET])
def test_has_risk_valid_pairs(source: NodeKind) -> None:
    validate_edge(EdgeKind.HAS_RISK, source, NodeKind.RISK)


def test_has_factor_valid() -> None:
    validate_edge(EdgeKind.HAS_FACTOR, NodeKind.RISK, NodeKind.RISK_FACTOR)


def test_has_exposure_valid() -> None:
    validate_edge(EdgeKind.HAS_EXPOSURE, NodeKind.RISK, NodeKind.RISK_EXPOSURE)


def test_has_risk_rejects_reversed() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HAS_RISK, NodeKind.RISK, NodeKind.ASSET)


def test_has_factor_rejects_wrong_source() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HAS_FACTOR, NodeKind.ASSET, NodeKind.RISK_FACTOR)


def test_has_exposure_rejects_wrong_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HAS_EXPOSURE, NodeKind.RISK, NodeKind.RISK_FACTOR)


def test_runtime_edges_still_valid_under_v12() -> None:
    validate_edge(EdgeKind.OBSERVED_ON, NodeKind.RUNTIME_EVENT, NodeKind.ASSET)
    validate_edge(EdgeKind.ORIGINATED_FROM, NodeKind.RUNTIME_EVENT, NodeKind.CLOUD_ACCOUNT)


def test_k8s_edges_still_valid_under_v12() -> None:
    validate_edge(EdgeKind.HOSTS, NodeKind.K8S_CLUSTER, NodeKind.K8S_NAMESPACE)


def test_cspm_edges_still_valid_under_v12() -> None:
    validate_edge(EdgeKind.AFFECTS, NodeKind.CSPM_FINDING, NodeKind.CLOUD_RESOURCE)


@pytest.mark.parametrize(
    ("edge", "source", "target"),
    [
        (EdgeKind.HAS_RISK, NodeKind.FINDING, NodeKind.RISK),
        (EdgeKind.HAS_RISK, NodeKind.IDENTITY, NodeKind.RISK),
        (EdgeKind.HAS_FACTOR, NodeKind.RISK_FACTOR, NodeKind.RISK),
        (EdgeKind.HAS_EXPOSURE, NodeKind.RISK_EXPOSURE, NodeKind.RISK),
        (EdgeKind.HAS_FACTOR, NodeKind.RISK, NodeKind.RISK_EXPOSURE),
    ],
)
def test_invalid_risk_pairs(
    edge: EdgeKind, source: NodeKind, target: NodeKind
) -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(edge, source, target)
