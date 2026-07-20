"""Ontology v11 Runtime Visibility edge pairing tests."""

from __future__ import annotations

import pytest

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ontology_version_at_least_v11() -> None:
    # Phase 7 bumped ontology to v12; runtime kinds remain valid.
    assert ONTOLOGY_VERSION >= 11


def test_runtime_node_kinds_exist() -> None:
    assert NodeKind.RUNTIME_EVENT.value == "runtime_event"
    assert NodeKind.RUNTIME_PROCESS.value == "runtime_process"
    assert NodeKind.RUNTIME_CONNECTION.value == "runtime_connection"


def test_runtime_edge_kinds_exist() -> None:
    assert EdgeKind.OBSERVED_ON.value == "observed_on"
    assert EdgeKind.ASSOCIATED_WITH.value == "associated_with"
    assert EdgeKind.ORIGINATED_FROM.value == "originated_from"


@pytest.mark.parametrize(
    "source",
    [NodeKind.RUNTIME_EVENT, NodeKind.RUNTIME_PROCESS, NodeKind.RUNTIME_CONNECTION],
)
@pytest.mark.parametrize(
    "target",
    [NodeKind.CLOUD_RESOURCE, NodeKind.ASSET, NodeKind.K8S_WORKLOAD],
)
def test_observed_on_valid_pairs(source: NodeKind, target: NodeKind) -> None:
    validate_edge(EdgeKind.OBSERVED_ON, source, target)


@pytest.mark.parametrize(
    "source",
    [NodeKind.RUNTIME_EVENT, NodeKind.RUNTIME_PROCESS, NodeKind.RUNTIME_CONNECTION],
)
@pytest.mark.parametrize(
    "target",
    [NodeKind.IDENTITY, NodeKind.IAM_ROLE, NodeKind.SERVICE_IDENTITY],
)
def test_associated_with_valid_pairs(source: NodeKind, target: NodeKind) -> None:
    validate_edge(EdgeKind.ASSOCIATED_WITH, source, target)


@pytest.mark.parametrize(
    "source",
    [NodeKind.RUNTIME_EVENT, NodeKind.RUNTIME_PROCESS, NodeKind.RUNTIME_CONNECTION],
)
def test_originated_from_valid_pairs(source: NodeKind) -> None:
    validate_edge(EdgeKind.ORIGINATED_FROM, source, NodeKind.CLOUD_ACCOUNT)


def test_observed_on_rejects_reversed() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.OBSERVED_ON, NodeKind.ASSET, NodeKind.RUNTIME_EVENT)


def test_associated_with_rejects_wrong_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.ASSOCIATED_WITH, NodeKind.RUNTIME_EVENT, NodeKind.CLOUD_ACCOUNT)


def test_originated_from_rejects_wrong_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.ORIGINATED_FROM, NodeKind.RUNTIME_EVENT, NodeKind.ASSET)


def test_k8s_edges_still_valid_under_v11() -> None:
    validate_edge(EdgeKind.HOSTS, NodeKind.K8S_CLUSTER, NodeKind.K8S_NAMESPACE)
    validate_edge(EdgeKind.RUNS_IN, NodeKind.K8S_WORKLOAD, NodeKind.K8S_NAMESPACE)
