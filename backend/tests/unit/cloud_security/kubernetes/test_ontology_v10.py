"""Ontology v10 Kubernetes edge pairing tests."""

from __future__ import annotations

import pytest

from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ontology_version_is_at_least_v10() -> None:
    assert ONTOLOGY_VERSION >= 10


def test_k8s_node_kinds_exist() -> None:
    assert NodeKind.K8S_CLUSTER.value == "k8s_cluster"
    assert NodeKind.K8S_NAMESPACE.value == "k8s_namespace"
    assert NodeKind.K8S_WORKLOAD.value == "k8s_workload"
    assert NodeKind.K8S_RBAC.value == "k8s_rbac"
    assert NodeKind.K8S_NETWORK_POLICY.value == "k8s_network_policy"
    assert NodeKind.K8S_SERVICE.value == "k8s_service"


def test_k8s_edge_kinds_exist() -> None:
    assert EdgeKind.RUNS_IN.value == "runs_in"
    assert EdgeKind.DEPLOYS.value == "deploys"
    assert EdgeKind.BINDS.value == "binds"
    assert EdgeKind.ALLOWS.value == "allows"
    assert EdgeKind.DENIES.value == "denies"
    assert EdgeKind.HOSTS.value == "hosts"
    assert EdgeKind.USES.value == "uses"
    assert EdgeKind.USES != EdgeKind.USES_MODEL


def test_hosts_valid_pair() -> None:
    validate_edge(EdgeKind.HOSTS, NodeKind.K8S_CLUSTER, NodeKind.K8S_NAMESPACE)


def test_deploys_valid_pairs() -> None:
    validate_edge(EdgeKind.DEPLOYS, NodeKind.K8S_CLUSTER, NodeKind.K8S_WORKLOAD)
    validate_edge(EdgeKind.DEPLOYS, NodeKind.K8S_NAMESPACE, NodeKind.K8S_WORKLOAD)


def test_runs_in_valid_pair() -> None:
    validate_edge(EdgeKind.RUNS_IN, NodeKind.K8S_WORKLOAD, NodeKind.K8S_NAMESPACE)


def test_binds_valid_pair() -> None:
    validate_edge(EdgeKind.BINDS, NodeKind.K8S_RBAC, NodeKind.K8S_WORKLOAD)


def test_allows_and_denies() -> None:
    validate_edge(EdgeKind.ALLOWS, NodeKind.K8S_NETWORK_POLICY, NodeKind.K8S_WORKLOAD)
    validate_edge(EdgeKind.DENIES, NodeKind.K8S_NETWORK_POLICY, NodeKind.K8S_WORKLOAD)


def test_uses_valid_pairs() -> None:
    validate_edge(EdgeKind.USES, NodeKind.K8S_WORKLOAD, NodeKind.K8S_SERVICE)
    validate_edge(EdgeKind.USES, NodeKind.K8S_WORKLOAD, NodeKind.K8S_RBAC)


def test_exposes_k8s_workload_to_service() -> None:
    validate_edge(EdgeKind.EXPOSES, NodeKind.K8S_WORKLOAD, NodeKind.K8S_SERVICE)
    validate_edge(EdgeKind.EXPOSES, NodeKind.HOST, NodeKind.SERVICE)


def test_hosts_rejects_reversed() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.HOSTS, NodeKind.K8S_NAMESPACE, NodeKind.K8S_CLUSTER)


def test_uses_rejects_wrong_source() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.USES, NodeKind.K8S_SERVICE, NodeKind.K8S_WORKLOAD)


def test_runs_in_rejects_wrong_target() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.RUNS_IN, NodeKind.K8S_WORKLOAD, NodeKind.K8S_CLUSTER)


def test_binds_rejects_wrong_source() -> None:
    with pytest.raises(InvalidRelationshipError):
        validate_edge(EdgeKind.BINDS, NodeKind.K8S_WORKLOAD, NodeKind.K8S_RBAC)
