from redforge.domain.security_graph.ontology import (
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_valid_pairing_accepted() -> None:
    validate_edge(EdgeKind.USES_MODEL, NodeKind.AI_AGENT, NodeKind.MODEL)


def test_invalid_pairing_rejected() -> None:
    try:
        validate_edge(EdgeKind.USES_MODEL, NodeKind.IP_ADDRESS, NodeKind.CLOUD_RESOURCE)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_hosts_model_valid() -> None:
    validate_edge(EdgeKind.HOSTS_MODEL, NodeKind.CLOUD_RESOURCE, NodeKind.MODEL)


def test_hosts_model_wrong_target_rejected() -> None:
    try:
        validate_edge(EdgeKind.HOSTS_MODEL, NodeKind.CLOUD_RESOURCE, NodeKind.HOST)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_has_finding_valid_from_any_asset_kind() -> None:
    validate_edge(EdgeKind.HAS_FINDING, NodeKind.HOST, NodeKind.FINDING)
    validate_edge(EdgeKind.HAS_FINDING, NodeKind.AI_AGENT, NodeKind.FINDING)


def test_has_finding_wrong_target_rejected() -> None:
    try:
        validate_edge(EdgeKind.HAS_FINDING, NodeKind.HOST, NodeKind.HOST)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_custom_edge_permissive_between_asset_kinds() -> None:
    validate_edge(EdgeKind.CUSTOM, NodeKind.HOST, NodeKind.IP_ADDRESS)


def test_custom_edge_rejects_finding_endpoint() -> None:
    try:
        validate_edge(EdgeKind.CUSTOM, NodeKind.HOST, NodeKind.FINDING)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_runs_on_valid() -> None:
    validate_edge(EdgeKind.RUNS_ON, NodeKind.APPLICATION, NodeKind.HOST)


def test_serves_endpoint_valid() -> None:
    validate_edge(EdgeKind.SERVES_ENDPOINT, NodeKind.MODEL, NodeKind.APPLICATION)


def test_retrieves_from_valid() -> None:
    validate_edge(EdgeKind.RETRIEVES_FROM, NodeKind.AI_SYSTEM, NodeKind.DATA_STORE)


def test_all_edge_kinds_have_an_ontology_entry() -> None:
    from redforge.domain.security_graph.ontology import EDGE_ONTOLOGY

    for kind in EdgeKind:
        assert kind in EDGE_ONTOLOGY
