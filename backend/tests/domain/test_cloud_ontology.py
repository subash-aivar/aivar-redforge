from redforge.domain.security_graph.ontology import (
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_cloud_account_contains_cloud_resource_valid() -> None:
    validate_edge(EdgeKind.CONTAINS, NodeKind.CLOUD_ACCOUNT, NodeKind.CLOUD_RESOURCE)


def test_cloud_resource_cannot_contain_cloud_account() -> None:
    try:
        validate_edge(EdgeKind.CONTAINS, NodeKind.CLOUD_RESOURCE, NodeKind.CLOUD_ACCOUNT)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_cloud_account_cannot_contain_host() -> None:
    try:
        validate_edge(EdgeKind.CONTAINS, NodeKind.CLOUD_ACCOUNT, NodeKind.HOST)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_cloud_account_cannot_use_model() -> None:
    try:
        validate_edge(EdgeKind.USES_MODEL, NodeKind.CLOUD_ACCOUNT, NodeKind.MODEL)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_no_can_access_edge_kind_exists() -> None:
    """CAN_ACCESS is deliberately NOT part of the ontology yet — no
    authoritative source proves identity-to-cloud-resource access."""
    assert not any(k.value == "can_access" for k in EdgeKind)
