from redforge.domain.security_graph.ontology import (
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_identity_member_of_group_valid() -> None:
    validate_edge(EdgeKind.MEMBER_OF, NodeKind.IDENTITY, NodeKind.GROUP)


def test_service_identity_member_of_group_valid() -> None:
    validate_edge(EdgeKind.MEMBER_OF, NodeKind.SERVICE_IDENTITY, NodeKind.GROUP)


def test_group_member_of_group_rejected() -> None:
    """Nested group->group membership is NOT enabled in M5 — no
    producing adapter resolves it yet."""
    try:
        validate_edge(EdgeKind.MEMBER_OF, NodeKind.GROUP, NodeKind.GROUP)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_member_of_wrong_target_rejected() -> None:
    try:
        validate_edge(EdgeKind.MEMBER_OF, NodeKind.IDENTITY, NodeKind.HOST)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_identity_cannot_use_model() -> None:
    try:
        validate_edge(EdgeKind.USES_MODEL, NodeKind.IDENTITY, NodeKind.MODEL)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")
