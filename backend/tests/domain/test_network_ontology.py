from redforge.domain.security_graph.ontology import (
    EdgeKind,
    InvalidRelationshipError,
    NodeKind,
    validate_edge,
)


def test_ip_connected_to_host_valid() -> None:
    validate_edge(EdgeKind.CONNECTED_TO, NodeKind.IP_ADDRESS, NodeKind.HOST)


def test_ip_connected_to_device_valid() -> None:
    validate_edge(EdgeKind.CONNECTED_TO, NodeKind.IP_ADDRESS, NodeKind.DEVICE)


def test_device_connected_to_network_valid() -> None:
    validate_edge(EdgeKind.CONNECTED_TO, NodeKind.DEVICE, NodeKind.NETWORK)


def test_host_exposes_service_valid() -> None:
    validate_edge(EdgeKind.EXPOSES, NodeKind.HOST, NodeKind.SERVICE)


def test_device_exposes_service_valid() -> None:
    validate_edge(EdgeKind.EXPOSES, NodeKind.DEVICE, NodeKind.SERVICE)


def test_ip_member_of_network_valid() -> None:
    validate_edge(EdgeKind.MEMBER_OF_NETWORK, NodeKind.IP_ADDRESS, NodeKind.NETWORK)


def test_network_cannot_expose_service() -> None:
    try:
        validate_edge(EdgeKind.EXPOSES, NodeKind.NETWORK, NodeKind.SERVICE)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_service_cannot_connect_to_network() -> None:
    try:
        validate_edge(EdgeKind.CONNECTED_TO, NodeKind.SERVICE, NodeKind.NETWORK)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_ip_member_of_network_does_not_reuse_directory_member_of() -> None:
    """M6 network membership must NOT overload M5's directory MEMBER_OF
    semantics — IP_ADDRESS is not a valid MEMBER_OF source."""
    try:
        validate_edge(EdgeKind.MEMBER_OF, NodeKind.IP_ADDRESS, NodeKind.NETWORK)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")


def test_host_cannot_use_model() -> None:
    try:
        validate_edge(EdgeKind.USES_MODEL, NodeKind.HOST, NodeKind.MODEL)
    except InvalidRelationshipError:
        pass
    else:
        raise AssertionError("expected InvalidRelationshipError")
