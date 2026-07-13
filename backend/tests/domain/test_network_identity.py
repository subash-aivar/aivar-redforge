import pytest

from redforge.domain.inventory.identity import (
    IdentityNormalizationError,
    IdentityScheme,
    build_external_id,
)


def test_ipv4_canonicalizes() -> None:
    ext = build_external_id(IdentityScheme.IP_ADDRESS, "192.168.1.10")
    assert ext == "ip_address:192.168.1.10"


def test_ipv6_canonicalizes() -> None:
    ext = build_external_id(IdentityScheme.IP_ADDRESS, "2001:0db8:0000:0000:0000:0000:0000:0001")
    ext2 = build_external_id(IdentityScheme.IP_ADDRESS, "2001:db8::1")
    assert ext == ext2


def test_invalid_ip_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.IP_ADDRESS, "999.999.999.999")


def test_cidr_host_bits_masked_identically() -> None:
    a = build_external_id(IdentityScheme.NETWORK_CIDR, "10.0.0.1/24")
    b = build_external_id(IdentityScheme.NETWORK_CIDR, "10.0.0.0/24")
    assert a == b == "network_cidr:10.0.0.0/24"


def test_cidr_different_prefix_differs() -> None:
    a = build_external_id(IdentityScheme.NETWORK_CIDR, "10.0.0.0/24")
    b = build_external_id(IdentityScheme.NETWORK_CIDR, "10.0.0.0/25")
    assert a != b


def test_invalid_cidr_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.NETWORK_CIDR, "not-a-network")


def test_discovery_host_requires_connector_scope() -> None:
    ext = build_external_id(IdentityScheme.DISCOVERY_HOST, "conn-1:HOST.EXAMPLE.com")
    assert ext == "discovery_host:conn-1:host.example.com"


def test_discovery_host_missing_connector_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.DISCOVERY_HOST, "host.example.com")


def test_service_endpoint_canonical_form() -> None:
    ext = build_external_id(IdentityScheme.SERVICE_ENDPOINT, "01ABC:TCP:22")
    assert ext == "service_endpoint:01ABC:tcp:22"


def test_service_endpoint_invalid_protocol_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.SERVICE_ENDPOINT, "01ABC:icmp:22")


def test_service_endpoint_out_of_range_port_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.SERVICE_ENDPOINT, "01ABC:tcp:70000")


def test_service_endpoint_malformed_rejected() -> None:
    with pytest.raises(IdentityNormalizationError):
        build_external_id(IdentityScheme.SERVICE_ENDPOINT, "not-enough-parts")
