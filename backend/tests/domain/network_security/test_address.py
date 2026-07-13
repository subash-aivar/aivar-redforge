"""Adversarial + regression tests for network address normalization,
classification, and bounded CIDR expansion — M16."""

from __future__ import annotations

import pytest

from redforge.domain.network_security.address import (
    MAX_NETWORK_ADDRESSES_PER_EXECUTION,
    NetworkAddressError,
    NetworkScopeTooLargeError,
    expand_cidr_bounded,
    normalize_and_classify,
    normalize_network,
)
from redforge.domain.validation_execution.value_objects import AddressClass


class TestMalformedInputRejected:
    @pytest.mark.parametrize("raw", ["not-an-ip", "999.999.999.999", "1.2.3", "", "  ", "gg::1"])
    def test_malformed_ipv4_or_ipv6_rejected(self, raw: str) -> None:
        with pytest.raises(NetworkAddressError):
            normalize_and_classify(raw)

    @pytest.mark.parametrize("raw", ["not-a-cidr", "10.0.0.0/abc", "10.0.0.0/99", ""])
    def test_malformed_cidr_rejected(self, raw: str) -> None:
        with pytest.raises(NetworkAddressError):
            normalize_network(raw)

    def test_malformed_input_never_raises_bare_value_error(self) -> None:
        # NetworkAddressError IS a ValueError subclass, but callers must
        # be able to catch the specific, controlled error type.
        with pytest.raises(NetworkAddressError):
            normalize_and_classify("garbage")


class TestCanonicalization:
    def test_ipv4_canonicalized(self) -> None:
        assert normalize_and_classify("10.20.30.40").value == "10.20.30.40"

    def test_ipv4_leading_zeros_rejected(self) -> None:
        # Python's ipaddress module deliberately rejects leading zeros
        # (octal-ambiguity security fix) — malformed, not silently
        # reinterpreted.
        with pytest.raises(NetworkAddressError):
            normalize_and_classify("127.000.000.001")

    def test_ipv6_canonicalized(self) -> None:
        result = normalize_and_classify("2001:0DB8:0000:0000:0000:0000:0000:0001")
        assert result.value == "2001:db8::1"

    def test_cidr_host_bits_masked(self) -> None:
        result = normalize_network("10.20.30.5/24")
        assert result.value == "10.20.30.0/24"


class TestClassification:
    @pytest.mark.parametrize(
        ("raw", "expected_class"),
        [
            ("127.0.0.1", AddressClass.LOOPBACK),
            ("::1", AddressClass.LOOPBACK),
            ("0.0.0.0", AddressClass.UNSPECIFIED),
            ("::", AddressClass.UNSPECIFIED),
            ("10.0.0.1", AddressClass.PRIVATE),
            ("169.254.1.1", AddressClass.LINK_LOCAL),
            ("fe80::1", AddressClass.LINK_LOCAL),
            ("224.0.0.1", AddressClass.MULTICAST),
            ("2001:db8::1", AddressClass.PRIVATE),  # documentation range (RFC 3849)
            ("8.8.8.8", AddressClass.PUBLIC),
            ("169.254.169.254", AddressClass.METADATA),
            ("::ffff:127.0.0.1", AddressClass.LOOPBACK),
        ],
    )
    def test_address_classification(self, raw: str, expected_class: AddressClass) -> None:
        assert normalize_and_classify(raw).address_class == expected_class

    def test_multicast_is_hard_denied(self) -> None:
        assert normalize_and_classify("224.0.0.1").is_hard_denied is True

    def test_unspecified_is_hard_denied(self) -> None:
        assert normalize_and_classify("0.0.0.0").is_hard_denied is True

    def test_metadata_is_hard_denied(self) -> None:
        assert normalize_and_classify("169.254.169.254").is_hard_denied is True

    def test_loopback_is_not_hard_denied(self) -> None:
        # LOOPBACK is authorization-gated, not categorically denied —
        # required for the owned local network lab.
        assert normalize_and_classify("127.0.0.1").is_hard_denied is False

    def test_private_is_not_hard_denied(self) -> None:
        assert normalize_and_classify("10.0.0.1").is_hard_denied is False


class TestBoundedCidrExpansion:
    def test_slash_32_yields_one_address(self) -> None:
        assert expand_cidr_bounded("10.20.30.40/32") == ["10.20.30.40"]

    def test_slash_31_yields_two_addresses(self) -> None:
        addresses = expand_cidr_bounded("10.20.30.40/31")
        assert len(addresses) == 2

    def test_slash_30_yields_two_usable_hosts(self) -> None:
        addresses = expand_cidr_bounded("10.20.30.40/30")
        assert len(addresses) == 2

    def test_exact_configured_boundary_accepted(self) -> None:
        # A /24 has 256 addresses == MAX_NETWORK_ADDRESSES_PER_EXECUTION.
        addresses = expand_cidr_bounded("10.20.30.0/24", max_addresses=256)
        assert len(addresses) <= 256

    def test_boundary_plus_one_rejected(self) -> None:
        with pytest.raises(NetworkScopeTooLargeError):
            expand_cidr_bounded("10.20.0.0/23", max_addresses=256)  # 512 addresses

    def test_huge_ipv4_scope_rejected_before_expansion(self) -> None:
        with pytest.raises(NetworkScopeTooLargeError):
            expand_cidr_bounded("10.0.0.0/8")

    def test_huge_ipv6_scope_rejected_without_expansion(self) -> None:
        # A /32 IPv6 network has 2^96 addresses — must be rejected by
        # the O(1) num_addresses check, never by materializing .hosts().
        with pytest.raises(NetworkScopeTooLargeError):
            expand_cidr_bounded("2001:db8::/32")

    def test_default_route_ipv4_rejected_immediately(self) -> None:
        with pytest.raises(NetworkAddressError):
            expand_cidr_bounded("0.0.0.0/0")

    def test_default_route_ipv6_rejected_immediately(self) -> None:
        with pytest.raises(NetworkAddressError):
            expand_cidr_bounded("::/0")

    def test_max_addresses_constant_is_bounded(self) -> None:
        assert MAX_NETWORK_ADDRESSES_PER_EXECUTION <= 4096


class TestNetworkContainment:
    def test_cidr_contains_member_address(self) -> None:
        network = normalize_network("10.20.30.0/24")
        assert network.contains("10.20.30.10") is True

    def test_cidr_does_not_contain_adjacent_address(self) -> None:
        network = normalize_network("10.20.30.0/24")
        assert network.contains("10.20.31.10") is False

    def test_ipv6_cidr_contains_member(self) -> None:
        network = normalize_network("2001:db8::/32")
        assert network.contains("2001:db8::1") is True

    def test_ipv6_cidr_does_not_contain_non_member(self) -> None:
        network = normalize_network("2001:db8::/32")
        assert network.contains("2001:db9::1") is False

    def test_containment_never_raises_for_malformed_address(self) -> None:
        network = normalize_network("10.20.30.0/24")
        assert network.contains("not-an-ip") is False

    def test_ipv4_network_does_not_contain_ipv6_address(self) -> None:
        network = normalize_network("10.20.30.0/24")
        assert network.contains("::1") is False


class TestCanonicalDeduplication:
    def test_ipv6_compressed_and_expanded_forms_produce_identical_canonical_value(self) -> None:
        expanded = normalize_and_classify("2001:0db8:0000:0000:0000:0000:0000:0001")
        compressed = normalize_and_classify("2001:db8::1")
        assert expanded.value == compressed.value

    def test_ipv6_mixed_case_hex_produces_identical_canonical_value(self) -> None:
        upper = normalize_and_classify("2001:DB8::1")
        lower = normalize_and_classify("2001:db8::1")
        assert upper.value == lower.value

    def test_ipv4_mapped_ipv6_and_ipv4_form_collapse_to_the_same_loopback_class(self) -> None:
        mapped = normalize_and_classify("::ffff:127.0.0.1")
        plain = normalize_and_classify("127.0.0.1")
        assert mapped.address_class == plain.address_class

    def test_duplicate_addresses_in_a_set_collapse_after_normalization(self) -> None:
        raw_values = ["2001:DB8::1", "2001:db8:0:0:0:0:0:1", "2001:db8::1"]
        normalized = {normalize_and_classify(v).value for v in raw_values}
        assert len(normalized) == 1

    def test_cidr_normalization_is_idempotent(self) -> None:
        once = normalize_network("10.20.30.0/24")
        twice = normalize_network(once.value)
        assert once.value == twice.value
