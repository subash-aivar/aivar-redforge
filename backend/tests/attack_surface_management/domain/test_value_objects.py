from __future__ import annotations

import pytest

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidAssetOwnershipError,
    InvalidCidrBlockError,
    InvalidCriticalityScoreError,
    InvalidDomainNameError,
    InvalidIpAddressError,
    InvalidSubdomainError,
    InvalidTechnologyFingerprintError,
)
from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.criticality_score import CriticalityScore
from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
from attack_surface_management.domain.value_objects.identifiers import (
    AssetId,
    CertificateId,
    DnsRecordId,
    NetworkRangeId,
    PortId,
    TenantId,
)
from attack_surface_management.domain.value_objects.ip_address import IPAddress
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner
from attack_surface_management.domain.value_objects.technology_fingerprint import (
    TechnologyFingerprint,
)

# -- identifiers -------------------------------------------------------


def test_tenant_id_is_shared_entity_id() -> None:
    from redforge.shared.identifiers import EntityId

    assert TenantId is EntityId
    tid = TenantId.generate()
    assert TenantId.from_string(str(tid)) == tid


@pytest.mark.parametrize("id_cls", [AssetId, NetworkRangeId, PortId, CertificateId, DnsRecordId])
def test_local_identifiers_generate_unique_values(id_cls: type) -> None:
    a, b = id_cls.generate(), id_cls.generate()
    assert a != b
    assert str(a) != str(b)


# -- domain name / subdomain --------------------------------------------


def test_domain_name_normalizes_case_and_trailing_dot() -> None:
    domain = DomainName("Example.COM.")
    assert str(domain) == "example.com"


@pytest.mark.parametrize("bad", ["", "not a domain", "-bad.com", "a" * 300])
def test_domain_name_rejects_invalid_values(bad: str) -> None:
    with pytest.raises(InvalidDomainNameError):
        DomainName(bad)


def test_subdomain_must_belong_to_parent_domain() -> None:
    parent = DomainName("example.com")
    sub = Subdomain("app.example.com", parent)
    assert str(sub) == "app.example.com"


def test_subdomain_rejects_fqdn_outside_parent() -> None:
    parent = DomainName("example.com")
    with pytest.raises(InvalidSubdomainError):
        Subdomain("app.other.com", parent)


# -- ip address / cidr --------------------------------------------------


def test_ip_address_parses_and_normalizes() -> None:
    ip = IPAddress("10.0.0.1")
    assert str(ip) == "10.0.0.1"
    assert ip.is_private is True
    assert ip.version == 4


def test_ip_address_rejects_invalid_value() -> None:
    with pytest.raises(InvalidIpAddressError):
        IPAddress("not-an-ip")


def test_cidr_block_parses_and_contains() -> None:
    cidr = CidrBlock("10.0.0.0/24")
    assert cidr.num_addresses == 256
    assert cidr.contains("10.0.0.5")
    assert not cidr.contains("10.0.1.5")


def test_cidr_block_rejects_invalid_value() -> None:
    with pytest.raises(InvalidCidrBlockError):
        CidrBlock("not-a-cidr")


# -- technology fingerprint / service banner -----------------------------


def test_technology_fingerprint_valid() -> None:
    fp = TechnologyFingerprint(name="nginx", version="1.24.0", confidence=0.9)
    assert str(fp) == "nginx 1.24.0"


def test_technology_fingerprint_rejects_bad_confidence() -> None:
    with pytest.raises(InvalidTechnologyFingerprintError):
        TechnologyFingerprint(name="nginx", version=None, confidence=1.5)


def test_technology_fingerprint_rejects_empty_name() -> None:
    with pytest.raises(InvalidTechnologyFingerprintError):
        TechnologyFingerprint(name="  ", version=None, confidence=0.5)


def test_service_banner_flags_high_risk_service() -> None:
    telnet = ServiceBanner(name="Telnet")
    assert telnet.name == "telnet"
    assert telnet.is_high_risk_service is True

    https = ServiceBanner(name="https")
    assert https.is_high_risk_service is False


# -- asset ownership / criticality score ---------------------------------


def test_asset_ownership_requires_owning_team() -> None:
    with pytest.raises(InvalidAssetOwnershipError):
        AssetOwnership(owning_team="  ")


def test_criticality_score_bounds() -> None:
    CriticalityScore(0)
    CriticalityScore(100)
    with pytest.raises(InvalidCriticalityScoreError):
        CriticalityScore(101)
    with pytest.raises(InvalidCriticalityScoreError):
        CriticalityScore(-1)
