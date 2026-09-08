from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from infrastructure_intel.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidNormalizedIdentifierError,
)
from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureConfidence,
    InfrastructureLifecycleStatus,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.evidence import (
    EvidenceCitation,
    SourceAttribution,
)
from infrastructure_intel.domain.value_objects.hosting import (
    CloudProviderRef,
    HostingProviderRef,
    NetworkOwnership,
    Region,
)
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId
from infrastructure_intel.domain.value_objects.normalized_identifier import (
    normalize_identifier,
)
from infrastructure_intel.domain.value_objects.version_record import VersionRecord

NOW = datetime(2026, 8, 6, tzinfo=UTC)
T = InfrastructureType


# ── Per-type identifier normalization ────────────────────────────────────


@pytest.mark.parametrize("raw", ["AS15169", "as15169", "  as 15169 ", "15169", "As-15169"])
def test_asn_collapses_to_canonical_form(raw: str) -> None:
    assert normalize_identifier(T.ASN, raw) == "AS15169"


def test_asn_strips_leading_zeroes_to_one_identity() -> None:
    assert normalize_identifier(T.ASN, "AS0015169") == "AS15169"


@pytest.mark.parametrize("raw", ["", "   ", "ASN", "AS", "notanumber", "AS12x", "AS-"])
def test_asn_rejects_non_numeric_forms(raw: str) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        normalize_identifier(T.ASN, raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("192.168.0.1", "192.168.0.1"),
        ("  8.8.8.8 ", "8.8.8.8"),
        ("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:db8::1", "2001:db8::1"),
    ],
)
def test_ip_address_canonicalizes_v4_and_v6(raw: str, expected: str) -> None:
    assert normalize_identifier(T.IP_ADDRESS, raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "999.1.1.1", "not-an-ip", "192.168.0.1/24"])
def test_ip_address_rejects_invalid_forms(raw: str) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        normalize_identifier(T.IP_ADDRESS, raw)


@pytest.mark.parametrize("raw", ["EVIL.Example.COM", "  evil.example.com  ", "Evil.Example.Com"])
def test_domain_lowercases_and_trims(raw: str) -> None:
    assert normalize_identifier(T.DOMAIN, raw) == "evil.example.com"


def test_url_lowercases_and_trims() -> None:
    assert (
        normalize_identifier(T.URL, "  HTTPS://Evil.Example.com/Path ")
        == "https://evil.example.com/path"
    )


@pytest.mark.parametrize("infrastructure_type", [T.DOMAIN, T.URL])
@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_domain_and_url_reject_empty_forms(
    infrastructure_type: InfrastructureType, raw: str
) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        normalize_identifier(infrastructure_type, raw)


@pytest.mark.parametrize(
    "raw", ["Bullet-Proof Hosting", "  bullet_proof_hosting ", "BULLET   PROOF  HOSTING"]
)
def test_provider_names_collapse_to_one_identity(raw: str) -> None:
    assert normalize_identifier(T.HOSTING_PROVIDER, raw) == "bullet proof hosting"


@pytest.mark.parametrize("infrastructure_type", [T.HOSTING_PROVIDER, T.CLOUD_PROVIDER])
@pytest.mark.parametrize("raw", ["", "   ", "---", "___"])
def test_provider_names_reject_empty_forms(
    infrastructure_type: InfrastructureType, raw: str
) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        normalize_identifier(infrastructure_type, raw)


def test_normalization_applies_nfkc() -> None:
    fullwidth = "ＥＶＩＬ.example.com"  # noqa: RUF001 — fullwidth input is the point
    assert normalize_identifier(T.DOMAIN, fullwidth) == "evil.example.com"


def test_normalization_rejects_non_string() -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        normalize_identifier(T.DOMAIN, None)  # type: ignore[arg-type]


def test_the_same_string_under_two_types_is_two_identities() -> None:
    """A hosting provider literally named "evil.example.com" and the
    domain itself are legitimately distinct records — the TYPE is part
    of the identity."""
    assert normalize_identifier(T.DOMAIN, "Evil.Example.com") == "evil.example.com"
    assert normalize_identifier(T.HOSTING_PROVIDER, "Evil.Example.com") == "evil.example.com"


# ── Identifiers ──────────────────────────────────────────────────────────


def test_infrastructure_id_rejects_nil_uuid() -> None:
    with pytest.raises(ValueError, match="nil UUID"):
        InfrastructureId(UUID(int=0))


def test_infrastructure_id_generate_is_unique_and_stringifies() -> None:
    a, b = InfrastructureId.generate(), InfrastructureId.generate()
    assert a != b
    assert str(a) == str(a.value)


# ── Hosting value objects ────────────────────────────────────────────────


def test_hosting_provider_ref_requires_non_empty_name() -> None:
    with pytest.raises(EmptyIdentifierError):
        HostingProviderRef(provider_name="  ")
    assert str(HostingProviderRef(provider_name="OVH")) == "OVH"


def test_cloud_provider_ref_carries_a_closed_enum() -> None:
    ref = CloudProviderRef(provider=CloudProvider.AWS)
    assert ref.provider is CloudProvider.AWS
    assert str(ref) == "aws"


def test_region_requires_non_empty_code() -> None:
    with pytest.raises(EmptyIdentifierError):
        Region(region_code=" ")
    assert str(Region(region_code="us-east-1")) == "us-east-1"


def test_region_is_free_text_not_a_closed_enum() -> None:
    """Geography does not close — an ISO-ish code and a loose regional
    label are both legitimate."""
    assert Region(region_code="EMEA").region_code == "EMEA"
    assert Region(region_code="ap-southeast-2").region_code == "ap-southeast-2"


def test_network_ownership_requires_a_registrant_organization() -> None:
    with pytest.raises(EmptyIdentifierError):
        NetworkOwnership(registrant_organization="   ")
    ownership = NetworkOwnership(registrant_organization="Shady Hosting BV")
    assert ownership.abuse_contact == ""
    assert ownership.notes == ""
    assert str(ownership) == "Shady Hosting BV"


# ── Evidence ─────────────────────────────────────────────────────────────


def test_evidence_citation_requires_non_empty_value() -> None:
    with pytest.raises(EmptyIdentifierError):
        EvidenceCitation("")
    assert str(EvidenceCitation("https://vendor/report")) == "https://vendor/report"


def test_source_attribution_requires_source_system_and_reference() -> None:
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system=" ", reference="r", observed_at=NOW)
    with pytest.raises(EmptyIdentifierError):
        SourceAttribution(source_system="s", reference="  ", observed_at=NOW)


def test_source_attribution_defaults_to_medium_confidence() -> None:
    attribution = SourceAttribution(source_system="s", reference="r", observed_at=NOW)
    assert attribution.confidence is InfrastructureConfidence.MEDIUM
    assert attribution.notes == ""


def test_version_record_validates_its_fields() -> None:
    with pytest.raises(ValueError, match="version must be >= 1"):
        VersionRecord(version=0, changed_at=NOW, change_summary="s", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary=" ", source="src")
    with pytest.raises(EmptyIdentifierError):
        VersionRecord(version=1, changed_at=NOW, change_summary="s", source=" ")


def test_value_objects_are_frozen() -> None:
    region = Region(region_code="us-east-1")
    with pytest.raises(AttributeError):
        region.region_code = "eu-west-1"  # type: ignore[misc]


# ── Enum vocabularies ────────────────────────────────────────────────────


def test_enum_vocabularies_are_closed_and_complete() -> None:
    assert len(InfrastructureLifecycleStatus) == 4
    assert len(InfrastructureType) == 6
    assert len(CloudProvider) == 7
    assert len(InfrastructureConfidence) == 4


def test_enums_reject_unknown_values() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        InfrastructureType("nonexistent_type")
    with pytest.raises(ValueError, match="not a valid"):
        CloudProvider("oracle_cloud")
