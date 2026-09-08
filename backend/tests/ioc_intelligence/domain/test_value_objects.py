from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    InvalidIndicatorValueError,
)
from ioc_intelligence.domain.value_objects.enums import IocType, SourceConfidence
from ioc_intelligence.domain.value_objects.indicator_value import (
    IndicatorCanonicalKey,
    normalize_indicator_value,
)
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution


def _now() -> datetime:
    return datetime(2026, 8, 4, tzinfo=UTC)


class TestNormalization:
    def test_equivalent_ip_values_normalize_to_same_canonical_key(self) -> None:
        a = IndicatorCanonicalKey.for_type(IocType.IP, "  1.2.3.4  ")
        b = IndicatorCanonicalKey.for_type(IocType.IP, "1.2.3.4")
        assert a == b

    def test_equivalent_domain_values_normalize_to_same_canonical_key(self) -> None:
        a = IndicatorCanonicalKey.for_type(IocType.DOMAIN, "Example.COM.")
        b = IndicatorCanonicalKey.for_type(IocType.DOMAIN, "example.com")
        assert a == b

    def test_equivalent_url_values_normalize_to_same_canonical_key(self) -> None:
        a = IndicatorCanonicalKey.for_type(IocType.URL, "HTTP://Example.com/path")
        b = IndicatorCanonicalKey.for_type(IocType.URL, "http://example.com/path")
        assert a == b

    def test_equivalent_hash_values_normalize_to_same_canonical_key(self) -> None:
        digest = "a" * 64
        a = IndicatorCanonicalKey.for_type(IocType.HASH, digest.upper())
        b = IndicatorCanonicalKey.for_type(IocType.HASH, digest)
        assert a == b

    def test_distinct_indicator_types_do_not_collide(self) -> None:
        ip_key = IndicatorCanonicalKey.for_type(IocType.IP, "1.2.3.4")
        domain_key = IndicatorCanonicalKey.for_type(IocType.DOMAIN, "1.2.3.4.example.com")
        assert ip_key != domain_key
        assert ip_key.ioc_type is IocType.IP
        assert domain_key.ioc_type is IocType.DOMAIN

    def test_invalid_ip_value_rejected(self) -> None:
        with pytest.raises(InvalidIndicatorValueError):
            normalize_indicator_value(IocType.IP, "not-an-ip")

    def test_invalid_domain_value_rejected(self) -> None:
        with pytest.raises(InvalidIndicatorValueError):
            normalize_indicator_value(IocType.DOMAIN, "not a domain")

    def test_invalid_url_value_rejected(self) -> None:
        with pytest.raises(InvalidIndicatorValueError):
            normalize_indicator_value(IocType.URL, "not-a-url")

    def test_invalid_hash_value_rejected(self) -> None:
        with pytest.raises(InvalidIndicatorValueError):
            normalize_indicator_value(IocType.HASH, "zzzz")

    def test_empty_value_rejected(self) -> None:
        with pytest.raises(InvalidIndicatorValueError):
            normalize_indicator_value(IocType.IP, "   ")


class TestSourceAttribution:
    def test_valid_attribution_preserves_provenance_fields(self) -> None:
        attribution = SourceAttribution(
            source_system="alienvault_otx",
            external_id="pulse-123",
            content_hash="deadbeef",
            observed_at=_now(),
            weight_applied=0.8,
            confidence=SourceConfidence.HIGH,
        )
        assert attribution.source_system == "alienvault_otx"
        assert attribution.external_id == "pulse-123"
        assert attribution.content_hash == "deadbeef"
        assert attribution.observed_at == _now()
        assert attribution.weight_applied == 0.8
        assert attribution.confidence is SourceConfidence.HIGH
        assert attribution.dedup_key == ("alienvault_otx", "pulse-123")

    def test_empty_source_system_rejected(self) -> None:
        with pytest.raises(EmptyIdentifierError):
            SourceAttribution(
                source_system="  ",
                external_id="x",
                content_hash=None,
                observed_at=_now(),
                weight_applied=0.5,
                confidence=SourceConfidence.LOW,
            )

    def test_weight_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="weight_applied"):
            SourceAttribution(
                source_system="abusech",
                external_id="x",
                content_hash=None,
                observed_at=_now(),
                weight_applied=1.5,
                confidence=SourceConfidence.LOW,
            )
