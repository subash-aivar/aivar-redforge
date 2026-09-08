"""Focused tests for M51.2 Phase A.1 R1/R2 (provider vocabulary
reconciliation + shared IOC type)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    DuplicateSourceAttributionError,
    UnrecognizedSourceSystemError,
)
from ioc_intelligence.domain.value_objects.enums import IocType, SourceConfidence
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
from redforge.domain.threat_intel.value_objects import IndicatorType, ProviderName
from redforge.shared.ioc_vocabulary import IOC_INTERNAL_SOURCE_SYSTEM


def _now() -> datetime:
    return datetime(2026, 8, 4, tzinfo=UTC)


def _attribution(source_system: str, external_id: str = "x") -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        external_id=external_id,
        content_hash=None,
        observed_at=_now(),
        weight_applied=0.5,
        confidence=SourceConfidence.MEDIUM,
    )


class TestSharedIocType:
    def test_ioc_and_legacy_threat_intel_use_the_exact_same_type_object(self) -> None:
        assert IocType is IndicatorType

    def test_all_four_serialized_values_unchanged(self) -> None:
        assert {member.value for member in IocType} == {"ip", "domain", "url", "hash"}
        assert IocType.IP.value == "ip"
        assert IocType.DOMAIN.value == "domain"
        assert IocType.URL.value == "url"
        assert IocType.HASH.value == "hash"

    def test_unknown_ioc_type_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a valid IndicatorType"):
            IocType("mutex")

    def test_canonical_key_still_builds_with_shared_type(self) -> None:
        key = IndicatorCanonicalKey.for_type(IocType.IP, "1.2.3.4")
        assert key.value == "ip:1.2.3.4"
        assert key.ioc_type is IocType.IP


class TestProviderVocabularyReconciliation:
    @pytest.mark.parametrize("provider", list(ProviderName))
    def test_source_attribution_accepts_every_approved_provider_name(
        self, provider: ProviderName
    ) -> None:
        attribution = _attribution(provider.value)
        assert attribution.source_system == provider.value

    def test_unknown_provider_string_is_rejected(self) -> None:
        with pytest.raises(UnrecognizedSourceSystemError):
            _attribution("totally_made_up_provider")

    def test_internal_redforge_evidence_provenance_is_supported(self) -> None:
        attribution = _attribution(IOC_INTERNAL_SOURCE_SYSTEM, external_id="analyst-finding-1")
        assert attribution.source_system == IOC_INTERNAL_SOURCE_SYSTEM
        assert attribution.external_id == "analyst-finding-1"

    def test_internal_source_is_not_a_member_of_provider_name(self) -> None:
        """Internal provenance must not weaken ProviderName's closed,
        egress-governing vocabulary."""
        assert IOC_INTERNAL_SOURCE_SYSTEM not in {p.value for p in ProviderName}

    def test_duplicate_attribution_detection_remains_deterministic(self) -> None:
        from ioc_intelligence.domain.aggregates.ioc import IOC
        from ioc_intelligence.domain.value_objects.identifiers import IocId
        from ioc_intelligence.domain.value_objects.validity import ValidityWindow

        canonical_key = IndicatorCanonicalKey.for_type(IocType.IP, "9.9.9.9")
        validity_window = ValidityWindow(valid_from=_now(), valid_until=None)
        ioc = IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=canonical_key,
            validity_window=validity_window,
            now=_now(),
            source_attributions=(_attribution(ProviderName.ABUSECH.value, "feed-1"),),
        )
        ioc.pop_events()
        with pytest.raises(DuplicateSourceAttributionError):
            ioc.add_source_attribution(
                None, _attribution(ProviderName.ABUSECH.value, "feed-1"), _now()
            )

    def test_preserves_external_id_confidence_weight_and_observed_at(self) -> None:
        observed = _now()
        attribution = SourceAttribution(
            source_system=ProviderName.RDAP.value,
            external_id="rdap-lookup-42",
            content_hash="cafebabe",
            observed_at=observed,
            weight_applied=0.65,
            confidence=SourceConfidence.HIGH,
        )
        assert attribution.external_id == "rdap-lookup-42"
        assert attribution.confidence is SourceConfidence.HIGH
        assert attribution.weight_applied == 0.65
        assert attribution.observed_at == observed
