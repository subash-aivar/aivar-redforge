from __future__ import annotations

import random
from datetime import UTC, datetime

from ioc_intelligence.domain.aggregates.ioc import IOC
from ioc_intelligence.domain.value_objects.enums import IocType, SourceConfidence
from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
from ioc_intelligence.domain.value_objects.identifiers import IocId, TenantId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution
from ioc_intelligence.domain.value_objects.validity import ValidityWindow
from redforge.shared.ioc_vocabulary import ProviderName


def make_tenant_id() -> TenantId:
    return TenantId.generate()


def random_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def make_attribution(
    source_system: str = ProviderName.ALIENVAULT_OTX.value, external_id: str | None = None
) -> SourceAttribution:
    return SourceAttribution(
        source_system=source_system,
        external_id=external_id or f"pulse-{random.randint(1, 10**9)}",
        content_hash="deadbeef",
        observed_at=datetime(2026, 8, 5, tzinfo=UTC),
        weight_applied=0.75,
        confidence=SourceConfidence.HIGH,
    )


def make_ioc(
    *,
    tenant_id: TenantId | None = None,
    raw_value: str | None = None,
    ioc_type: IocType = IocType.IP,
    source_attributions: tuple[SourceAttribution, ...] | None = None,
    evidence_citations: tuple[EvidenceCitation, ...] = (),
    valid_until: datetime | None = None,
    now: datetime | None = None,
) -> IOC:
    now = now or datetime(2026, 8, 5, tzinfo=UTC)
    canonical_key = IndicatorCanonicalKey.for_type(ioc_type, raw_value or random_ip())
    attributions = source_attributions if source_attributions is not None else (make_attribution(),)
    if tenant_id is None:
        return IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=canonical_key,
            validity_window=ValidityWindow(valid_from=now, valid_until=valid_until),
            now=now,
            source_attributions=attributions,
            evidence_citations=evidence_citations,
        )
    return IOC.observe_tenant(
        ioc_id=IocId.generate(),
        tenant_id=tenant_id,
        canonical_key=canonical_key,
        validity_window=ValidityWindow(valid_from=now, valid_until=valid_until),
        now=now,
        source_attributions=attributions,
        evidence_citations=evidence_citations,
    )
