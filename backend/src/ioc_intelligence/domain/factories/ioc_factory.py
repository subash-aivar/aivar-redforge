"""IocFactory — the single supported construction path for raw
indicator values into `IOC` aggregates (M51.2 Phase A).

Splits "who may construct" (this factory: normalizes the raw value,
builds the canonical key, applies TTL policy, delegates to `IOC.observe`
/ `IOC.observe_tenant`) from "what must be true" (enforced inside the
`IOC` aggregate itself — provenance, tenancy). Mirrors
`ThreatActorFactory`'s already-certified split.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.domain.aggregates.ioc import IOC
from ioc_intelligence.domain.policies.ttl_policy import IocTTLPolicy
from ioc_intelligence.domain.value_objects.identifiers import IocId
from ioc_intelligence.domain.value_objects.indicator_value import IndicatorCanonicalKey
from ioc_intelligence.domain.value_objects.validity import ValidityWindow

if TYPE_CHECKING:
    from datetime import datetime

    from ioc_intelligence.domain.value_objects.enums import IocType
    from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
    from ioc_intelligence.domain.value_objects.identifiers import TenantId
    from ioc_intelligence.domain.value_objects.provenance import SourceAttribution


class IocFactory:
    def __init__(self, ttl_policy: IocTTLPolicy | None = None) -> None:
        self._ttl_policy = ttl_policy or IocTTLPolicy()

    def observe_global(
        self,
        ioc_type: IocType,
        raw_value: str,
        now: datetime,
        source_attributions: tuple[SourceAttribution, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
    ) -> IOC:
        """Global IOC intelligence from an approved shared source."""
        canonical_key = IndicatorCanonicalKey.for_type(ioc_type, raw_value)
        validity_window = self._build_validity_window(ioc_type, now)
        return IOC.observe(
            ioc_id=IocId.generate(),
            tenant_id=None,
            canonical_key=canonical_key,
            validity_window=validity_window,
            now=now,
            source_attributions=source_attributions,
            evidence_citations=evidence_citations,
        )

    def observe_tenant(
        self,
        tenant_id: TenantId,
        ioc_type: IocType,
        raw_value: str,
        now: datetime,
        source_attributions: tuple[SourceAttribution, ...] = (),
        evidence_citations: tuple[EvidenceCitation, ...] = (),
    ) -> IOC:
        """Tenant-scoped observation backed by that tenant's own evidence."""
        canonical_key = IndicatorCanonicalKey.for_type(ioc_type, raw_value)
        validity_window = self._build_validity_window(ioc_type, now)
        return IOC.observe_tenant(
            ioc_id=IocId.generate(),
            tenant_id=tenant_id,
            canonical_key=canonical_key,
            validity_window=validity_window,
            now=now,
            source_attributions=source_attributions,
            evidence_citations=evidence_citations,
        )

    def _build_validity_window(self, ioc_type: IocType, now: datetime) -> ValidityWindow:
        valid_until = self._ttl_policy.valid_until(ioc_type, valid_from=now)
        return ValidityWindow(valid_from=now, valid_until=valid_until)
