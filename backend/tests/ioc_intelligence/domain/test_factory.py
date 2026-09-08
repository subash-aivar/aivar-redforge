from __future__ import annotations

from datetime import UTC, datetime

from ioc_intelligence.domain.factories.ioc_factory import IocFactory
from ioc_intelligence.domain.value_objects.enums import IocType, SourceConfidence
from ioc_intelligence.domain.value_objects.evidence import EvidenceCitation
from ioc_intelligence.domain.value_objects.identifiers import TenantId
from ioc_intelligence.domain.value_objects.provenance import SourceAttribution


def _now() -> datetime:
    return datetime(2026, 8, 4, tzinfo=UTC)


def _attribution() -> SourceAttribution:
    return SourceAttribution(
        source_system="abusech",
        external_id="feed-9",
        content_hash=None,
        observed_at=_now(),
        weight_applied=0.7,
        confidence=SourceConfidence.MEDIUM,
    )


class TestIocFactory:
    def test_observe_global_builds_canonical_key_and_ttl(self) -> None:
        factory = IocFactory()
        ioc = factory.observe_global(
            IocType.DOMAIN, "Example.com", _now(), source_attributions=(_attribution(),)
        )
        assert ioc.tenant_id is None
        assert ioc.canonical_key.value == "domain:example.com"
        assert ioc.validity_window.valid_until is not None

    def test_observe_tenant_builds_tenant_scoped_ioc(self) -> None:
        factory = IocFactory()
        tenant_id = TenantId.generate()
        ioc = factory.observe_tenant(
            tenant_id,
            IocType.HASH,
            "a" * 64,
            _now(),
            evidence_citations=(EvidenceCitation("internal-1"),),
        )
        assert ioc.tenant_id == tenant_id
        assert ioc.canonical_key.value == f"hash:{'a' * 64}"
