from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from exposure.application.commands.exposure_commands import IngestVulnerabilitySignalCommand
from exposure.domain.ports.i_threat_intelligence_query_port import (
    ConfidenceLevel,
    ThreatActorMatch,
)
from exposure.domain.value_objects.identifiers import TenantId
from exposure.infrastructure.acl.threat_intelligence_m21_adapter import (
    ThreatIntelligenceM21Adapter,
)
from exposure.infrastructure.container import ExposureContainer
from exposure.infrastructure.persistence.in_memory_unit_of_work import InMemoryUnitOfWork
from exposure.infrastructure.projections.threat_actor_match_cache import (
    ThreatActorMatchCache,
)
from redforge.shared.identifiers import EntityId

ANALYST = ("exposure:analyst",)


@pytest.fixture
def tenant() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def container() -> ExposureContainer:
    uow = InMemoryUnitOfWork()
    threat = ThreatIntelligenceM21Adapter()
    return ExposureContainer(uow_factory=lambda: uow, threat_port=threat)


def test_cache_staleness_48h() -> None:
    cache = ThreatActorMatchCache(tenant_id=EntityId.generate())
    assert cache.is_stale()
    now = datetime.now(UTC)
    cache.apply_targeting(
        threat_actor_ref="apt-1",
        cve_ids=["CVE-2024-1"],
        asset_classes=["web"],
        at=now - timedelta(hours=47),
        from_event=True,
    )
    assert not cache.is_stale(now)
    cache.last_event_update_at = now - timedelta(hours=49)
    assert cache.is_stale(now)


@pytest.mark.asyncio
async def test_event_path_attaches_threat_amplifier(
    tenant: TenantId, container: ExposureContainer
) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant,
            event_id="vuln-1",
            vulnerability_instance_id="vi-1",
            asset_ref_id=asset,
            cvss_base=5.0,
            is_kev=True,
            technique_refs=("T1059",),
            cve_ids=("CVE-2024-1",),
            asset_classes=("web",),
            actor_roles=ANALYST,
        )
    )
    attached = await container.threat_subscriber.on_threat_actor_asset_class_targeting_updated(
        tenant_id=tenant,
        event_id="m21-evt-1",
        threat_actor_ref="apt-42",
        targeted_cve_ids=["CVE-2024-1"],
        targeted_asset_classes=[],
        targeting_confidence="High",
    )
    assert attached == 1
    cache = await container.threat_query.get_threat_actor_targeting(tenant, ANALYST)
    assert "CVE-2024-1" in cache["entries"]
    assert cache["is_stale"] is False


@pytest.mark.asyncio
async def test_poll_path_and_unavailability(tenant: TenantId, container: ExposureContainer) -> None:
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant,
            event_id="vuln-2",
            vulnerability_instance_id="vi-2",
            asset_ref_id=asset,
            cvss_base=6.0,
            is_kev=False,
            technique_refs=(),
            cve_ids=("CVE-2024-9",),
            asset_classes=("db",),
            actor_roles=ANALYST,
        )
    )
    assert isinstance(container.threat_port, ThreatIntelligenceM21Adapter)
    container.threat_port.seed(
        ThreatActorMatch(
            threat_actor_ref="apt-9",
            matched_cve_ids=("CVE-2024-9",),
            matched_asset_classes=("db",),
            matched_techniques=("T1190",),
            matched_iocs=("1.2.3.4",),
            confidence=ConfidenceLevel.HIGH,
        )
    )
    ok = await container.threat_poll_scheduler.run_for_tenant(tenant)
    assert ok["ok"] is True
    assert int(ok["attached"]) >= 1

    container.threat_port.mark_unavailable()
    fail = await container.threat_sync.poll_and_refresh(tenant)
    assert fail["ok"] is False
    # Existing amplifiers retained — cache still has entries
    cache = await container.cache_repo.load(tenant)
    assert "CVE-2024-9" in cache.entries


@pytest.mark.asyncio
async def test_cold_bootstrap(tenant: TenantId, container: ExposureContainer) -> None:
    assert isinstance(container.threat_port, ThreatIntelligenceM21Adapter)
    container.threat_port.seed(
        ThreatActorMatch(
            threat_actor_ref="apt-cold",
            matched_cve_ids=("CVE-COLD",),
            matched_asset_classes=(),
        )
    )
    result = await container.threat_sync.bootstrap_if_cold(tenant)
    assert result["ok"] is True
