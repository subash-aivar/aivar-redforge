"""Real-PostgreSQL integration tests for the M51.2 Phase A5 legacy ACL
adapters and the full ingestion orchestrator path against real
`threat_intel_indicators`/`threat_intel_enrichments` rows."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from ioc_intelligence.application.services.ioc_ingestion_orchestrator import (
    IocIngestionOrchestrator,
)
from ioc_intelligence.infrastructure.acl.ioc_correlation_query_adapter import (
    SqlAlchemyIocCorrelationQueryAdapter,
)
from ioc_intelligence.infrastructure.acl.ioc_enrichment_query_adapter import (
    SqlAlchemyIocEnrichmentQueryAdapter,
)
from ioc_intelligence.infrastructure.acl.legacy_ioc_observation_adapter import (
    SqlAlchemyLegacyIocObservationAdapter,
)
from ioc_intelligence.infrastructure.container import IocIntelContainer
from ioc_intelligence.infrastructure.persistence.repositories.pg_ioc_repository import (
    PgIocRepository,
)
from redforge.infrastructure.database.models.threat_intel import (
    ThreatIntelEnrichmentModel,
    ThreatIntelIndicatorModel,
)
from redforge.shared.ioc_vocabulary import IOC_INTERNAL_SOURCE_SYSTEM, ProviderName
from tests.ioc_intelligence.infrastructure.helpers import make_tenant_id

pytestmark = pytest.mark.integration


def _org_id(tenant_id) -> str:
    return str(tenant_id)


async def _insert_legacy_indicator(
    session, organization_id: str, indicator_type: str, indicator: str, *, now: datetime
) -> str:
    row_id = str(uuid.uuid4())[:26]
    session.add(
        ThreatIntelIndicatorModel(
            id=row_id,
            organization_id=organization_id,
            indicator=indicator,
            indicator_type=indicator_type,
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    await session.flush()
    return row_id


async def _insert_enrichment(
    session,
    organization_id: str,
    indicator_id: str,
    provider_name: str,
    kind: str,
    data: dict,
    *,
    now: datetime,
    success: bool = True,
    expires_at: datetime | None = None,
) -> None:
    session.add(
        ThreatIntelEnrichmentModel(
            id=str(uuid.uuid4())[:26],
            organization_id=organization_id,
            indicator_id=indicator_id,
            provider_name=provider_name,
            kind=kind,
            success=success,
            error_category=None,
            data=data,
            detail="",
            fetched_at=now,
            expires_at=expires_at or (now + timedelta(hours=6)),
        )
    )
    await session.flush()


@pytest.mark.asyncio
class TestLegacyObservationAdapter:
    async def test_reads_tenant_scoped_legacy_row(self, ioc_session) -> None:
        tenant_id = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)
        legacy_id = await _insert_legacy_indicator(
            ioc_session, _org_id(tenant_id), "ip", "3.3.3.3", now=now
        )
        await ioc_session.commit()

        adapter = SqlAlchemyLegacyIocObservationAdapter(ioc_session)
        rows = await adapter.list_recent_observations(_org_id(tenant_id), limit=10, offset=0)
        assert len(rows) == 1
        assert rows[0].legacy_indicator_id == legacy_id
        assert rows[0].ioc_type == "ip"
        assert rows[0].normalized_value == "3.3.3.3"

    async def test_does_not_read_other_tenants_rows(self, ioc_session) -> None:
        tenant_a = make_tenant_id()
        tenant_b = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)
        await _insert_legacy_indicator(ioc_session, _org_id(tenant_a), "ip", "3.3.3.4", now=now)
        await ioc_session.commit()

        adapter = SqlAlchemyLegacyIocObservationAdapter(ioc_session)
        rows = await adapter.list_recent_observations(_org_id(tenant_b), limit=10, offset=0)
        assert rows == []


@pytest.mark.asyncio
class TestFullIngestionAgainstRealLegacyTables:
    async def test_legacy_row_ingests_into_exactly_one_ioc(self, ioc_session_factory) -> None:
        tenant_id = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)

        setup_session = ioc_session_factory()
        try:
            await _insert_legacy_indicator(
                setup_session, _org_id(tenant_id), "ip", "4.4.4.4", now=now
            )
            await setup_session.commit()
        finally:
            await setup_session.close()

        container = IocIntelContainer(ioc_session_factory)
        session = container.new_session()
        try:
            orchestrator = container.build_ingestion_orchestrator(session)
            result = await orchestrator.ingest_tenant(tenant_id)
            assert result.iocs_touched == 1
            assert result.errors == []
        finally:
            await session.close()

        verify_session = ioc_session_factory()
        try:
            iocs = (await PgIocRepository(verify_session).list_and_count(tenant_id))[0]
            assert len(iocs) == 1
            assert iocs[0].canonical_key.normalized_value == "4.4.4.4"
            internal = [
                a
                for a in iocs[0].source_attributions
                if a.source_system == IOC_INTERNAL_SOURCE_SYSTEM
            ]
            assert len(internal) == 1
        finally:
            await verify_session.close()

    async def test_rerunning_ingestion_is_idempotent(self, ioc_session_factory) -> None:
        tenant_id = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)

        setup_session = ioc_session_factory()
        try:
            await _insert_legacy_indicator(
                setup_session, _org_id(tenant_id), "ip", "4.4.4.5", now=now
            )
            await setup_session.commit()
        finally:
            await setup_session.close()

        container = IocIntelContainer(ioc_session_factory)

        for _ in range(2):
            session = container.new_session()
            try:
                await container.build_ingestion_orchestrator(session).ingest_tenant(tenant_id)
            finally:
                await session.close()

        verify_session = ioc_session_factory()
        try:
            iocs = (await PgIocRepository(verify_session).list_and_count(tenant_id))[0]
            assert len(iocs) == 1
            assert len(iocs[0].source_attributions) == 1
        finally:
            await verify_session.close()

    async def test_enrichment_and_correlation_add_provenance_without_duplication(
        self, ioc_session_factory
    ) -> None:
        tenant_id = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)

        setup_session = ioc_session_factory()
        try:
            legacy_id = await _insert_legacy_indicator(
                setup_session, _org_id(tenant_id), "ip", "4.4.4.6", now=now
            )
            await _insert_enrichment(
                setup_session,
                _org_id(tenant_id),
                legacy_id,
                ProviderName.ABUSEIPDB.value,
                "reputation",
                {
                    "provider": ProviderName.ABUSEIPDB.value,
                    "indicator": "4.4.4.6",
                    "indicator_type": "ip",
                    "confidence_score": 90.0,
                    "confidence_semantics": "abuseConfidenceScore",
                    "categories": [],
                    "report_count": 5,
                    "distinct_reporter_count": 3,
                    "last_reported_at": None,
                    "provider_reference_id": "abuseipdb-1",
                    "fetched_at": now.isoformat(),
                    "raw_provider_url": "",
                },
                now=now,
                expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
            await _insert_enrichment(
                setup_session,
                _org_id(tenant_id),
                legacy_id,
                ProviderName.ALIENVAULT_OTX.value,
                "ioc_match",
                {
                    "provider": ProviderName.ALIENVAULT_OTX.value,
                    "indicator": "4.4.4.6",
                    "indicator_type": "ip",
                    "threat_type": "botnet",
                    "malware_family": None,
                    "tags": [],
                    "provider_first_seen": None,
                    "provider_last_seen": None,
                    "provider_reference_id": "otx-pulse-1",
                    "fetched_at": now.isoformat(),
                },
                now=now,
                expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            )
            await setup_session.commit()
        finally:
            await setup_session.close()

        container = IocIntelContainer(ioc_session_factory)
        for _ in range(2):  # idempotence across two runs, in the same test
            session = container.new_session()
            try:
                await container.build_ingestion_orchestrator(session).ingest_tenant(tenant_id)
            finally:
                await session.close()

        verify_session = ioc_session_factory()
        try:
            iocs = (await PgIocRepository(verify_session).list_and_count(tenant_id))[0]
            assert len(iocs) == 1
            attributions = iocs[0].source_attributions
            assert len(attributions) == 3  # internal + reputation + correlation, never duplicated
            reputation = next(
                a for a in attributions if a.source_system == ProviderName.ABUSEIPDB.value
            )
            assert reputation.external_id == "abuseipdb-1"
            assert reputation.confidence.value == "very_high"
            correlation = next(
                a for a in attributions if a.source_system == ProviderName.ALIENVAULT_OTX.value
            )
            assert correlation.external_id == "otx-pulse-1"
            assert iocs[0].epistemic_state.value == "observation"  # never auto-advanced
        finally:
            await verify_session.close()

    async def test_cross_tenant_isolation_during_ingestion(self, ioc_session_factory) -> None:
        tenant_a = make_tenant_id()
        tenant_b = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)

        setup_session = ioc_session_factory()
        try:
            await _insert_legacy_indicator(
                setup_session, _org_id(tenant_a), "ip", "4.4.4.7", now=now
            )
            await setup_session.commit()
        finally:
            await setup_session.close()

        container = IocIntelContainer(ioc_session_factory)
        session = container.new_session()
        try:
            await container.build_ingestion_orchestrator(session).ingest_tenant(tenant_b)
        finally:
            await session.close()

        verify_session = ioc_session_factory()
        try:
            assert ((await PgIocRepository(verify_session).list_and_count(tenant_b))[0]) == []
            assert (
                ((await PgIocRepository(verify_session).list_and_count(tenant_a))[0]) == []
            )  # not ingested yet
        finally:
            await verify_session.close()

    async def test_no_provider_network_call_occurs(self, ioc_session_factory, monkeypatch) -> None:
        """Both adapters and the orchestrator only ever call SQLAlchemy
        repository methods — assert no `httpx`/`aiohttp` client is even
        imported/constructed by patching the one HTTP client class the
        legacy provider adapters use, and confirming it's never
        touched."""
        from redforge.infrastructure.threat_intel.http_client import ThreatIntelHttpClient

        called = {"count": 0}
        original_init = ThreatIntelHttpClient.__init__

        def _tracking_init(self, *args, **kwargs):
            called["count"] += 1
            return original_init(self, *args, **kwargs)

        monkeypatch.setattr(ThreatIntelHttpClient, "__init__", _tracking_init)

        tenant_id = make_tenant_id()
        now = datetime(2026, 8, 5, tzinfo=UTC)
        setup_session = ioc_session_factory()
        try:
            await _insert_legacy_indicator(
                setup_session, _org_id(tenant_id), "ip", "4.4.4.8", now=now
            )
            await setup_session.commit()
        finally:
            await setup_session.close()

        container = IocIntelContainer(ioc_session_factory)
        session = container.new_session()
        try:
            await container.build_ingestion_orchestrator(session).ingest_tenant(tenant_id)
        finally:
            await session.close()

        assert called["count"] == 0


@pytest.mark.asyncio
class TestContainerWiring:
    async def test_container_builds_real_adapters_not_stubs(self, ioc_session_factory) -> None:
        container = IocIntelContainer(ioc_session_factory)
        session = container.new_session()
        try:
            orchestrator = container.build_ingestion_orchestrator(session)
            assert isinstance(orchestrator, IocIngestionOrchestrator)
            assert isinstance(orchestrator._legacy, SqlAlchemyLegacyIocObservationAdapter)
            assert isinstance(orchestrator._enrichment, SqlAlchemyIocEnrichmentQueryAdapter)
            assert isinstance(orchestrator._correlation, SqlAlchemyIocCorrelationQueryAdapter)
        finally:
            await session.close()
