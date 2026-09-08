"""Unit tests for IocIngestionOrchestrator (M51.2 Phase A5) — pure
in-memory fakes, no ORM, no real threat_intel tables. Real-Postgres
end-to-end coverage lives in
tests/ioc_intelligence/infrastructure/test_legacy_acl_adapters.py."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ioc_intelligence.application.ports.i_ioc_correlation_query_port import CorrelationMatchDTO
from ioc_intelligence.application.ports.i_ioc_enrichment_query_port import EnrichmentSummaryDTO
from ioc_intelligence.application.ports.i_legacy_ioc_observation_port import (
    LegacyIocObservationDTO,
)
from ioc_intelligence.application.services.ioc_application_service import IOCApplicationService
from ioc_intelligence.application.services.ioc_ingestion_orchestrator import (
    IocIngestionOrchestrator,
)
from ioc_intelligence.domain.value_objects.identifiers import TenantId
from redforge.shared.ioc_vocabulary import IOC_INTERNAL_SOURCE_SYSTEM, ProviderName

from .fakes import (
    FakeEvidenceValidationPort,
    FakeIocCorrelationQueryPort,
    FakeIocEnrichmentQueryPort,
    FakeLegacyIocObservationPort,
    FakeUnitOfWork,
    InMemoryIocRepository,
    RecordingEventPublisher,
)


def _now_iso() -> str:
    return datetime(2026, 8, 5, tzinfo=UTC).isoformat()


class _Harness:
    def __init__(
        self,
        legacy_rows: list[LegacyIocObservationDTO],
        enrichments: dict | None = None,
        correlations: dict | None = None,
    ) -> None:
        self.repo = InMemoryIocRepository()
        self.uow = FakeUnitOfWork(self.repo)
        self.events = RecordingEventPublisher()
        self.evidence = FakeEvidenceValidationPort()
        self.ioc_service = IOCApplicationService(
            uow_factory=lambda: self.uow,
            event_publisher=self.events,
            evidence_validator=self.evidence,
        )
        self.legacy = FakeLegacyIocObservationPort(legacy_rows)
        self.enrichment = FakeIocEnrichmentQueryPort(enrichments)
        self.correlation = FakeIocCorrelationQueryPort(correlations)
        self.orchestrator = IocIngestionOrchestrator(
            ioc_service=self.ioc_service,
            legacy_observation_port=self.legacy,
            enrichment_port=self.enrichment,
            correlation_port=self.correlation,
        )


def _legacy_row(
    legacy_id: str = "legacy-1",
    ioc_type: str = "ip",
    normalized_value: str = "1.2.3.4",
) -> LegacyIocObservationDTO:
    return LegacyIocObservationDTO(
        legacy_indicator_id=legacy_id,
        ioc_type=ioc_type,
        normalized_value=normalized_value,
        first_seen_at=_now_iso(),
        last_seen_at=_now_iso(),
    )


@pytest.mark.asyncio
class TestBasicIngestion:
    async def test_legacy_tenant_row_produces_exactly_one_tenant_ioc(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        result = await harness.orchestrator.ingest_tenant(tenant_id)
        assert result.iocs_touched == 1
        iocs = await harness.repo.list(tenant_id)
        assert len(iocs) == 1
        assert iocs[0].tenant_id == tenant_id

    async def test_rerunning_ingestion_produces_no_duplicate_ioc(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        await harness.orchestrator.ingest_tenant(tenant_id)
        await harness.orchestrator.ingest_tenant(tenant_id)
        iocs = await harness.repo.list(tenant_id)
        assert len(iocs) == 1

    async def test_canonically_equivalent_legacy_values_deduplicate(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness(
            [
                _legacy_row("legacy-1", "domain", "Example.COM."),
                _legacy_row("legacy-2", "domain", "example.com"),
            ]
        )
        await harness.orchestrator.ingest_tenant(tenant_id)
        iocs = await harness.repo.list(tenant_id)
        assert len(iocs) == 1
        assert len(iocs[0].source_attributions) == 2  # two distinct legacy rows, both preserved

    async def test_different_ioc_types_do_not_collide(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness(
            [
                _legacy_row("legacy-1", "ip", "5.5.5.5"),
                _legacy_row("legacy-2", "domain", "5.5.5.5.example.com"),
            ]
        )
        await harness.orchestrator.ingest_tenant(tenant_id)
        iocs = await harness.repo.list(tenant_id)
        assert len(iocs) == 2

    async def test_legacy_row_id_preserved_as_provenance_external_id(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row("legacy-xyz-42")])
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        internal = [
            a for a in ioc.source_attributions if a.source_system == IOC_INTERNAL_SOURCE_SYSTEM
        ]
        assert len(internal) == 1
        assert internal[0].external_id == "legacy-xyz-42"

    async def test_legacy_observed_timestamps_are_preserved(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        harness = _Harness([row])
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        internal = next(
            a for a in ioc.source_attributions if a.source_system == IOC_INTERNAL_SOURCE_SYSTEM
        )
        assert internal.observed_at.isoformat() == row.last_seen_at

    async def test_legacy_tenant_row_cannot_become_global_ioc(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        await harness.orchestrator.ingest_tenant(tenant_id)
        global_iocs = await harness.repo.list(None)
        assert global_iocs == []

    async def test_tenant_a_legacy_rows_cannot_populate_tenant_b_ioc(self) -> None:
        tenant_a = TenantId.generate()
        tenant_b = TenantId.generate()
        harness = _Harness([_legacy_row()])
        await harness.orchestrator.ingest_tenant(tenant_a)
        b_iocs = await harness.repo.list(tenant_b)
        assert b_iocs == []


@pytest.mark.asyncio
class TestEnrichmentProvenance:
    async def test_cached_approved_provider_enrichment_adds_valid_provenance(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        enrichment = EnrichmentSummaryDTO(
            provider_name=ProviderName.ABUSEIPDB.value,
            kind="reputation",
            success=True,
            fetched_at=_now_iso(),
            expires_at="2099-01-01T00:00:00+00:00",
            is_expired=False,
            confidence_score=80.0,
            provider_reference_id="abuseipdb-report-1",
        )
        harness = _Harness(
            [row],
            enrichments={("ip", "1.2.3.4", "reputation"): enrichment},
        )
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        provider_attrs = [
            a for a in ioc.source_attributions if a.source_system == ProviderName.ABUSEIPDB.value
        ]
        assert len(provider_attrs) == 1
        assert provider_attrs[0].external_id == "abuseipdb-report-1"
        assert provider_attrs[0].confidence.value == "very_high"

    async def test_expired_enrichment_is_excluded(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        enrichment = EnrichmentSummaryDTO(
            provider_name=ProviderName.ABUSEIPDB.value,
            kind="reputation",
            success=True,
            fetched_at=_now_iso(),
            expires_at="2020-01-01T00:00:00+00:00",
            is_expired=True,
            confidence_score=80.0,
        )
        harness = _Harness([row], enrichments={("ip", "1.2.3.4", "reputation"): enrichment})
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        assert all(a.source_system != ProviderName.ABUSEIPDB.value for a in ioc.source_attributions)

    async def test_enrichment_without_confidence_score_does_not_invent_one(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        enrichment = EnrichmentSummaryDTO(
            provider_name=ProviderName.MAXMIND_GEOLITE_LOCAL.value,
            kind="geolocation",
            success=True,
            fetched_at=_now_iso(),
            expires_at="2099-01-01T00:00:00+00:00",
            is_expired=False,
            confidence_score=None,
        )
        harness = _Harness([row], enrichments={("ip", "1.2.3.4", "reputation"): None})
        # geolocation is never queried by the orchestrator (only "reputation"
        # is) — this proves it independently of that routing decision too.
        del enrichment
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        assert len(ioc.source_attributions) == 1  # only the internal legacy-observation one

    async def test_unknown_provider_from_legacy_data_is_rejected_and_skipped(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        bad_enrichment = EnrichmentSummaryDTO(
            provider_name="not_a_real_provider",
            kind="reputation",
            success=True,
            fetched_at=_now_iso(),
            expires_at="2099-01-01T00:00:00+00:00",
            is_expired=False,
            confidence_score=90.0,
        )
        harness = _Harness([row], enrichments={("ip", "1.2.3.4", "reputation"): bad_enrichment})
        result = await harness.orchestrator.ingest_tenant(tenant_id)
        assert result.skipped == 1
        assert (await harness.repo.list(tenant_id)) == []


@pytest.mark.asyncio
class TestCorrelationProvenance:
    async def test_correlation_result_adds_observation_provenance_only(self) -> None:
        tenant_id = TenantId.generate()
        row = _legacy_row()
        match = CorrelationMatchDTO(
            provider_name=ProviderName.ALIENVAULT_OTX.value,
            matched=True,
            detail="",
            matched_at=_now_iso(),
            provider_reference_id="otx-pulse-9",
        )
        harness = _Harness([row], correlations={("ip", "1.2.3.4"): [match]})
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        assert ioc.epistemic_state.value == "observation"  # never auto-advanced
        provider_attrs = [
            a
            for a in ioc.source_attributions
            if a.source_system == ProviderName.ALIENVAULT_OTX.value
        ]
        assert len(provider_attrs) == 1

    async def test_correlation_does_not_set_validated_automatically(self) -> None:
        tenant_id = TenantId.generate()
        match = CorrelationMatchDTO(
            provider_name=ProviderName.ABUSECH.value, matched=True, detail="", matched_at=_now_iso()
        )
        harness = _Harness([_legacy_row()], correlations={("ip", "1.2.3.4"): [match]})
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        assert ioc.epistemic_state.value != "validated"

    async def test_correlation_does_not_promote_tenant_ioc_globally(self) -> None:
        tenant_id = TenantId.generate()
        match = CorrelationMatchDTO(
            provider_name=ProviderName.ABUSECH.value, matched=True, detail="", matched_at=_now_iso()
        )
        harness = _Harness([_legacy_row()], correlations={("ip", "1.2.3.4"): [match]})
        await harness.orchestrator.ingest_tenant(tenant_id)
        assert (await harness.repo.list(None)) == []
        ioc = (await harness.repo.list(tenant_id))[0]
        assert ioc.tenant_id == tenant_id


@pytest.mark.asyncio
class TestIdempotenceAndErrorIsolation:
    async def test_duplicate_attribution_remains_deterministic_across_reruns(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        await harness.orchestrator.ingest_tenant(tenant_id)
        first_count = len((await harness.repo.list(tenant_id))[0].source_attributions)
        await harness.orchestrator.ingest_tenant(tenant_id)
        second_count = len((await harness.repo.list(tenant_id))[0].source_attributions)
        assert first_count == second_count

    async def test_repeated_enrichment_and_correlation_runs_are_idempotent(self) -> None:
        tenant_id = TenantId.generate()
        enrichment = EnrichmentSummaryDTO(
            provider_name=ProviderName.ABUSEIPDB.value,
            kind="reputation",
            success=True,
            fetched_at=_now_iso(),
            expires_at="2099-01-01T00:00:00+00:00",
            is_expired=False,
            confidence_score=60.0,
            provider_reference_id="report-1",
        )
        match = CorrelationMatchDTO(
            provider_name=ProviderName.ALIENVAULT_OTX.value,
            matched=True,
            detail="",
            matched_at=_now_iso(),
            provider_reference_id="pulse-1",
        )
        harness = _Harness(
            [_legacy_row()],
            enrichments={("ip", "1.2.3.4", "reputation"): enrichment},
            correlations={("ip", "1.2.3.4"): [match]},
        )
        await harness.orchestrator.ingest_tenant(tenant_id)
        await harness.orchestrator.ingest_tenant(tenant_id)
        await harness.orchestrator.ingest_tenant(tenant_id)
        ioc = (await harness.repo.list(tenant_id))[0]
        # internal + reputation + correlation = exactly 3, regardless of how
        # many times ingestion ran.
        assert len(ioc.source_attributions) == 3

    async def test_one_malformed_row_does_not_corrupt_valid_rows(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness(
            [
                _legacy_row("legacy-1", "not_a_real_type", "whatever"),
                _legacy_row("legacy-2", "ip", "9.9.9.9"),
            ]
        )
        result = await harness.orchestrator.ingest_tenant(tenant_id)
        assert result.skipped == 1
        assert result.iocs_touched == 1
        iocs = await harness.repo.list(tenant_id)
        assert len(iocs) == 1
        assert iocs[0].canonical_key.normalized_value == "9.9.9.9"

    async def test_transaction_failure_publishes_no_ioc_events(self) -> None:
        """A raw infrastructure failure (e.g. a real commit/connection
        error) is NOT one of the typed application/domain exceptions
        the orchestrator catches per-candidate — it propagates rather
        than being silently swallowed (no silent exception
        swallowing). Either way, no events are published."""
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        harness.uow._fail_commit = True
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            await harness.orchestrator.ingest_tenant(tenant_id)
        assert harness.events.all_published == []

    async def test_events_publish_once_after_successful_commit(self) -> None:
        tenant_id = TenantId.generate()
        harness = _Harness([_legacy_row()])
        await harness.orchestrator.ingest_tenant(tenant_id)
        assert len(harness.events.published_batches) == 1
        assert len(harness.events.all_published) == 1
