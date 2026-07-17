"""M22 Phase 3 — STIX/TAXII Integration: PostgreSQL end-to-end proof
suite.

Runs against the SAME dedicated proof database Phase 2 owns
(`redforge_m22_feed_sync_proof_test`, migrated to head via `alembic
upgrade head`) — Phase 3 introduces NO schema changes (no new
migration): `ReferenceDataSource.STIX_TAXII_FEED` is a Python-level
`StrEnum` member stored into the existing `stix_ingestion_log
.source_system` `VARCHAR(30)` column, and every other Phase 3 write
goes through Phase 1's existing `attack_tactics` / `attack_techniques`
/ `attack_technique_relationships` / `vulnerabilities` tables via the
existing `ReferenceDataAdminService`.

Every test here exercises the REAL, production `StixTaxiiFeedConnector`
+ REAL `TaxiiClient` + REAL `FeedSyncOrchestrationService` against a
REAL PostgreSQL database. The only thing ever faked is the outbound
TAXII HTTP transport itself (`httpx.MockTransport`, injected into a
real `TaxiiClient`) — there is no real network access to a TAXII
server in a test suite, but every layer of RedForge's own code between
"HTTP response bytes" and "row committed in PostgreSQL" is exercised
for real, including the connector seam
(`FeedConnectorRegistry`/`FeedSyncExecutor`) Phase 2 already proved
independently of any real connector.

Covers:
  Section A: End-to-end synchronization — a full STIX object batch
             (tactic + technique + vulnerability) fetched from a fake
             TAXII collection and persisted into Phase 1's reference-
             data tables through the real orchestration service.
  Section B: Incremental synchronization — the checkpoint recorded by
             a successful attempt is used as `added_after` on the next
             attempt.
  Section C: Idempotency — re-syncing identical STIX content does not
             duplicate rows.
  Section D: Error handling — an unreadable collection, and a
             genuinely SSRF-unsafe (loopback-resolving) endpoint, both
             fail the `FeedSyncRun` honestly rather than silently
             succeeding or crashing the worker.
  Section E: Authentication — a bearer credential resolved via
             `Feed.credential_ref` is actually forwarded to the TAXII
             server.
  Section F: No architecture regression — every other `FeedSourceKind`
             is still unregistered and still fails honestly with
             `UnknownFeedConnectorError`, exactly as Phase 2 left it.
"""

from __future__ import annotations

import os
import time

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
from redforge.application.threat_intel.feed_admin_service import FeedAdminService
from redforge.application.threat_intel.feed_connector import FeedConnectorRegistry
from redforge.application.threat_intel.feed_query_service import FeedQueryService
from redforge.application.threat_intel.feed_sync_orchestration_service import (
    FeedSyncOrchestrationService,
)
from redforge.application.threat_intel.stix_taxii_connector import StixTaxiiFeedConnector
from redforge.domain.threat_intel.feed_exceptions import UnknownFeedConnectorError
from redforge.domain.threat_intel.feed_value_objects import (
    FeedSourceKind,
    FeedSyncRunStatus,
    FeedSyncTrigger,
    RetryPolicy,
)
from redforge.infrastructure.credential_resolver import EnvironmentCredentialResolver
from redforge.infrastructure.threat_intel.taxii_client import TaxiiClient

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m22_feed_sync_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_M22_FEED_SYNC_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)

_API_ROOT_URL = "https://taxii.example.test/api1/"

_FAST_RETRY = RetryPolicy(
    max_attempts=2, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter_factor=0.0
)


def _unique_key(prefix: str) -> str:
    return f"{prefix}_{time.time_ns()}"


def _unique_stix_uuid(prefix: str) -> str:
    """A syntactically valid v4-shaped hex UUID unique to this test
    run, so concurrent/module-scoped tests never collide on the same
    STIX id across runs of this file."""
    suffix = f"{time.time_ns():032x}"[-32:]
    return f"{suffix[0:8]}-{suffix[8:12]}-{suffix[12:16]}-{suffix[16:20]}-{suffix[20:32]}"


def _tactic_object(stix_id: str, *, tactic_id: str, shortname: str) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{stix_id}",
        "name": f"Tactic {tactic_id}",
        "description": "A proof-test tactic.",
        "x_mitre_shortname": shortname,
        "external_references": [{"source_name": "mitre-attack", "external_id": tactic_id}],
    }


def _technique_object(stix_id: str, *, technique_id: str, tactic_shortname: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{stix_id}",
        "name": f"Technique {technique_id}",
        "description": "A proof-test technique.",
        "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic_shortname}],
    }


def _vulnerability_object(stix_id: str, *, cve_id: str) -> dict:
    return {
        "type": "vulnerability",
        "id": f"vulnerability--{stix_id}",
        "name": cve_id,
        "description": "A proof-test vulnerability.",
        "external_references": [{"source_name": "cve", "external_id": cve_id}],
    }


class _FakeTaxiiServer:
    """A minimal, in-process stand-in for a real TAXII 2.1 server —
    every request is served from `httpx.MockTransport`, so no real
    socket is ever opened. Routes purely on URL path suffix, since
    that's all `StixTaxiiFeedConnector` ever needs
    (`/collections/{id}/` and `/collections/{id}/objects/`)."""

    def __init__(self, *, can_read: bool = True, object_pages: list[dict] | None = None) -> None:
        self.can_read = can_read
        self.object_pages = object_pages if object_pages is not None else [{"objects": [], "more": False}]
        self.requests: list[httpx.Request] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.endswith("/objects/"):
            objects_call_index = sum(
                1 for r in self.requests if r.url.path.endswith("/objects/")
            ) - 1
            page = self.object_pages[min(objects_call_index, len(self.object_pages) - 1)]
            return httpx.Response(200, json=page)
        return httpx.Response(
            200,
            json={
                "id": "col-1",
                "title": "Proof Collection",
                "can_read": self.can_read,
                "can_write": False,
            },
        )

    def objects_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path.endswith("/objects/")]


def _connector_for(server: _FakeTaxiiServer, session_factory) -> StixTaxiiFeedConnector:
    transport = httpx.MockTransport(server)
    http_client = httpx.AsyncClient(transport=transport, follow_redirects=False)

    async def _resolve_test_host(hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)  # a real, public, non-reserved address

    taxii_client = TaxiiClient(http_client=http_client, resolver=_resolve_test_host)
    return StixTaxiiFeedConnector(
        session_factory=session_factory,
        credential_resolver=EnvironmentCredentialResolver(),
        metrics=InMemoryMetricsCollector(),
        taxii_client=taxii_client,
    )


async def _registered_active_feed(
    session_factory,
    *,
    connector_config: dict,
    credential_ref: str | None = None,
    retry_policy: RetryPolicy | None = None,
) -> str:
    admin = FeedAdminService(session_factory)
    feed = await admin.register_feed(
        actor_id="admin-1",
        feed_key=_unique_key("stix_taxii_feed"),
        display_name="STIX/TAXII Proof Feed",
        source_kind=FeedSourceKind.STIX_TAXII_PULL.value,
        interval_seconds=600,
        connector_config=connector_config,
        credential_ref=credential_ref,
        retry_policy=retry_policy or _FAST_RETRY,
    )
    feed = await admin.activate_feed(actor_id="admin-1", feed_id=feed.id)
    return feed.id


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


# ─────────────────────────────────────────────────────────────────────────────
# Section A — End-to-end synchronization
# ─────────────────────────────────────────────────────────────────────────────


class TestEndToEndSynchronization:
    async def test_full_batch_is_fetched_mapped_and_persisted(self, session_factory) -> None:
        tactic_id = f"TA{time.time_ns() % 10000:04d}"
        technique_id = f"T{time.time_ns() % 10000:04d}"
        cve_id = f"CVE-2026-{time.time_ns() % 1000000:06d}"
        shortname = _unique_key("shortname")

        server = _FakeTaxiiServer(
            object_pages=[
                {
                    "objects": [
                        _tactic_object(
                            _unique_stix_uuid("t"), tactic_id=tactic_id, shortname=shortname
                        ),
                        _technique_object(
                            _unique_stix_uuid("h"),
                            technique_id=technique_id,
                            tactic_shortname=shortname,
                        ),
                        _vulnerability_object(_unique_stix_uuid("v"), cve_id=cve_id),
                    ],
                    "more": False,
                }
            ]
        )
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": "col-1"},
        )

        run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )

        assert run.status is FeedSyncRunStatus.SUCCEEDED, run.error_message
        assert run.items_fetched == 3
        assert run.items_processed == 3
        assert run.items_failed == 0
        assert run.checkpoint_after is not None

        async with session_factory() as session:
            tactic_row = await session.execute(
                text("SELECT tactic_id, shortname FROM attack_tactics WHERE tactic_id = :tid"),
                {"tid": tactic_id},
            )
            assert tactic_row.first() == (tactic_id, shortname)

            technique_row = await session.execute(
                text(
                    "SELECT technique_id, tactic_ids FROM attack_techniques "
                    "WHERE technique_id = :tid"
                ),
                {"tid": technique_id},
            )
            row = technique_row.first()
            assert row is not None
            assert row[0] == technique_id
            assert tactic_id in row[1]

            vuln_row = await session.execute(
                text("SELECT cve_id FROM vulnerabilities WHERE cve_id = :cid"), {"cid": cve_id}
            )
            assert vuln_row.first() == (cve_id,)

            ingestion_row = await session.execute(
                text(
                    "SELECT source_system FROM stix_ingestion_log "
                    "WHERE external_id = :cid AND object_type = 'vulnerability'"
                ),
                {"cid": cve_id},
            )
            assert ingestion_row.first() == ("stix_taxii_feed",)


# ─────────────────────────────────────────────────────────────────────────────
# Section B — Incremental synchronization
# ─────────────────────────────────────────────────────────────────────────────


class TestIncrementalSynchronization:
    async def test_second_attempt_sends_previous_checkpoint_as_added_after(
        self, session_factory
    ) -> None:
        server = _FakeTaxiiServer(object_pages=[{"objects": [], "more": False}])
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": "col-1"},
        )

        first_run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert first_run.status is FeedSyncRunStatus.SUCCEEDED
        first_checkpoint = first_run.checkpoint_after
        assert first_checkpoint is not None

        first_objects_request = server.objects_requests()[0]
        assert "added_after" not in dict(first_objects_request.url.params)

        second_run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert second_run.status is FeedSyncRunStatus.SUCCEEDED

        second_objects_request = server.objects_requests()[1]
        assert dict(second_objects_request.url.params)["added_after"] == first_checkpoint


# ─────────────────────────────────────────────────────────────────────────────
# Section C — Idempotency
# ─────────────────────────────────────────────────────────────────────────────


class TestIdempotency:
    async def test_resyncing_identical_content_does_not_duplicate_rows(
        self, session_factory
    ) -> None:
        technique_id = f"T{time.time_ns() % 10000:04d}"
        stix_uuid = _unique_stix_uuid("dup")
        page = {
            "objects": [_technique_object(stix_uuid, technique_id=technique_id, tactic_shortname="")],
            "more": False,
        }
        server = _FakeTaxiiServer(object_pages=[page, page])
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": "col-1"},
        )

        await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )

        async with session_factory() as session:
            count_row = await session.execute(
                text("SELECT COUNT(*) FROM attack_techniques WHERE technique_id = :tid"),
                {"tid": technique_id},
            )
            assert count_row.scalar_one() == 1


# ─────────────────────────────────────────────────────────────────────────────
# Section D — Error handling
# ─────────────────────────────────────────────────────────────────────────────


class TestErrorHandling:
    async def test_unreadable_collection_fails_the_run_honestly(self, session_factory) -> None:
        server = _FakeTaxiiServer(can_read=False)
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": "col-1"},
        )

        run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.FAILED
        assert "not readable" in (run.error_message or "")
        assert server.objects_requests() == []

        query = FeedQueryService(session_factory)
        updated_feed = await query.get_feed(feed_id)
        assert updated_feed.consecutive_failure_count == 1
        assert updated_feed.checkpoint is None

    async def test_a_genuinely_ssrf_unsafe_endpoint_fails_the_run_via_the_real_dns_resolver(
        self, session_factory
    ) -> None:
        """No injected resolver here at all — `TaxiiClient()`'s
        production default (`socket.getaddrinfo`) resolves `localhost`
        to a real loopback address, and the connector's real SSRF gate
        must refuse it, end to end, through the real orchestration
        service."""
        connector = StixTaxiiFeedConnector(
            session_factory=session_factory,
            credential_resolver=EnvironmentCredentialResolver(),
            metrics=InMemoryMetricsCollector(),
            # `taxii_client` deliberately omitted: production default,
            # real DNS resolution, real SSRF gate.
        )
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={
                "api_root_url": "https://localhost/api1/",
                "collection_id": "col-1",
            },
            retry_policy=RetryPolicy(
                max_attempts=1, base_delay_seconds=0.0, max_delay_seconds=0.0, jitter_factor=0.0
            ),
        )

        run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.FAILED
        assert "non-public" in (run.error_message or "") or "resolv" in (run.error_message or "")


# ─────────────────────────────────────────────────────────────────────────────
# Section E — Authentication
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthentication:
    async def test_bearer_credential_is_resolved_and_forwarded_to_the_server(
        self, session_factory
    ) -> None:
        env_var_name = f"REDFORGE_TEST_TAXII_TOKEN_{time.time_ns()}"
        os.environ[env_var_name] = "proof-bearer-token"
        try:
            server = _FakeTaxiiServer(object_pages=[{"objects": [], "more": False}])
            connector = _connector_for(server, session_factory)
            registry = FeedConnectorRegistry()
            registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
            orchestration = FeedSyncOrchestrationService(session_factory, registry)

            feed_id = await _registered_active_feed(
                session_factory,
                connector_config={
                    "api_root_url": _API_ROOT_URL,
                    "collection_id": "col-1",
                    "auth_scheme": "bearer",
                },
                credential_ref=env_var_name,
            )

            run = await orchestration.trigger_sync(
                feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
            )
            assert run.status is FeedSyncRunStatus.SUCCEEDED, run.error_message
            assert server.requests[0].headers["authorization"] == "Bearer proof-bearer-token"
        finally:
            os.environ.pop(env_var_name, None)

    async def test_missing_bearer_credential_ref_fails_the_run(self, session_factory) -> None:
        server = _FakeTaxiiServer()
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        feed_id = await _registered_active_feed(
            session_factory,
            connector_config={
                "api_root_url": _API_ROOT_URL,
                "collection_id": "col-1",
                "auth_scheme": "bearer",
            },
            credential_ref=None,
        )

        run = await orchestration.trigger_sync(
            feed_id=feed_id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
        )
        assert run.status is FeedSyncRunStatus.FAILED
        assert server.requests == []


# ─────────────────────────────────────────────────────────────────────────────
# Section F — No architecture regression
# ─────────────────────────────────────────────────────────────────────────────


class TestNoArchitectureRegression:
    async def test_other_source_kinds_still_fail_honestly_with_no_registered_connector(
        self, session_factory
    ) -> None:
        """Registering `StixTaxiiFeedConnector` against
        `FeedSourceKind.STIX_TAXII_PULL` must not accidentally satisfy
        `trigger_sync` for any other `FeedSourceKind` — the registry
        is a per-kind mapping, never a catch-all."""
        server = _FakeTaxiiServer()
        connector = _connector_for(server, session_factory)
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)
        orchestration = FeedSyncOrchestrationService(session_factory, registry)

        admin = FeedAdminService(session_factory)
        feed = await admin.register_feed(
            actor_id="admin-1",
            feed_key=_unique_key("static_http_regression_feed"),
            display_name="Static HTTP Feed",
            source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD.value,
            interval_seconds=600,
        )
        feed = await admin.activate_feed(actor_id="admin-1", feed_id=feed.id)

        with pytest.raises(UnknownFeedConnectorError):
            await orchestration.trigger_sync(
                feed_id=feed.id, trigger=FeedSyncTrigger.MANUAL, actor_id="admin-1"
            )
        assert server.requests == []
