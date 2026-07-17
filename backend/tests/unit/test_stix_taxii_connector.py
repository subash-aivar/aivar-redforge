"""Unit tests for `StixTaxiiFeedConnector` — M22 Phase 3 (STIX/TAXII
Integration).

No real database and no real network: `ReferenceDataAdminService` and
`TaxiiClient` are both injected as fakes (`admin_service=`,
`taxii_client=` constructor parameters), so every test here exercises
the connector's own orchestration logic — config validation, auth
construction, pagination/caps, and outcome aggregation — in complete
isolation. The end-to-end path against a *real* PostgreSQL database
and a real `FeedSyncOrchestrationService` is covered separately by
`tests/integration/test_m22_stix_taxii_pg.py`.
"""

from __future__ import annotations

import pytest

from redforge.application.platform.metrics_abstraction import InMemoryMetricsCollector
from redforge.application.threat_intel.feed_connector import (
    FeedConnectorRegistry,
    FeedSyncContext,
    FeedSyncExecutor,
)
from redforge.application.threat_intel.reference_data_admin_service import (
    BatchUpsertResult,
    ItemError,
)
from redforge.application.threat_intel.stix_taxii_connector import (
    StixTaxiiFeedConnector,
    TaxiiConnectorConfigError,
    TaxiiSyncAttemptTooLargeError,
    _build_auth,
    _resolve_config,
)
from redforge.core.exceptions import CredentialResolutionError
from redforge.domain.threat_intel.feed_value_objects import FeedSourceKind
from redforge.domain.threat_intel.reference_data_value_objects import ReferenceDataSource
from redforge.infrastructure.threat_intel.taxii_client import (
    TaxiiAuth,
    TaxiiCollection,
    TaxiiDiscovery,
    TaxiiEnvelope,
)

_API_ROOT_URL = "https://taxii.example.com/api1/"
_DISCOVERY_URL = "https://taxii.example.com/taxii2/"
_COLLECTION_ID = "col-1"
_FEED_ID = "feed-abc"


def _make_context(
    *, connector_config: dict, credential_ref: str | None = None, checkpoint: str | None = None
) -> FeedSyncContext:
    return FeedSyncContext(
        feed_id=_FEED_ID,
        feed_key="stix-feed",
        source_kind=FeedSourceKind.STIX_TAXII_PULL,
        connector_config=connector_config,
        credential_ref=credential_ref,
        checkpoint=checkpoint,
    )


def _attack_pattern_obj(stix_id: str, *, technique_id: str = "T1001") -> dict:
    return {
        "type": "attack-pattern",
        "id": stix_id,
        "name": "A Technique",
        "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
    }


def _empty_batch_result(object_type: str) -> BatchUpsertResult:
    return BatchUpsertResult(
        source_system="mitre_attack",
        object_type=object_type,
        batch_id="batch-1",
        total=0,
        created=0,
        updated=0,
        unchanged=0,
        failed=0,
        errors=[],
    )


class _FakeCredentialResolver:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets = secrets or {}

    def resolve(self, auth_ref: str) -> str:
        if auth_ref not in self._secrets:
            raise CredentialResolutionError(auth_ref)
        return self._secrets[auth_ref]


class _FakeTaxiiClient:
    def __init__(
        self,
        *,
        discovery: TaxiiDiscovery | None = None,
        collection: TaxiiCollection | None = None,
        object_pages: list[TaxiiEnvelope] | None = None,
    ) -> None:
        self._discovery = discovery
        self._collection = collection or TaxiiCollection(
            id=_COLLECTION_ID, title="Test Collection", description=None, can_read=True, can_write=False
        )
        self._object_pages = object_pages or [TaxiiEnvelope(objects=(), more=False)]
        self.get_discovery_calls: list[str] = []
        self.get_collection_calls: list[str] = []
        self.get_objects_calls: list[dict] = []

    async def get_discovery(self, discovery_url: str, *, auth: TaxiiAuth) -> TaxiiDiscovery:
        self.get_discovery_calls.append(discovery_url)
        assert self._discovery is not None
        return self._discovery

    async def get_collection(
        self, api_root_url: str, collection_id: str, *, auth: TaxiiAuth
    ) -> TaxiiCollection:
        self.get_collection_calls.append(collection_id)
        return self._collection

    async def get_objects(
        self,
        api_root_url: str,
        collection_id: str,
        *,
        auth: TaxiiAuth,
        added_after: str | None = None,
        limit: int = 500,
        next_cursor: str | None = None,
    ) -> TaxiiEnvelope:
        self.get_objects_calls.append(
            {"added_after": added_after, "limit": limit, "next_cursor": next_cursor}
        )
        index = len(self.get_objects_calls) - 1
        return self._object_pages[min(index, len(self._object_pages) - 1)]


class _FakeAdminService:
    def __init__(
        self,
        *,
        tactics_result: BatchUpsertResult | None = None,
        techniques_result: BatchUpsertResult | None = None,
        relationships_result: BatchUpsertResult | None = None,
        vulnerabilities_result: BatchUpsertResult | None = None,
    ) -> None:
        self._tactics_result = tactics_result
        self._techniques_result = techniques_result
        self._relationships_result = relationships_result
        self._vulnerabilities_result = vulnerabilities_result
        self.upsert_tactics_calls: list = []
        self.upsert_techniques_calls: list = []
        self.upsert_technique_relationships_calls: list = []
        self.upsert_vulnerabilities_calls: list = []

    async def upsert_tactics(self, *, actor_id: str, tactics: list, batch_id: str | None = None):
        self.upsert_tactics_calls.append((actor_id, tactics))
        return self._tactics_result or BatchUpsertResult(
            source_system="mitre_attack", object_type="attack_tactic", batch_id="b",
            total=len(tactics), created=len(tactics), updated=0, unchanged=0, failed=0, errors=[],
        )

    async def upsert_techniques(self, *, actor_id: str, techniques: list, batch_id: str | None = None):
        self.upsert_techniques_calls.append((actor_id, techniques))
        return self._techniques_result or BatchUpsertResult(
            source_system="mitre_attack", object_type="attack_technique", batch_id="b",
            total=len(techniques), created=len(techniques), updated=0, unchanged=0, failed=0, errors=[],
        )

    async def upsert_technique_relationships(
        self, *, actor_id: str, relationships: list, batch_id: str | None = None
    ):
        self.upsert_technique_relationships_calls.append((actor_id, relationships))
        return self._relationships_result or BatchUpsertResult(
            source_system="mitre_attack", object_type="attack_technique_relationship", batch_id="b",
            total=len(relationships), created=len(relationships), updated=0, unchanged=0, failed=0, errors=[],
        )

    async def upsert_vulnerabilities(
        self,
        *,
        actor_id: str,
        vulnerabilities: list,
        source_system: ReferenceDataSource = ReferenceDataSource.NVD_CVE,
        batch_id: str | None = None,
    ):
        self.upsert_vulnerabilities_calls.append((actor_id, vulnerabilities, source_system))
        return self._vulnerabilities_result or BatchUpsertResult(
            source_system=source_system.value, object_type="vulnerability", batch_id="b",
            total=len(vulnerabilities), created=len(vulnerabilities), updated=0, unchanged=0, failed=0, errors=[],
        )


def _make_connector(
    *,
    taxii_client: _FakeTaxiiClient | None = None,
    admin_service: _FakeAdminService | None = None,
    credential_resolver: _FakeCredentialResolver | None = None,
    metrics: InMemoryMetricsCollector | None = None,
) -> StixTaxiiFeedConnector:
    return StixTaxiiFeedConnector(
        session_factory=None,  # never touched: `admin_service` is always injected in these tests
        credential_resolver=credential_resolver or _FakeCredentialResolver(),
        metrics=metrics or InMemoryMetricsCollector(),
        taxii_client=taxii_client or _FakeTaxiiClient(),
        admin_service=admin_service or _FakeAdminService(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_config
# ─────────────────────────────────────────────────────────────────────────────


class TestResolveConfig:
    def test_minimal_valid_config_with_api_root_url(self) -> None:
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})
        assert config.api_root_url == _API_ROOT_URL
        assert config.discovery_url is None
        assert config.collection_id == _COLLECTION_ID
        assert config.auth_scheme == "none"
        assert config.page_limit == 500

    def test_minimal_valid_config_with_discovery_url(self) -> None:
        config = _resolve_config({"discovery_url": _DISCOVERY_URL, "collection_id": _COLLECTION_ID})
        assert config.discovery_url == _DISCOVERY_URL
        assert config.api_root_url is None

    def test_missing_collection_id_raises(self) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config({"api_root_url": _API_ROOT_URL})

    def test_blank_collection_id_raises(self) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": "   "})

    def test_missing_both_urls_raises(self) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config({"collection_id": _COLLECTION_ID})

    def test_invalid_auth_scheme_raises(self) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config(
                {"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID, "auth_scheme": "digest"}
            )

    def test_basic_scheme_without_username_raises(self) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config(
                {
                    "api_root_url": _API_ROOT_URL,
                    "collection_id": _COLLECTION_ID,
                    "auth_scheme": "basic",
                }
            )

    def test_basic_scheme_with_username_succeeds(self) -> None:
        config = _resolve_config(
            {
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "basic",
                "auth_username": "svc-account",
            }
        )
        assert config.auth_username == "svc-account"

    @pytest.mark.parametrize("bad_limit", [0, -5, "500", True, 1.5])
    def test_invalid_page_limit_raises(self, bad_limit) -> None:
        with pytest.raises(TaxiiConnectorConfigError):
            _resolve_config(
                {
                    "api_root_url": _API_ROOT_URL,
                    "collection_id": _COLLECTION_ID,
                    "page_limit": bad_limit,
                }
            )

    def test_custom_page_limit_is_applied(self) -> None:
        config = _resolve_config(
            {"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID, "page_limit": 250}
        )
        assert config.page_limit == 250


# ─────────────────────────────────────────────────────────────────────────────
# _build_auth
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildAuth:
    def test_none_scheme_never_touches_the_resolver(self) -> None:
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})
        auth = _build_auth(config, credential_ref=None, credential_resolver=_FakeCredentialResolver())
        assert auth.scheme == "none"

    def test_basic_scheme_resolves_credential_and_carries_username(self) -> None:
        config = _resolve_config(
            {
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "basic",
                "auth_username": "svc-account",
            }
        )
        resolver = _FakeCredentialResolver({"TAXII_SECRET": "s3cr3t"})
        auth = _build_auth(config, credential_ref="TAXII_SECRET", credential_resolver=resolver)
        assert auth.scheme == "basic"
        assert auth.username == "svc-account"
        assert auth.secret == "s3cr3t"

    def test_basic_scheme_without_credential_ref_raises(self) -> None:
        config = _resolve_config(
            {
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "basic",
                "auth_username": "svc-account",
            }
        )
        with pytest.raises(TaxiiConnectorConfigError):
            _build_auth(config, credential_ref=None, credential_resolver=_FakeCredentialResolver())

    def test_bearer_scheme_resolves_secret(self) -> None:
        config = _resolve_config(
            {
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "bearer",
            }
        )
        resolver = _FakeCredentialResolver({"TAXII_TOKEN": "tok-123"})
        auth = _build_auth(config, credential_ref="TAXII_TOKEN", credential_resolver=resolver)
        assert auth.scheme == "bearer"
        assert auth.secret == "tok-123"

    def test_unresolvable_credential_ref_propagates(self) -> None:
        config = _resolve_config(
            {"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID, "auth_scheme": "bearer"}
        )
        with pytest.raises(CredentialResolutionError):
            _build_auth(
                config, credential_ref="UNSET_VAR", credential_resolver=_FakeCredentialResolver()
            )


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_api_root
# ─────────────────────────────────────────────────────────────────────────────


class TestResolveApiRoot:
    async def test_direct_api_root_url_is_used_without_discovery(self) -> None:
        fake_client = _FakeTaxiiClient()
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        resolved = await connector._resolve_api_root(config, auth=TaxiiAuth.none())
        assert resolved == _API_ROOT_URL
        assert fake_client.get_discovery_calls == []

    async def test_discovery_default_is_preferred(self) -> None:
        fake_client = _FakeTaxiiClient(
            discovery=TaxiiDiscovery(
                title="t", description=None, api_roots=(_API_ROOT_URL, "https://other/"), default=_API_ROOT_URL
            )
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"discovery_url": _DISCOVERY_URL, "collection_id": _COLLECTION_ID})

        resolved = await connector._resolve_api_root(config, auth=TaxiiAuth.none())
        assert resolved == _API_ROOT_URL
        assert fake_client.get_discovery_calls == [_DISCOVERY_URL]

    async def test_discovery_falls_back_to_first_api_root_when_no_default(self) -> None:
        fake_client = _FakeTaxiiClient(
            discovery=TaxiiDiscovery(title="t", description=None, api_roots=("https://first/",), default=None)
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"discovery_url": _DISCOVERY_URL, "collection_id": _COLLECTION_ID})

        resolved = await connector._resolve_api_root(config, auth=TaxiiAuth.none())
        assert resolved == "https://first/"

    async def test_discovery_with_no_api_roots_at_all_raises(self) -> None:
        fake_client = _FakeTaxiiClient(
            discovery=TaxiiDiscovery(title="t", description=None, api_roots=(), default=None)
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"discovery_url": _DISCOVERY_URL, "collection_id": _COLLECTION_ID})

        with pytest.raises(TaxiiConnectorConfigError):
            await connector._resolve_api_root(config, auth=TaxiiAuth.none())


# ─────────────────────────────────────────────────────────────────────────────
# _fetch_and_parse_all — pagination, caps, per-object error isolation
# ─────────────────────────────────────────────────────────────────────────────


class TestFetchAndParseAll:
    async def test_single_page_parses_supported_objects(self) -> None:
        fake_client = _FakeTaxiiClient(
            object_pages=[
                TaxiiEnvelope(
                    objects=(_attack_pattern_obj("attack-pattern--11111111-1111-1111-1111-111111111111"),),
                    more=False,
                )
            ]
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        objects, items_fetched, items_failed = await connector._fetch_and_parse_all(
            api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after=None
        )
        assert len(objects) == 1
        assert items_fetched == 1
        assert items_failed == 0

    async def test_unsupported_type_is_skipped_and_not_counted_as_failed(self) -> None:
        fake_client = _FakeTaxiiClient(
            object_pages=[TaxiiEnvelope(objects=({"type": "identity", "id": "identity--x"},), more=False)]
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        objects, items_fetched, items_failed = await connector._fetch_and_parse_all(
            api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after=None
        )
        assert objects == []
        assert items_fetched == 1
        assert items_failed == 0

    async def test_malformed_supported_object_is_skipped_and_counted_as_failed(self) -> None:
        malformed = {"type": "attack-pattern", "id": "attack-pattern--11111111-1111-1111-1111-111111111111"}
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(malformed,), more=False)])
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        objects, items_fetched, items_failed = await connector._fetch_and_parse_all(
            api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after=None
        )
        assert objects == []
        assert items_fetched == 1
        assert items_failed == 1

    async def test_pagination_across_multiple_pages_is_aggregated(self) -> None:
        fake_client = _FakeTaxiiClient(
            object_pages=[
                TaxiiEnvelope(
                    objects=(_attack_pattern_obj("attack-pattern--11111111-1111-1111-1111-111111111111"),),
                    more=True,
                    next="cursor-2",
                ),
                TaxiiEnvelope(
                    objects=(_attack_pattern_obj("attack-pattern--22222222-2222-2222-2222-222222222222"),),
                    more=False,
                ),
            ]
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        objects, items_fetched, _items_failed = await connector._fetch_and_parse_all(
            api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after="2026-01-01T00:00:00+00:00"
        )
        assert items_fetched == 2
        assert len(objects) == 2
        assert fake_client.get_objects_calls[0]["added_after"] == "2026-01-01T00:00:00+00:00"
        assert fake_client.get_objects_calls[1]["next_cursor"] == "cursor-2"

    async def test_total_object_ceiling_is_enforced_across_pages(self, monkeypatch) -> None:
        import redforge.application.threat_intel.stix_taxii_connector as connector_module

        monkeypatch.setattr(connector_module, "MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT", 1)
        fake_client = _FakeTaxiiClient(
            object_pages=[
                TaxiiEnvelope(
                    objects=(
                        _attack_pattern_obj("attack-pattern--11111111-1111-1111-1111-111111111111"),
                        _attack_pattern_obj("attack-pattern--22222222-2222-2222-2222-222222222222"),
                    ),
                    more=False,
                )
            ]
        )
        connector = _make_connector(taxii_client=fake_client)
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        with pytest.raises(TaxiiSyncAttemptTooLargeError):
            await connector._fetch_and_parse_all(
                api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after=None
            )

    async def test_page_ceiling_is_enforced_when_server_never_signals_completion(
        self, monkeypatch
    ) -> None:
        import redforge.application.threat_intel.stix_taxii_connector as connector_module

        monkeypatch.setattr(connector_module, "MAX_PAGES_PER_SYNC_ATTEMPT", 3)

        class _NeverEndingClient(_FakeTaxiiClient):
            async def get_objects(self, *args, **kwargs) -> TaxiiEnvelope:
                await super().get_objects(*args, **kwargs)
                return TaxiiEnvelope(objects=(), more=True, next="always-more")

        connector = _make_connector(taxii_client=_NeverEndingClient())
        config = _resolve_config({"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID})

        with pytest.raises(TaxiiSyncAttemptTooLargeError):
            await connector._fetch_and_parse_all(
                api_root_url=_API_ROOT_URL, config=config, auth=TaxiiAuth.none(), added_after=None
            )


# ─────────────────────────────────────────────────────────────────────────────
# execute() — full connector orchestration, no real DB or network
# ─────────────────────────────────────────────────────────────────────────────


class TestExecute:
    async def test_config_error_is_raised_before_any_taxii_call(self) -> None:
        fake_client = _FakeTaxiiClient()
        connector = _make_connector(taxii_client=fake_client)
        context = _make_context(connector_config={"api_root_url": _API_ROOT_URL})  # missing collection_id

        with pytest.raises(TaxiiConnectorConfigError):
            await connector.execute(context)
        assert fake_client.get_collection_calls == []

    async def test_unreadable_collection_raises_before_fetching_objects(self) -> None:
        fake_client = _FakeTaxiiClient(
            collection=TaxiiCollection(
                id=_COLLECTION_ID, title="No Read", description=None, can_read=False, can_write=False
            )
        )
        connector = _make_connector(taxii_client=fake_client)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID}
        )

        with pytest.raises(TaxiiConnectorConfigError):
            await connector.execute(context)
        assert fake_client.get_objects_calls == []

    async def test_empty_collection_never_touches_the_admin_service(self) -> None:
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(), more=False)])
        fake_admin = _FakeAdminService()
        connector = _make_connector(taxii_client=fake_client, admin_service=fake_admin)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID}
        )

        outcome = await connector.execute(context)
        assert outcome.items_fetched == 0
        assert outcome.items_processed == 0
        assert outcome.items_failed == 0
        assert fake_admin.upsert_tactics_calls == []
        assert fake_admin.upsert_techniques_calls == []
        assert fake_admin.upsert_technique_relationships_calls == []
        assert fake_admin.upsert_vulnerabilities_calls == []

    async def test_checkpoint_is_the_attempt_start_time_not_a_value_from_the_response(self) -> None:
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(), more=False)])
        connector = _make_connector(taxii_client=fake_client)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID},
            checkpoint="2020-01-01T00:00:00+00:00",
        )

        from datetime import UTC, datetime

        before = datetime.now(UTC)
        outcome = await connector.execute(context)
        after = datetime.now(UTC)

        assert outcome.checkpoint is not None
        checkpoint_dt = datetime.fromisoformat(outcome.checkpoint)
        assert before <= checkpoint_dt <= after

    async def test_successful_upserts_are_counted_as_processed(self) -> None:
        vuln_obj = {
            "type": "vulnerability",
            "id": "vulnerability--11111111-1111-1111-1111-111111111111",
            "name": "CVE-2024-1234",
            "external_references": [{"source_name": "cve", "external_id": "CVE-2024-1234"}],
        }
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(vuln_obj,), more=False)])
        fake_admin = _FakeAdminService()
        connector = _make_connector(taxii_client=fake_client, admin_service=fake_admin)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID}
        )

        outcome = await connector.execute(context)
        assert outcome.items_fetched == 1
        assert outcome.items_processed == 1
        assert outcome.items_failed == 0
        assert len(fake_admin.upsert_vulnerabilities_calls) == 1
        actor_id, vulns, source_system = fake_admin.upsert_vulnerabilities_calls[0]
        assert actor_id == _FEED_ID
        assert vulns[0].cve_id == "CVE-2024-1234"
        assert source_system is ReferenceDataSource.STIX_TAXII_FEED

    async def test_unmapped_and_upsert_failures_are_both_reflected_in_items_failed(self) -> None:
        mapped_and_unmapped = [
            {
                "type": "vulnerability",
                "id": "vulnerability--11111111-1111-1111-1111-111111111111",
                "name": "CVE-2024-1",
                "external_references": [{"source_name": "cve", "external_id": "CVE-2024-1"}],
            },
            {
                # No 'cve' external reference — unmapped by the ACL mapper.
                "type": "vulnerability",
                "id": "vulnerability--22222222-2222-2222-2222-222222222222",
                "name": "No CVE Ref",
            },
        ]
        fake_client = _FakeTaxiiClient(
            object_pages=[TaxiiEnvelope(objects=tuple(mapped_and_unmapped), more=False)]
        )
        failing_result = BatchUpsertResult(
            source_system="stix_taxii_feed",
            object_type="vulnerability",
            batch_id="b",
            total=1,
            created=0,
            updated=0,
            unchanged=0,
            failed=1,
            errors=[ItemError(index=0, identifier="CVE-2024-1", message="boom")],
        )
        fake_admin = _FakeAdminService(vulnerabilities_result=failing_result)
        connector = _make_connector(taxii_client=fake_client, admin_service=fake_admin)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID}
        )

        outcome = await connector.execute(context)
        assert outcome.items_fetched == 2
        assert outcome.items_processed == 0
        # 1 unmapped (no cve ref) + 1 upsert failure.
        assert outcome.items_failed == 2

    async def test_metrics_are_recorded_with_feed_labels(self) -> None:
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(), more=False)])
        metrics = InMemoryMetricsCollector()
        connector = _make_connector(taxii_client=fake_client, metrics=metrics)
        context = _make_context(
            connector_config={"api_root_url": _API_ROOT_URL, "collection_id": _COLLECTION_ID}
        )

        await connector.execute(context)
        samples = metrics.snapshot("threat_intel.stix_taxii.items_fetched")
        assert len(samples) == 1
        assert dict(samples[0].labels)["feed_id"] == _FEED_ID

    async def test_basic_auth_credential_is_resolved_and_used(self) -> None:
        fake_client = _FakeTaxiiClient(object_pages=[TaxiiEnvelope(objects=(), more=False)])
        resolver = _FakeCredentialResolver({"TAXII_PASSWORD": "hunter2"})
        connector = _make_connector(taxii_client=fake_client, credential_resolver=resolver)
        context = _make_context(
            connector_config={
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "basic",
                "auth_username": "svc",
            },
            credential_ref="TAXII_PASSWORD",
        )

        # Should not raise — the credential resolves successfully.
        await connector.execute(context)

    async def test_missing_credential_ref_for_bearer_scheme_raises(self) -> None:
        fake_client = _FakeTaxiiClient()
        connector = _make_connector(taxii_client=fake_client)
        context = _make_context(
            connector_config={
                "api_root_url": _API_ROOT_URL,
                "collection_id": _COLLECTION_ID,
                "auth_scheme": "bearer",
            }
        )

        with pytest.raises(TaxiiConnectorConfigError):
            await connector.execute(context)


# ─────────────────────────────────────────────────────────────────────────────
# FeedConnectorRegistry integration
# ─────────────────────────────────────────────────────────────────────────────


class TestRegistryIntegration:
    def test_connector_satisfies_the_feed_sync_executor_protocol(self) -> None:
        connector = _make_connector()
        assert isinstance(connector, FeedSyncExecutor)

    def test_connector_can_be_registered_and_retrieved_for_stix_taxii_pull(self) -> None:
        registry = FeedConnectorRegistry()
        connector = _make_connector()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, connector)

        assert registry.get(FeedSourceKind.STIX_TAXII_PULL) is connector
        assert FeedSourceKind.STIX_TAXII_PULL in registry.list_registered()

    def test_other_source_kinds_remain_unregistered(self) -> None:
        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, _make_connector())

        assert registry.get(FeedSourceKind.STATIC_HTTP_DOWNLOAD) is None
        assert registry.get(FeedSourceKind.HTTP_API_INCREMENTAL) is None
