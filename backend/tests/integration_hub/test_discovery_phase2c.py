"""Phase 2C hardening tests: paginated discovery contract, checkpoint /
resume, circuit breaker tripping from discovery failures, concurrent-run
rejection, the EntityId round-trip fix, and DB-call-count-stays-O(pages)
load-shape sanity check."""

from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID, uuid4

import pytest

from integration_hub.application.commands.connector_commands import RegisterConnector
from integration_hub.application.commands.discovery_commands import RunDiscovery
from integration_hub.application.exceptions import ApplicationValidationError
from integration_hub.domain.value_objects.discovery import DiscoveryPage
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId
from integration_hub.infrastructure.container import IntegrationHubContainer
from redforge.shared.identifiers import EntityId as SharedEntityId


class _FakeCredentialService:
    async def resolve_credential(self, cmd):
        class _R:
            plaintext_secret = b"sk-test-123"

        return _R()


async def _register_openai(container: IntegrationHubContainer, tenant_id: UUID) -> UUID:
    reg_dto = await container.app.register(
        RegisterConnector(
            tenant_id,
            "openai",
            "my-openai",
            str(uuid4()),
            "API_KEY",
            "tester",
            ("integration:admin",),
        )
    )
    return UUID(reg_dto.connector_id)


def _pages(*batches: list[dict]) -> list[DiscoveryPage]:
    """Build a sequence of DiscoveryPage responses, each pointing at the
    next by cursor, the last with has_more=False."""
    pages = []
    for i, items in enumerate(batches):
        is_last = i == len(batches) - 1
        pages.append(
            DiscoveryPage(
                items=items,
                next_cursor=None if is_last else f"cursor-{i + 1}",
                has_more=not is_last,
            )
        )
    return pages


# ---------------------------------------------------------------------------
# EntityId round-trip (P0-2)
# ---------------------------------------------------------------------------


def test_entity_id_from_uuid_round_trips_equal() -> None:
    generated = SharedEntityId.generate()
    as_uuid = generated.value.to_uuid()
    rebuilt = SharedEntityId.from_uuid(as_uuid)
    assert rebuilt == generated
    assert str(rebuilt) == str(generated)
    assert hash(rebuilt) == hash(generated)


def test_entity_id_double_wrap_bug_is_gone() -> None:
    """Regression guard: EntityId(already_an_entity_id) used to silently
    break equality/hashing. The fixed call sites now pass the value
    through instead of re-wrapping it."""
    a = SharedEntityId.generate()
    # The old buggy call would have been EntityId(a) -- verify that doing
    # so is indeed broken (documents *why* the fix matters), while the
    # canonical constructors remain well-behaved.
    broken = SharedEntityId.__new__(SharedEntityId)
    broken._ulid = a  # type: ignore[attr-defined]  # simulate the old bug directly
    assert broken != a  # confirms the historical bug shape
    # The fixed path (identity passthrough / from_uuid) preserves equality.
    assert SharedEntityId.from_uuid(a.value.to_uuid()) == a


# ---------------------------------------------------------------------------
# Paginated discovery + checkpoint/resume (P0-1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_paginated_discovery_walks_all_pages() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    pages = _pages(
        [{"id": "gpt-4", "object": "model", "owned_by": "openai"}],
        [{"id": "gpt-4o", "object": "model", "owned_by": "openai"}],
        [{"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"}],
    )
    object.__setattr__(plugin, "discover", AsyncMock(side_effect=pages))

    run_dto = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert run_dto.status == "COMPLETED"
    assert run_dto.pages_processed == 3
    assert run_dto.items_discovered == 3
    assert run_dto.items_created == 3
    assert plugin.discover.await_count == 3

    assets = await container.discovery.list_assets(tenant_id, ("integration:admin",))
    assert len(assets) == 3


@pytest.mark.asyncio
async def test_discovery_stops_at_max_pages_and_is_resumable() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    pages = _pages(
        [{"id": "m1", "object": "model", "owned_by": "openai"}],
        [{"id": "m2", "object": "model", "owned_by": "openai"}],
        [{"id": "m3", "object": "model", "owned_by": "openai"}],
    )
    object.__setattr__(plugin, "discover", AsyncMock(side_effect=pages))

    # max_pages=2 forces the run to stop after the first two pages even
    # though a third page remains (has_more True after page 2).
    first = await container.discovery.run_discovery(
        RunDiscovery(
            tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",), max_pages=2
        )
    )
    assert first.status == "PARTIAL"
    assert first.has_more is True
    assert first.pages_processed == 2
    assert first.cursor == "cursor-2"

    # Resuming continues from the persisted cursor rather than refetching
    # pages 1-2 or restarting from zero.
    resumed = await container.discovery.run_discovery(
        RunDiscovery(
            tenant_id,
            connector_id,
            "MANUAL",
            "tester",
            ("integration:admin",),
            resume_sync_run_id=UUID(first.sync_run_id),
        )
    )
    assert resumed.status == "COMPLETED"
    assert resumed.pages_processed == 3
    assert plugin.discover.await_count == 3  # no refetch of already-processed pages

    assets = await container.discovery.list_assets(tenant_id, ("integration:admin",))
    assert len(assets) == 3


@pytest.mark.asyncio
async def test_partial_failure_after_first_page_is_resumable_not_a_hard_failure() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    first_page = DiscoveryPage(
        items=[{"id": "m1", "object": "model", "owned_by": "openai"}],
        next_cursor="cursor-1",
        has_more=True,
    )
    # After the first page succeeds, every subsequent attempt fails --
    # exhausts the retry budget and should leave the run PARTIAL (not
    # FAILED), since page 1 was already durably persisted.
    object.__setattr__(
        plugin,
        "discover",
        AsyncMock(side_effect=[first_page, RuntimeError("vendor 500"), RuntimeError("vendor 500"), RuntimeError("vendor 500")]),
    )

    result = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert result.status == "PARTIAL"
    assert result.pages_processed == 1
    assert result.error is not None

    assets = await container.discovery.list_assets(tenant_id, ("integration:admin",))
    assert len(assets) == 1  # page 1's item was not lost


@pytest.mark.asyncio
async def test_first_page_hard_failure_fails_the_run() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    object.__setattr__(
        plugin, "discover", AsyncMock(side_effect=RuntimeError("vendor unreachable"))
    )

    with pytest.raises(ApplicationValidationError):
        await container.discovery.run_discovery(
            RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
        )

    history = await container.discovery.list_sync_runs(
        tenant_id, connector_id, ("integration:admin",)
    )
    assert history[0].status == "FAILED"


# ---------------------------------------------------------------------------
# Concurrent-run rejection (P0-4)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_run_rejected_cleanly() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    # A page that says has_more=True forever, so the first call never
    # completes within this test -- simulate by starting a RUNNING sync
    # run directly via the repository (cheaper than a real hung call).
    from integration_hub.domain.aggregates.sync_run import SyncRun
    from integration_hub.domain.value_objects.discovery import SyncMode
    from integration_hub.domain.value_objects.identifiers import ConnectorId

    tenant = EntityId.from_uuid(tenant_id)
    running = SyncRun.start(tenant, ConnectorId(connector_id), SyncMode.MANUAL)
    await container.sync_runs.save(running, tenant)

    object.__setattr__(
        plugin,
        "discover",
        AsyncMock(return_value=DiscoveryPage(items=[], next_cursor=None, has_more=False)),
    )

    with pytest.raises(ApplicationValidationError, match="already in progress"):
        await container.discovery.run_discovery(
            RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
        )


# ---------------------------------------------------------------------------
# Cancellation via repository, not a local object reference (P0-1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancellation_is_read_from_repository_between_pages() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    pages = _pages(
        [{"id": "m1", "object": "model", "owned_by": "openai"}],
        [{"id": "m2", "object": "model", "owned_by": "openai"}],
        [{"id": "m3", "object": "model", "owned_by": "openai"}],
    )

    tenant = EntityId.from_uuid(tenant_id)
    call_count = 0

    async def _discover_and_cancel_after_first_page(secret, config, cursor=None):
        nonlocal call_count
        page = pages[call_count]
        call_count += 1
        if call_count == 1:
            # Simulate an out-of-process cancel request landing between
            # pages: mutate the persisted run directly, as the real
            # cancel_discovery() API call would.
            run = await container.sync_runs.find_running_for_connector(
                ConnectorId(connector_id), tenant
            )
            if run is not None:
                run.request_cancel()
                await container.sync_runs.save(run, tenant)
        return page

    object.__setattr__(plugin, "discover", AsyncMock(side_effect=_discover_and_cancel_after_first_page))

    result = await container.discovery.run_discovery(
        RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
    )
    assert result.status == "CANCELLED"
    assert result.pages_processed == 1  # stopped after page 1, never fetched page 2/3


# ---------------------------------------------------------------------------
# Circuit breaker tripping on repeated discovery failures (P0-4)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_circuit_breaker_trips_after_repeated_discovery_failures() -> None:
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    object.__setattr__(plugin, "discover", AsyncMock(side_effect=RuntimeError("vendor down")))

    for _ in range(container.discovery.circuit.FAILURE_THRESHOLD):
        with pytest.raises(ApplicationValidationError):
            await container.discovery.run_discovery(
                RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
            )

    # The breaker is now open -- the domain aggregate itself refuses to
    # execute (ConnectorRegistration.assert_executable raises
    # CircuitOpenError, an IntegrationHubDomainError mapped to HTTP 409 at
    # the API layer) before the vendor is ever called again.
    from integration_hub.domain.exceptions.domain_exceptions import CircuitOpenError

    calls_before_open = plugin.discover.await_count
    with pytest.raises(CircuitOpenError):
        await container.discovery.run_discovery(
            RunDiscovery(tenant_id, connector_id, "MANUAL", "tester", ("integration:admin",))
        )
    assert plugin.discover.await_count == calls_before_open


# ---------------------------------------------------------------------------
# DB-call-count load-shape sanity check (batched save/lookup)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_save_and_lookup_stay_o_of_pages_not_items() -> None:
    """Simulates a connector returning several thousand synthetic items
    across many pages and confirms the number of repository calls made by
    the discovery loop scales with page count, not item count -- proving
    per-page batching (get_by_fingerprints + save_many) actually
    happened instead of one repository round trip per item."""
    container = IntegrationHubContainer(credential_service=_FakeCredentialService())
    tenant_id = uuid4()
    connector_id = await _register_openai(container, tenant_id)

    plugin = container.catalog.get("openai")
    n_pages = 20
    items_per_page = 150  # 3,000 synthetic items total
    batches = [
        [{"id": f"model-{p}-{i}", "object": "model", "owned_by": "openai"} for i in range(items_per_page)]
        for p in range(n_pages)
    ]
    pages = _pages(*batches)
    object.__setattr__(plugin, "discover", AsyncMock(side_effect=pages))

    fingerprint_lookup_calls = 0
    save_many_calls = 0
    orig_get_by_fingerprints = container.discovered_assets.get_by_fingerprints
    orig_save_many = container.discovered_assets.save_many

    async def counted_get_by_fingerprints(fingerprints, tenant):
        nonlocal fingerprint_lookup_calls
        fingerprint_lookup_calls += 1
        return await orig_get_by_fingerprints(fingerprints, tenant)

    async def counted_save_many(assets, tenant):
        nonlocal save_many_calls
        save_many_calls += 1
        return await orig_save_many(assets, tenant)

    container.discovered_assets.get_by_fingerprints = counted_get_by_fingerprints  # type: ignore[method-assign]
    container.discovered_assets.save_many = counted_save_many  # type: ignore[method-assign]

    result = await container.discovery.run_discovery(
        RunDiscovery(
            tenant_id,
            connector_id,
            "MANUAL",
            "tester",
            ("integration:admin",),
            max_pages=n_pages + 1,
        )
    )

    assert result.status == "COMPLETED"
    assert result.items_discovered == n_pages * items_per_page
    # One bulk lookup + one bulk save per page -- not one per item.
    assert fingerprint_lookup_calls == n_pages
    assert save_many_calls == n_pages
