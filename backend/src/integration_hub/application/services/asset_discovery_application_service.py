"""Sync engine: fetches paginated raw payloads via a connector plugin's
`discover` fn, normalizes them via the registered `INormalizer`, diffs
against persisted assets by fingerprint to classify CREATED/MODIFIED/
DELETED, persists in page-sized batches, checkpoints the run's cursor
after every page, and emits domain events.

Reuses the same `CircuitBreakerService` instance as
`IntegrationHubApplicationService` (health checks) — no separate
resilience mechanism invented. Each page fetch is retried with bounded
exponential backoff before being counted as a circuit-breaker failure.
"""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

import structlog

from integration_hub.application._auth import require_admin
from integration_hub.application.commands.discovery_commands import CancelDiscovery, RunDiscovery
from integration_hub.application.dtos.discovery_dtos import (
    AssetRelationshipDTO,
    DiscoveredAssetDTO,
    SyncRunDTO,
)
from integration_hub.application.exceptions import (
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from integration_hub.application.ports.credential_vault import ICredentialVaultPort
from integration_hub.application.services.normalizer_registry import NormalizerRegistry
from integration_hub.domain.aggregates.sync_run import SyncRun
from integration_hub.domain.events.discovery_events import SyncRunCompleted
from integration_hub.domain.services.circuit_breaker_service import CircuitBreakerService
from integration_hub.domain.value_objects.discovery import ChangeType, SyncMode, SyncRunStatus
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId, TenantId
from integration_hub.infrastructure.plugin_catalog import ConnectorPluginCatalog

logger = structlog.get_logger(__name__)

_RETRY_ATTEMPTS = 3
_RETRY_BASE_DELAY_SECONDS = 0.25


class AssetDiscoveryApplicationService:
    def __init__(
        self,
        assets: Any,
        sync_runs: Any,
        registrations: Any,
        catalog: ConnectorPluginCatalog,
        normalizers: NormalizerRegistry,
        event_sink: list[Any] | None = None,
        credential_service: ICredentialVaultPort | None = None,
        circuit: CircuitBreakerService | None = None,
    ) -> None:
        self._assets = assets
        self._sync_runs = sync_runs
        self._regs = registrations
        self._catalog = catalog
        self._normalizers = normalizers
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._credential_service = credential_service
        # Shared with IntegrationHubApplicationService when wired via the
        # container — one breaker per connector registration, tripped by
        # either health checks or discovery failures alike.
        self.circuit = circuit if circuit is not None else CircuitBreakerService()

    def _tenant(self, value: TenantId | UUID) -> EntityId:
        """Normalize either an already-canonical `TenantId` (=`EntityId`,
        the real shape at the API boundary via `Depends(tenant_id_header)`)
        or a raw `uuid.UUID` (still used positionally by a number of
        existing unit tests that construct commands directly) into one
        consistent `EntityId`.

        This used to unconditionally call `EntityId(value)`, which for an
        `EntityId` input silently double-wrapped it (breaking `==`/hashing)
        and for a raw `UUID` input built a `ULID`-typed slot holding a
        plain `UUID` object instead of a real `ULID` — internally
        self-consistent only because every call site funneled through the
        same wrong construction, but incompatible with an `EntityId` built
        the canonical way (`.generate()`/`.from_uuid()`) for the same
        value. Branching here keeps both call shapes correct and mutually
        consistent."""
        if isinstance(value, EntityId):
            return value
        return EntityId.from_uuid(value)

    def _asset_dto(self, asset: Any) -> DiscoveredAssetDTO:
        return DiscoveredAssetDTO(
            asset_id=str(asset.asset_id),
            tenant_id=str(asset.tenant_id),
            connector_id=str(asset.connector_id),
            external_id=asset.identity.external_id,
            name=asset.name,
            category=asset.category.value,
            vendor=asset.vendor.value,
            region=asset.region,
            owner=asset.owner,
            security_state=asset.security_state.value,
            compliance_state=asset.compliance_state.value,
            health_status=asset.health_status,
            risk_score=asset.risk_score.value,
            tags=dict(asset.tags),
            metadata=dict(asset.metadata),
            relationships=[
                AssetRelationshipDTO(
                    relationship_type=r.relationship_type.value,
                    target_external_id=r.target_external_id,
                    target_asset_id=r.target_asset_id,
                )
                for r in asset.relationships
            ],
            discovered_at=asset.discovered_at.isoformat(),
            last_synced_at=asset.last_synced_at.isoformat(),
        )

    def _sync_dto(self, run: SyncRun, *, has_more: bool = False) -> SyncRunDTO:
        return SyncRunDTO(
            sync_run_id=str(run.sync_run_id),
            connector_id=str(run.connector_id),
            mode=run.mode.value,
            status=run.status.value,
            started_at=run.started_at.isoformat(),
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
            items_discovered=run.items_discovered,
            items_created=run.items_created,
            items_updated=run.items_updated,
            items_deleted=run.items_deleted,
            error=run.error,
            cursor=run.cursor,
            pages_processed=run.pages_processed,
            has_more=has_more,
        )

    async def _resolve_secret(self, reg: Any, tenant_id: TenantId) -> str:
        if self._credential_service is None:
            raise ApplicationValidationError("credential vault is not wired")
        resolved = await self._credential_service.resolve(
            tenant_id=tenant_id,
            credential_id=UUID(reg.credential_ref.vault_key),
            principal_id=tenant_id,
            purpose="integration_hub.discovery",
        )
        secret: str = resolved.secret_value
        return secret

    async def _fetch_page_with_retry(
        self, plugin: Any, secret: str, config: dict[str, str], cursor: str | None
    ) -> Any:
        """Bounded exponential backoff around one page fetch. Raises the
        last exception if all attempts are exhausted."""
        last_exc: Exception | None = None
        for attempt in range(1, _RETRY_ATTEMPTS + 1):
            try:
                return await plugin.discover(secret, config, cursor)
            except Exception as exc:
                last_exc = exc
                if attempt < _RETRY_ATTEMPTS:
                    delay = _RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1))
                    logger.warning(
                        "integration_hub.discovery.retry_attempt",
                        connector_id=plugin.connector_id,
                        attempt=attempt,
                        max_attempts=_RETRY_ATTEMPTS,
                        delay_seconds=delay,
                        error=str(exc),
                    )
                    await asyncio.sleep(delay)
        assert last_exc is not None
        raise last_exc

    async def run_discovery(self, cmd: RunDiscovery) -> SyncRunDTO:
        require_admin(cmd.roles)
        tenant = self._tenant(cmd.tenant_id)
        connector_id = ConnectorId(cmd.connector_id)
        reg = await self._regs.get(connector_id, tenant)
        if reg is None:
            raise ApplicationNotFoundError("connector not found")
        reg.assert_executable()

        plugin = self._catalog.get(str(reg.connector_type))
        if plugin is None or plugin.discover is None:
            raise ApplicationValidationError(
                f"connector does not support discovery: {reg.connector_type}"
            )
        normalizer = self._normalizers.get(plugin.connector_id)
        if normalizer is None:
            raise ApplicationValidationError(
                f"no normalizer registered for connector: {plugin.connector_id}"
            )

        try:
            mode = SyncMode(cmd.mode)
        except ValueError as exc:
            raise ApplicationValidationError(f"invalid sync mode: {cmd.mode}") from exc

        # Concurrent-run guard: a clean ApplicationValidationError instead
        # of relying on an unhandled DB unique-constraint violation.
        running = await self._sync_runs.find_running_for_connector(connector_id, tenant)
        run: SyncRun
        if cmd.resume_sync_run_id is not None:
            existing = await self._sync_runs.get(cmd.resume_sync_run_id, tenant)
            if existing is None or existing.connector_id.value != connector_id.value:
                raise ApplicationNotFoundError("sync run not found for this connector")
            if existing.status not in (SyncRunStatus.PARTIAL, SyncRunStatus.RUNNING):
                raise ApplicationValidationError(
                    f"sync run {cmd.resume_sync_run_id} is not resumable "
                    f"(status={existing.status.value})"
                )
            run = existing
            run.status = SyncRunStatus.RUNNING
        else:
            if running is not None:
                raise ApplicationValidationError(
                    f"a discovery run is already in progress for connector "
                    f"{cmd.connector_id} (sync_run_id={running.sync_run_id})"
                )
            run = SyncRun.start(tenant, connector_id, mode)
        await self._sync_runs.save(run, tenant)

        if not self.circuit.allow_request(reg):
            run.fail("circuit breaker open — connector has too many recent failures")
            await self._sync_runs.save(run, tenant)
            logger.warning(
                "integration_hub.discovery.circuit_open",
                connector_id=str(cmd.connector_id),
                tenant_id=str(tenant),
            )
            raise ApplicationValidationError(
                "connector circuit breaker is open — too many recent failures"
            )

        secret = await self._resolve_secret(reg, cmd.tenant_id)
        config = {k: str(v) for k, v in (reg.configuration or {}).items()}

        logger.info(
            "integration_hub.discovery.start",
            connector_id=str(cmd.connector_id),
            tenant_id=str(tenant),
            sync_run_id=str(run.sync_run_id),
            resumed=cmd.resume_sync_run_id is not None,
            cursor=run.cursor,
        )

        cursor = run.cursor
        has_more = True
        pages_this_invocation = 0

        while has_more and pages_this_invocation < cmd.max_pages:
            # Cancellation is checked against the persisted flag (via the
            # repository), not a local in-memory object reference, so an
            # out-of-process cancel request (see cancel_discovery) takes
            # effect between pages of this same run.
            fresh = await self._sync_runs.get(run.sync_run_id, tenant)
            if fresh is not None and fresh.cancelled:
                run.cancelled = True
                logger.info(
                    "integration_hub.discovery.cancelled",
                    connector_id=str(cmd.connector_id),
                    sync_run_id=str(run.sync_run_id),
                )
                break

            try:
                page = await self._fetch_page_with_retry(plugin, secret, config, cursor)
            except Exception as exc:
                self.circuit.record_failure(reg)
                await self._regs.save(reg, tenant)
                logger.error(
                    "integration_hub.discovery.sync_failed",
                    connector_id=str(cmd.connector_id),
                    sync_run_id=str(run.sync_run_id),
                    pages_processed=run.pages_processed,
                    error=str(exc),
                )
                if run.pages_processed > 0:
                    # Partial success: at least one page was already
                    # persisted, so this is resumable, not a hard failure.
                    run.mark_partial(str(exc))
                    await self._sync_runs.save(run, tenant)
                    return self._sync_dto(run, has_more=True)
                run.fail(str(exc))
                await self._sync_runs.save(run, tenant)
                raise ApplicationValidationError(f"discovery failed: {exc}") from exc

            self.circuit.record_success(reg)
            await self._regs.save(reg, tenant)

            # Re-check cancellation immediately before we do our own
            # save() below: an external cancel_discovery() call could have
            # landed (and persisted) while the page fetch above was in
            # flight, and this run's own upcoming save() must not clobber
            # that flag by writing back a stale `run.cancelled=False`.
            fresh_after_fetch = await self._sync_runs.get(run.sync_run_id, tenant)
            if fresh_after_fetch is not None and fresh_after_fetch.cancelled:
                run.cancelled = True

            page_created = page_updated = 0
            normalized_items = [
                normalizer.normalize(raw, tenant_id=tenant, connector_id=connector_id)
                for raw in page.items
            ]
            fingerprints = [n.identity.fingerprint for n in normalized_items]

            # Bulk fingerprint lookup + bulk save: one round trip each per
            # page instead of one per item, so DB call count stays O(pages)
            # rather than O(items) across the whole run.
            existing_by_fp = await self._assets.get_by_fingerprints(fingerprints, tenant)
            to_save = []
            for normalized in normalized_items:
                fp = normalized.identity.fingerprint
                existing = existing_by_fp.get(fp)
                if existing is None:
                    to_save.append(normalized)
                    self._events.extend(normalized.pop_events())
                    page_created += 1
                else:
                    change = existing.apply_sync(
                        name=normalized.name,
                        region=normalized.region,
                        owner=normalized.owner,
                        tags=normalized.tags,
                        metadata=normalized.metadata,
                        configuration=normalized.configuration,
                    )
                    to_save.append(existing)
                    self._events.extend(existing.pop_events())
                    if change != ChangeType.UNCHANGED:
                        page_updated += 1
            await self._assets.save_many(to_save, tenant)

            cursor = page.next_cursor
            has_more = page.has_more
            pages_this_invocation += 1
            run.record_page(
                cursor=cursor,
                discovered=len(page.items),
                created=page_created,
                updated=page_updated,
            )
            await self._sync_runs.save(run, tenant)
            logger.info(
                "integration_hub.discovery.page_complete",
                connector_id=str(cmd.connector_id),
                sync_run_id=str(run.sync_run_id),
                page=run.pages_processed,
                items_in_page=len(page.items),
                has_more=has_more,
            )

        if has_more and not run.cancelled:
            # Hit the per-invocation max-pages safety limit with more
            # pages remaining — leave PARTIAL/resumable rather than
            # blocking this request indefinitely.
            run.mark_partial()
            await self._sync_runs.save(run, tenant)
            logger.info(
                "integration_hub.discovery.partial",
                connector_id=str(cmd.connector_id),
                sync_run_id=str(run.sync_run_id),
                pages_processed=run.pages_processed,
            )
            return self._sync_dto(run, has_more=True)

        deleted = 0
        if not run.cancelled:
            # Deletion detection only applies once the run has actually
            # walked every page (has_more is False) — a partial run must
            # not delete assets it hasn't seen yet.
            #
            # Deliberately NOT based on an in-memory `seen_fingerprints`
            # set: a resumed run spans multiple invocations of this
            # method (see `resume_sync_run_id`), each with its own fresh
            # local `seen_fingerprints`, so a set built only from *this*
            # invocation's pages would wrongly look like "not seen" for
            # every asset processed in an earlier invocation and delete
            # it. Every asset actually touched by any page of this run
            # (across every invocation) had its `last_synced_at` bumped
            # to "now" at the time it was normalized+saved, and `now` is
            # always >= the run's `started_at` (which never changes on
            # resume) — so "not touched this run" is equivalent to
            # "last_synced_at is still older than this run started".
            existing_assets = await self._assets.find_all_for_connector(connector_id, tenant)
            for asset in existing_assets:
                if asset.last_synced_at < run.started_at:
                    asset.mark_removed()
                    self._events.extend(asset.pop_events())
                    await self._assets.delete(asset.asset_id, tenant)
                    deleted += 1

        run.complete(
            discovered=run.items_discovered,
            created=run.items_created,
            updated=run.items_updated,
            deleted=deleted,
        )
        await self._sync_runs.save(run, tenant)
        logger.info(
            "integration_hub.discovery.sync_complete",
            connector_id=str(cmd.connector_id),
            sync_run_id=str(run.sync_run_id),
            status=run.status.value,
            items_discovered=run.items_discovered,
            items_created=run.items_created,
            items_updated=run.items_updated,
            items_deleted=deleted,
        )
        self._events.append(
            SyncRunCompleted(
                tenant_id=str(tenant),
                aggregate_id=str(run.sync_run_id),
                sync_run_id=str(run.sync_run_id),
                connector_id=str(cmd.connector_id),
                items_discovered=run.items_discovered,
                items_created=run.items_created,
                items_updated=run.items_updated,
                items_deleted=deleted,
                completed_at=run.completed_at.isoformat() if run.completed_at else "",
            )
        )
        return self._sync_dto(run, has_more=False)

    async def cancel_discovery(self, cmd: CancelDiscovery) -> SyncRunDTO:
        require_admin(cmd.roles)
        tenant = self._tenant(cmd.tenant_id)
        run = await self._sync_runs.get(cmd.sync_run_id, tenant)
        if run is None or run.connector_id.value != cmd.connector_id:
            raise ApplicationNotFoundError("sync run not found for this connector")
        if run.status not in (SyncRunStatus.RUNNING,):
            raise ApplicationValidationError(
                f"sync run {cmd.sync_run_id} is not running (status={run.status.value})"
            )
        run.request_cancel()
        await self._sync_runs.save(run, tenant)
        logger.info(
            "integration_hub.discovery.cancel_requested",
            connector_id=str(cmd.connector_id),
            sync_run_id=str(cmd.sync_run_id),
        )
        return self._sync_dto(run)

    async def list_sync_runs(
        self, tenant_id: TenantId, connector_id: UUID, roles: tuple[str, ...], limit: int = 20
    ) -> list[SyncRunDTO]:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        rows = await self._sync_runs.find_for_connector(
            ConnectorId(connector_id), self._tenant(tenant_id), limit
        )
        return [self._sync_dto(r) for r in rows]

    async def list_assets(
        self,
        tenant_id: TenantId,
        roles: tuple[str, ...],
        *,
        category: str | None = None,
        vendor: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "-discovered_at",
    ) -> list[DiscoveredAssetDTO]:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        rows = await self._assets.find_all_for_tenant(
            self._tenant(tenant_id),
            category=category,
            vendor=vendor,
            tag=tag,
            limit=limit,
            offset=offset,
            order_by=order_by,
        )
        return [self._asset_dto(a) for a in rows]

    async def get_asset(
        self, tenant_id: TenantId, asset_id: UUID, roles: tuple[str, ...]
    ) -> DiscoveredAssetDTO:
        if "integration:admin" not in roles and "playbook:analyst" not in roles:
            require_admin(roles)
        asset = await self._assets.get(asset_id, self._tenant(tenant_id))
        if asset is None:
            raise ApplicationNotFoundError("asset not found")
        return self._asset_dto(asset)

    async def list_relationships(
        self, tenant_id: TenantId, asset_id: UUID, roles: tuple[str, ...]
    ) -> list[AssetRelationshipDTO]:
        dto = await self.get_asset(tenant_id, asset_id, roles)
        return list(dto.relationships)
