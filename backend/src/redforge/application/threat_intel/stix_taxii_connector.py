"""STIX/TAXII feed connector — M22 Phase 3 (STIX/TAXII Integration).

The single `FeedSyncExecutor` this phase adds. Registered against
`FeedSourceKind.STIX_TAXII_PULL` in `app.py`'s
`_start_feed_sync_scheduler` startup hook — see
`feed_connector.FeedConnectorRegistry`'s own module docstring for the
exact two-step "implement + register" contract this class fulfills.
Nothing in `feed_sync_orchestration_service.py` or `feed_sync_worker.py`
changed to accommodate it: this is a pure Protocol implementation
plugged in from the outside, exactly as the architecture freeze's
plug-in-seam requirement and the M22 Phase 2 report's Decision 6
describe.

One `execute()` call performs exactly one bounded, best-effort
synchronization attempt:

  1. Validate `context.connector_config` (fails fast, before any
     network call, on a misconfigured feed).
  2. Resolve credentials (if any) via `context.credential_ref` and
     build a `TaxiiAuth`.
  3. Resolve the TAXII API root — either given directly
     (`connector_config["api_root_url"]`) or discovered
     (`connector_config["discovery_url"]`).
  4. Confirm the configured collection exists and is readable.
  5. Page through `/objects/`, using `context.checkpoint` as the
     `added_after` incremental cursor, applying the exact same
     object-count/nesting-depth validation gate
     (`stix_parser.validate_object_list`) to every page that a raw
     STIX bundle file would go through — a TAXII server is exactly as
     untrusted as any other STIX source, and this is the "STIX bundle
     validation" and "TAXII envelope validation" requirements sharing
     one implementation rather than two.
  6. Parse every validated object into its typed dataclass
     (`stix_parser.parse_object`), skipping (and counting) any
     malformed object of an otherwise-supported type; silently
     skipping (never counting as failed) any unsupported STIX type.
  7. Map the accumulated batch into `ReferenceDataAdminService` input
     DTOs (`stix_reference_data_mapper.map_stix_objects`).
  8. Upsert tactics, then techniques, then relationships, then
     vulnerabilities, in that dependency order — techniques reference
     tactics by id and relationships reference techniques by id, and
     `ReferenceDataAdminService` validates those references against
     what has already been committed.
  9. Return a `FeedSyncOutcome` whose `checkpoint` is the wall-clock
     time this attempt *started* — never a value derived from any
     object inside the response. Any object added to the TAXII
     collection between that instant and the moment the server
     actually executes the query is deliberately re-fetched (and
     harmlessly re-upserted — every upsert path here is content-hash
     idempotent, per `ReferenceDataAdminService`) on the *next*
     attempt, rather than risk it being skipped forever by a
     checkpoint that raced ahead of it.

Every raised exception (bad config, SSRF-unsafe URL, oversized/
malformed container, TAXII 4xx/5xx) is a plain, undecorated raise — no
internal retry loop — per `FeedSyncExecutor`'s own contract:
`FeedSyncOrchestrationService` wraps this call with `RetryExecutor`
using the feed's configured `RetryPolicy`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.application.threat_intel.feed_connector import FeedSyncContext, FeedSyncOutcome
from redforge.application.threat_intel.reference_data_admin_service import (
    ReferenceDataAdminService,
)
from redforge.application.threat_intel.stix_reference_data_mapper import (
    StixMappingResult,
    map_stix_objects,
)
from redforge.core.exceptions import ValidationError
from redforge.domain.threat_intel.reference_data_value_objects import ReferenceDataSource
from redforge.domain.threat_intel.stix_exceptions import MalformedStixObjectError
from redforge.domain.threat_intel.stix_objects import StixParsedObject
from redforge.domain.threat_intel.stix_parser import parse_object, validate_object_list
from redforge.infrastructure.threat_intel.taxii_client import TaxiiAuth, TaxiiClient

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.contracts import CredentialResolverPort
    from redforge.application.platform.runtime_contracts import MetricsCollector

log = logging.getLogger(__name__)

#: Defense in depth against a misbehaving or malicious TAXII server
#: that keeps returning `more: true` forever. `DEFAULT_PAGE_LIMIT`
#: (500, see `taxii_client.py`) x this many pages is comfortably above
#: the current MITRE ATT&CK Enterprise object count (~10-15k objects
#: including relationships) while still being a hard, enforced
#: ceiling — never "however many pages the server feels like sending".
MAX_PAGES_PER_SYNC_ATTEMPT = 100

#: Total-objects ceiling across every page of one sync attempt —
#: independent of, and in addition to, `stix_parser`'s existing
#: per-page `MAX_OBJECTS_PER_CONTAINER` cap. Guards against a server
#: that honors the `limit` param per-page but never sets `more: false`.
MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT = 50_000

_VALID_AUTH_SCHEMES = frozenset({"none", "basic", "bearer"})


class TaxiiConnectorConfigError(ValidationError):
    """A `Feed.connector_config` for `FeedSourceKind.STIX_TAXII_PULL`
    is missing a required key or holds an invalid value, or the
    configured collection/credential does not permit reading it.
    Always a misconfiguration on the admin's side, never a transient
    TAXII server or network failure."""


class TaxiiSyncAttemptTooLargeError(ValidationError):
    """The TAXII collection returned more pages or objects in a single
    sync attempt than `MAX_PAGES_PER_SYNC_ATTEMPT` /
    `MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT` allow — defense against a
    misbehaving or malicious server that never signals completion."""


@dataclass(frozen=True, slots=True)
class _ResolvedConfig:
    discovery_url: str | None
    api_root_url: str | None
    collection_id: str
    auth_scheme: str
    auth_username: str | None
    page_limit: int


def _resolve_config(connector_config: dict[str, Any]) -> _ResolvedConfig:
    """Validate and normalize `Feed.connector_config` for
    `FeedSourceKind.STIX_TAXII_PULL`. Raises `TaxiiConnectorConfigError`
    on any missing/invalid key — deliberately fails before any network
    call, never guessing a default for a security-relevant setting
    (auth scheme, collection id)."""
    collection_id = connector_config.get("collection_id")
    if not isinstance(collection_id, str) or not collection_id.strip():
        raise TaxiiConnectorConfigError("connector_config.collection_id is required")

    discovery_url = connector_config.get("discovery_url")
    api_root_url = connector_config.get("api_root_url")
    has_discovery = isinstance(discovery_url, str) and bool(discovery_url.strip())
    has_api_root = isinstance(api_root_url, str) and bool(api_root_url.strip())
    if not has_discovery and not has_api_root:
        raise TaxiiConnectorConfigError(
            "connector_config must set either 'discovery_url' or 'api_root_url'"
        )

    auth_scheme = connector_config.get("auth_scheme", "none")
    if auth_scheme not in _VALID_AUTH_SCHEMES:
        raise TaxiiConnectorConfigError(
            f"connector_config.auth_scheme must be one of "
            f"{sorted(_VALID_AUTH_SCHEMES)}, got {auth_scheme!r}"
        )

    auth_username = connector_config.get("auth_username")
    if auth_scheme == "basic" and not (
        isinstance(auth_username, str) and auth_username.strip()
    ):
        raise TaxiiConnectorConfigError(
            "connector_config.auth_username is required when auth_scheme is 'basic'"
        )

    page_limit = connector_config.get("page_limit", 500)
    if not isinstance(page_limit, int) or isinstance(page_limit, bool) or page_limit <= 0:
        raise TaxiiConnectorConfigError("connector_config.page_limit must be a positive integer")

    return _ResolvedConfig(
        discovery_url=discovery_url if has_discovery else None,
        api_root_url=api_root_url if has_api_root else None,
        collection_id=collection_id.strip(),
        auth_scheme=auth_scheme,
        auth_username=auth_username.strip() if isinstance(auth_username, str) else None,
        page_limit=page_limit,
    )


def _build_auth(
    config: _ResolvedConfig,
    *,
    credential_ref: str | None,
    credential_resolver: CredentialResolverPort,
) -> TaxiiAuth:
    if config.auth_scheme == "none":
        return TaxiiAuth.none()

    if not credential_ref:
        raise TaxiiConnectorConfigError(
            f"feed.credential_ref is required when auth_scheme is {config.auth_scheme!r}"
        )
    secret = credential_resolver.resolve(credential_ref)

    if config.auth_scheme == "basic":
        return TaxiiAuth(scheme="basic", username=config.auth_username, secret=secret)
    return TaxiiAuth(scheme="bearer", secret=secret)


class StixTaxiiFeedConnector:
    """`FeedSyncExecutor` for `FeedSourceKind.STIX_TAXII_PULL`.

    Stateless across calls except for its injected collaborators
    (`session_factory`, `credential_resolver`, `metrics`, `taxii_client`)
    — every piece of per-attempt state lives in local variables inside
    `execute()`, so one connector instance is safely shared across
    every `Feed` of this `source_kind` (registered once, in
    `app.py`, against the shared `FeedConnectorRegistry`).

    `taxii_client` and `admin_service` are both injectable purely for
    deterministic unit testing (a fake TAXII transport / a fake
    admin-service double) without a real network or database —
    production wiring (`app.py`) always leaves both at their default.
    """

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        credential_resolver: CredentialResolverPort,
        metrics: MetricsCollector,
        taxii_client: TaxiiClient | None = None,
        admin_service: ReferenceDataAdminService | None = None,
    ) -> None:
        self._admin_service = admin_service or ReferenceDataAdminService(session_factory)
        self._credential_resolver = credential_resolver
        self._metrics = metrics
        self._taxii_client = taxii_client or TaxiiClient()

    async def execute(self, context: FeedSyncContext) -> FeedSyncOutcome:
        attempt_started_at = datetime.now(UTC)

        config = _resolve_config(context.connector_config)
        auth = _build_auth(
            config,
            credential_ref=context.credential_ref,
            credential_resolver=self._credential_resolver,
        )

        api_root_url = await self._resolve_api_root(config, auth=auth)

        collection = await self._taxii_client.get_collection(
            api_root_url, config.collection_id, auth=auth
        )
        if not collection.can_read:
            raise TaxiiConnectorConfigError(
                f"TAXII collection {config.collection_id!r} is not readable "
                "by the configured credential"
            )

        parsed_objects, items_fetched, parse_failures = await self._fetch_and_parse_all(
            api_root_url=api_root_url,
            config=config,
            auth=auth,
            added_after=context.checkpoint,
        )

        mapping = map_stix_objects(parsed_objects)
        items_processed, upsert_failures = await self._upsert_all(context=context, mapping=mapping)
        items_failed = parse_failures + mapping.unmapped_count + upsert_failures

        self._record_metrics(
            context=context,
            items_fetched=items_fetched,
            items_processed=items_processed,
            items_failed=items_failed,
        )
        log.info(
            "StixTaxiiFeedConnector: feed_id=%s collection=%s "
            "items_fetched=%d items_processed=%d items_failed=%d",
            context.feed_id,
            config.collection_id,
            items_fetched,
            items_processed,
            items_failed,
        )

        return FeedSyncOutcome(
            checkpoint=attempt_started_at.isoformat(),
            items_fetched=items_fetched,
            items_processed=items_processed,
            items_failed=items_failed,
        )

    async def _resolve_api_root(self, config: _ResolvedConfig, *, auth: TaxiiAuth) -> str:
        if config.api_root_url is not None:
            return config.api_root_url

        assert config.discovery_url is not None  # enforced by `_resolve_config`
        discovery = await self._taxii_client.get_discovery(config.discovery_url, auth=auth)
        api_root_url = discovery.default or (
            discovery.api_roots[0] if discovery.api_roots else None
        )
        if api_root_url is None:
            raise TaxiiConnectorConfigError(
                f"TAXII discovery at {config.discovery_url!r} advertised no api_roots"
            )
        return api_root_url

    async def _fetch_and_parse_all(
        self,
        *,
        api_root_url: str,
        config: _ResolvedConfig,
        auth: TaxiiAuth,
        added_after: str | None,
    ) -> tuple[list[StixParsedObject], int, int]:
        """Page through the configured collection's `/objects/`
        endpoint until the server signals completion (`more: false`)
        or a safety ceiling is hit, validating and parsing every page
        as it arrives rather than buffering raw pages before
        validation."""
        parsed_objects: list[StixParsedObject] = []
        items_fetched = 0
        items_failed = 0
        next_cursor: str | None = None

        for _page_index in range(MAX_PAGES_PER_SYNC_ATTEMPT):
            envelope = await self._taxii_client.get_objects(
                api_root_url,
                config.collection_id,
                auth=auth,
                added_after=added_after,
                limit=config.page_limit,
                next_cursor=next_cursor,
            )
            raw_objects = validate_object_list(list(envelope.objects))
            items_fetched += len(raw_objects)
            if items_fetched > MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT:
                raise TaxiiSyncAttemptTooLargeError(
                    f"TAXII collection {config.collection_id!r} exceeded "
                    f"{MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT} objects across the "
                    "pages fetched in a single sync attempt"
                )

            for raw_obj in raw_objects:
                try:
                    parsed = parse_object(raw_obj)
                except MalformedStixObjectError:
                    log.warning(
                        "StixTaxiiFeedConnector: skipping malformed STIX object "
                        "id=%r in collection=%s",
                        raw_obj.get("id"),
                        config.collection_id,
                    )
                    items_failed += 1
                    continue
                if parsed is not None:
                    parsed_objects.append(parsed)

            if not envelope.more or envelope.next is None:
                break
            next_cursor = envelope.next
        else:
            raise TaxiiSyncAttemptTooLargeError(
                f"TAXII collection {config.collection_id!r} did not signal "
                f"completion within {MAX_PAGES_PER_SYNC_ATTEMPT} pages"
            )

        return parsed_objects, items_fetched, items_failed

    async def _upsert_all(
        self, *, context: FeedSyncContext, mapping: StixMappingResult
    ) -> tuple[int, int]:
        """Upsert every mapped list, in dependency order, via the
        Phase 1 `ReferenceDataAdminService` — the one and only write
        path into the reference-data model. Returns
        `(items_processed, items_failed)` aggregated across all four
        object types.

        `actor_id` for these audit entries is the triggering `feed_id`
        itself: `platform_audit_log.actor_id` is `VARCHAR(26)` — the
        exact width of a ULID — so it cannot hold a human-readable
        prefixed string once a 26-character `feed_id` is appended
        (`FeedSyncContext` carries no separate human/system actor
        identity to fall back to; extending it would mean modifying
        Phase 2's synchronization framework, which is out of scope).
        The raw `feed_id` is itself a real, unique, directly-queryable
        identity — every ingestion batch this connector produces is
        still exactly traceable back to the one `Feed` that triggered
        it via `feeds.id`.
        """
        actor_id = context.feed_id
        processed = 0
        failed = 0

        if mapping.tactics:
            result = await self._admin_service.upsert_tactics(
                actor_id=actor_id, tactics=mapping.tactics
            )
            processed += result.created + result.updated + result.unchanged
            failed += result.failed

        if mapping.techniques:
            result = await self._admin_service.upsert_techniques(
                actor_id=actor_id, techniques=mapping.techniques
            )
            processed += result.created + result.updated + result.unchanged
            failed += result.failed

        if mapping.relationships:
            result = await self._admin_service.upsert_technique_relationships(
                actor_id=actor_id, relationships=mapping.relationships
            )
            processed += result.created + result.updated + result.unchanged
            failed += result.failed

        if mapping.vulnerabilities:
            result = await self._admin_service.upsert_vulnerabilities(
                actor_id=actor_id,
                vulnerabilities=mapping.vulnerabilities,
                source_system=ReferenceDataSource.STIX_TAXII_FEED,
            )
            processed += result.created + result.updated + result.unchanged
            failed += result.failed

        return processed, failed

    def _record_metrics(
        self,
        *,
        context: FeedSyncContext,
        items_fetched: int,
        items_processed: int,
        items_failed: int,
    ) -> None:
        labels = {"feed_id": context.feed_id, "feed_key": context.feed_key}
        self._metrics.record_counter(
            "threat_intel.stix_taxii.items_fetched", float(items_fetched), labels
        )
        self._metrics.record_counter(
            "threat_intel.stix_taxii.items_processed", float(items_processed), labels
        )
        self._metrics.record_counter(
            "threat_intel.stix_taxii.items_failed", float(items_failed), labels
        )
