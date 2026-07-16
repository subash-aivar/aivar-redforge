"""Value objects for the Feed Synchronization Foundation sub-context —
M22 Phase 2.

This is the generic synchronization *platform* that future threat-intel
feed connectors (MITRE ATT&CK STIX bundle, CISA KEV JSON, EPSS CSV, NVD
incremental API, per-tenant STIX/TAXII pulls in M22 Phase 3+) register
against. Nothing here knows about STIX, TAXII, or any specific external
provider — `FeedSourceKind` is deliberately a closed set of *transport/
ingestion strategies*, not concrete provider names, so a Phase 3
connector plugs in by adding one enum value plus a
`FeedSyncExecutor` implementation registered in
`application.threat_intel.feed_connector.FeedConnectorRegistry` —
never by touching `Feed`, `FeedSyncRun`, or the orchestration service.

Enums are all StrEnum + @unique; VOs are frozen dataclasses with
`__post_init__` validation. Same conventions as
`reference_data_value_objects.py` (M22 Phase 1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum, unique

from redforge.domain.threat_intel.feed_exceptions import (
    InvalidFeedKeyError,
    InvalidRetryPolicyError,
    InvalidSyncScheduleError,
)

_FEED_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

#: Hard floor on the sync poll interval. Per the M22 Hardening Review
#: (Part 1, Background Workers / Part 8 Required Changes): an
#: admin-configurable poll frequency with no minimum floor lets a
#: misconfigured feed hammer an external endpoint or the database with
#: duplicate ingestion attempts. Generalized here from the review's
#: TAXII-specific recommendation ("1 hour recommended") to every feed
#: this platform will ever schedule — 5 minutes is generous enough for
#: legitimate near-real-time feeds while still being a real floor.
MIN_SYNC_INTERVAL_SECONDS = 300


@unique
class FeedSourceKind(StrEnum):
    """Closed set of feed ingestion *strategies* — never a free-text
    provider string, mirroring the exact invariant M18's `ProviderName`
    and M22 Phase 1's `ReferenceDataSource` already establish: a new
    concrete provider requires a new enum value plus a connector, never
    a caller-supplied string.

    Deliberately generic — no `STIX` or `TAXII`-specific business logic
    exists anywhere in Phase 2. These values describe *how* a future
    connector will fetch data, not *what* it fetches:

    - `STATIC_HTTP_DOWNLOAD` — one-shot bulk file fetch (e.g. the MITRE
      ATT&CK STIX bundle, the CISA KEV JSON feed, the EPSS CSV export).
    - `HTTP_API_INCREMENTAL` — paginated/incremental REST API pull with
      a resumable cursor (e.g. NVD's `lastModStartDate` API).
    - `STIX_TAXII_PULL` — TAXII 2.1 collection poll (M22 Phase 3+).
    - `MANUAL_UPLOAD` — an operator-supplied file/bundle with no
      scheduled network fetch at all (checkpoint is caller-supplied).
    """

    STATIC_HTTP_DOWNLOAD = "static_http_download"
    HTTP_API_INCREMENTAL = "http_api_incremental"
    STIX_TAXII_PULL = "stix_taxii_pull"
    MANUAL_UPLOAD = "manual_upload"


@unique
class FeedStatus(StrEnum):
    """`Feed` aggregate lifecycle. Transitions are enforced on the
    entity (`Feed.activate/pause/resume/disable`), never inferred from
    field mutation, mirroring `ConnectorStatus` (M18) /
    `InvestigationStatus` (M21).

    DRAFT   -> ACTIVE                         (activate)
    ACTIVE  -> PAUSED                          (pause)
    PAUSED  -> ACTIVE                          (resume)
    {DRAFT, ACTIVE, PAUSED} -> DISABLED        (disable)
    DISABLED is terminal — register a new Feed instead of reviving one,
    keeping the sync/audit history of a disabled feed unambiguous.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


@unique
class FeedSyncRunStatus(StrEnum):
    """`FeedSyncRun` lifecycle. PENDING/RUNNING are the only non-terminal
    states — the DB enforces at most one non-terminal run per feed via a
    partial unique index (see migration 0036), independent of and in
    addition to the application-level advisory lock."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@unique
class FeedSyncTrigger(StrEnum):
    """What initiated a `FeedSyncRun` — observability metadata, not a
    security boundary (both paths go through the same
    authorization-gated orchestration service call)."""

    SCHEDULED = "scheduled"
    MANUAL = "manual"


@dataclass(frozen=True, slots=True)
class FeedKey:
    """A stable, human-assigned business identifier for a `Feed` (e.g.
    `mitre_attack_enterprise`, `cisa_kev`), distinct from its ULID
    surrogate key. Lowercase snake_case, 3-64 characters — validated so
    it is safe to use in logs, advisory-lock key derivation, and URLs
    without further escaping."""

    value: str

    def __post_init__(self) -> None:
        if not _FEED_KEY_RE.match(self.value):
            raise InvalidFeedKeyError(self.value)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class SyncSchedule:
    """How often a `Feed` should be synchronized.

    `interval_seconds` must be at least `MIN_SYNC_INTERVAL_SECONDS` —
    there is no way to construct a `SyncSchedule` that bypasses the
    floor, closing the exact gap the Hardening Review flagged (Part 1:
    "TAXII pull frequency ... has no floor or circuit breaker
    defined").
    """

    interval_seconds: int

    def __post_init__(self) -> None:
        if self.interval_seconds < MIN_SYNC_INTERVAL_SECONDS:
            raise InvalidSyncScheduleError(
                f"interval_seconds must be >= {MIN_SYNC_INTERVAL_SECONDS} "
                f"(got {self.interval_seconds!r})"
            )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Retry/backoff configuration for one `Feed`'s sync executions.

    Field names and validation intentionally mirror
    `application.platform.retry_strategy.RetryConfig` exactly — this VO
    is the *persisted configuration*, converted to a `RetryConfig` by
    the orchestration service at execution time so the actual backoff
    math is implemented exactly once (`RetryExecutor`), never
    duplicated here.
    """

    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    jitter_factor: float = 0.25

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise InvalidRetryPolicyError("max_attempts must be >= 1")
        if self.base_delay_seconds < 0:
            raise InvalidRetryPolicyError("base_delay_seconds must be non-negative")
        if self.max_delay_seconds < self.base_delay_seconds:
            raise InvalidRetryPolicyError("max_delay_seconds must be >= base_delay_seconds")
        if not (0.0 <= self.jitter_factor <= 1.0):
            raise InvalidRetryPolicyError("jitter_factor must be in [0, 1]")
