# M22 Phase 3 — STIX/TAXII Integration: Implementation Report

**Status**: COMPLETE (Phase 3 of 7 only — Phases 4-7 explicitly out of scope, not started)
**Date**: 2026-07-16
**Migration head**: `0036` (unchanged — Phase 3 required no schema change)
**Commit status**: NOT COMMITTED, NOT PUSHED — awaiting review per explicit instruction.

---

## 1. Scope

This phase implements the **first real feed connector** for the M22 feed-synchronization platform:
a TAXII 2.1 client and STIX 2.1 parser/mapper that plug into Phase 2's `FeedSyncExecutor` /
`FeedConnectorRegistry` seam without any change to Phase 2's orchestration, locking, retry, or
scheduling logic.

**Implemented** (per the approved brief):

- TAXII 2.1 client — discovery, collection listing/reading, paginated object retrieval, Basic/Bearer
  authentication, explicit SSRF defenses for admin-configurable endpoint URLs.
- Incremental synchronization using Phase 2's opaque `checkpoint` mechanism (the TAXII `added_after`
  query parameter, populated from the attempt's own start time — never a value read back from the
  remote server).
- STIX 2.1 parsing and validation — a custom, lightweight parser (no third-party `stix2` library) with
  byte-size, object-count, and nesting-depth caps.
- Mapping of 4 supported STIX object types (`attack-pattern`, `x-mitre-tactic`, `relationship`,
  `vulnerability`) into the Phase 1 reference-data model, via a dedicated application-layer ACL
  mapper — no direct STIX→ORM coupling anywhere.
- `StixTaxiiFeedConnector`, a concrete `FeedSyncExecutor` implementation, registered against
  `FeedSourceKind.STIX_TAXII_PULL` in production wiring (`app.py`).
- Robust error handling (dedicated STIX/TAXII exception hierarchies), retry integration (reuses
  Phase 2's `FeedSyncOrchestrationService` retry loop — no new retry/backoff code), structured
  logging, metrics (via the existing `MetricsCollector` abstraction), audit events (via Phase 1's
  `ReferenceDataAdminService`, unchanged), and per-feed `connector_config`-driven configuration.
- Tests — domain unit tests, application-layer unit tests, infrastructure unit tests, and PostgreSQL
  integration tests (including a genuine end-to-end run through `FeedSyncOrchestrationService`).

**Explicitly NOT implemented** (deferred to later M22 phases, per instruction):

- Threat Fusion Engine
- Attack Path Engine
- Investigation-context integration
- Frontend
- Any change to Phase 2's synchronization framework (`FeedSyncOrchestrationService`,
  `FeedAdminService`, `FeedQueryService`, the scheduler worker, or migration `0036`)
- STIX object types beyond the 4 listed above (`indicator`, `malware`, `campaign`,
  `intrusion-set`, `course-of-action`, `identity`, etc. are structurally unsupported — the parser
  recognizes them as valid STIX but the mapper does not translate them, since the Phase 1
  reference-data model has no aggregate for them yet)

---

## 2. Architecture Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **A custom, lightweight STIX parser — not the third-party `stix2` library.** | The M22 Hardening Review's P0 finding: a general-purpose STIX object-graph library is designed to resolve and hold an entire bundle's object graph in memory, which is a DoS vector against an admin-configurable, externally-fetched payload. The custom parser (`stix_parser.py`) validates raw byte length, JSON-decodes defensively (catching `RecursionError` from adversarially nested JSON), enforces `MAX_OBJECTS_PER_CONTAINER` and `MAX_NESTING_DEPTH` caps, and only then dispatches each object to a narrow, type-specific parser function that reads a small, fixed set of fields — never a generic graph walk. |
| 2 | **SSRF defense via dynamic DNS-resolution + IP-classification, not a static host allowlist.** | The existing `ThreatIntelHttpClient`'s `_ALLOWED_HOSTS` pattern is unusable here — a TAXII endpoint is an admin-configured, per-feed URL (`connector_config.api_root_url`/`discovery_url`), not a fixed set of known-good hosts. `taxii_client.py`'s `validate_ssrf_safe()` instead: (a) rejects any non-`https` scheme outright, (b) resolves the hostname via DNS and classifies every resolved address, rejecting loopback/link-local/private/multicast/reserved/cloud-metadata ranges (reusing the existing `is_public_ip()` classifier from `infrastructure/threat_intel/ip_classification.py`, not a second implementation), (c) never follows redirects (`httpx.Client(follow_redirects=False)`, so a benign-looking initial host cannot redirect to an internal one post-validation), and (d) caps every response body size before it is ever fully buffered. |
| 3 | **STIX `external_references[].url` fields are treated as inert text metadata, never fetched or resolved.** | The Hardening Review's P1 finding: an `attack-pattern` or `vulnerability` object's `external_references` array can carry arbitrary attacker-influenced URLs (e.g. a malicious CTI feed embedding a link to an internal service). Neither the parser (`stix_parser.py`) nor the mapper (`stix_reference_data_mapper.py`) ever issues an HTTP request against any URL found inside a STIX object body — only the connector's own `api_root_url`/`discovery_url` (explicit, admin-configured, SSRF-validated) is ever dereferenced. `_find_external_url()` in the mapper reads the string purely for storage as `Vulnerability.reference_url`, never as a fetch target. |
| 4 | **A three-layer Anti-Corruption Layer between the STIX wire format and the RedForge domain model.** | The Hardening Review's P1 finding (no ACL was defined between the STIX object model and the RedForge domain model). Layer 1 (`domain/threat_intel/stix_parser.py`, domain layer): raw JSON → flat, validated STIX dataclasses (`stix_objects.py`) — knows only STIX shape, nothing about ATT&CK/CVE. Layer 2 (`application/threat_intel/stix_reference_data_mapper.py`, application layer): STIX dataclasses → Phase 1's existing `TacticInput`/`TechniqueInput`/`RelationshipInput`/`VulnerabilityInput` DTOs — the one place STIX vocabulary (`kill_chain_phases`, `external_references`, `x_mitre_*` custom properties) is translated into ATT&CK/CVE vocabulary. Layer 3 (`application/threat_intel/stix_taxii_connector.py`): orchestrates fetch → parse → map → upsert, calling the *existing, unmodified* Phase 1 `ReferenceDataAdminService` for every write — Phase 3 adds zero new persistence code for reference data. |
| 5 | **`StixTaxiiFeedConnector` is the only production `FeedSyncExecutor` registered, against exactly `FeedSourceKind.STIX_TAXII_PULL`.** | Confirms Phase 2's Decision 6 (the registry/Protocol seam) works exactly as designed: no change was needed anywhere in `feed_connector.py`, `feed_sync_orchestration_service.py`, `feed_admin_service.py`, `feed_query_service.py`, the scheduler worker, or migration `0036` to add this connector. Every other `FeedSourceKind` (`STATIC_HTTP_DOWNLOAD`, `HTTP_API_INCREMENTAL`, `MANUAL_UPLOAD`) remains unregistered and continues to fail honestly with `UnknownFeedConnectorError` — proven directly in the PostgreSQL integration suite (`TestNoArchitectureRegression`). |
| 6 | **Incremental sync checkpoint is the *server-local* attempt-start timestamp, never a value echoed back by the remote TAXII server.** | TAXII 2.1's `added_after` filter is a request parameter, not a response field — there is no cursor the server hands back to persist. Using `context` (`checkpoint_before`, from Phase 2) as the `added_after` value for *this* attempt, and the wall-clock time this attempt started as the *next* attempt's checkpoint, is the standard "since last successful poll" pattern and avoids ever trusting attacker-influenced response content as sync-progress state. This is checked explicitly in `test_checkpoint_is_the_attempt_start_time_not_a_value_from_the_response` and the PG suite's `TestIncrementalSynchronization`. |
| 7 | **`actor_id` for `ReferenceDataAdminService` audit calls is the raw `feed_id`, not a synthetic prefixed string.** | `platform_audit_log.actor_id` is `VARCHAR(26)` — exactly the width of a ULID (confirmed against migration history; Phase 2's own `_SCHEDULER_ACTOR_ID = "system:feed_sync_scheduler"` is exactly 26 characters, evidently sized deliberately). `FeedSyncContext` (Phase 2, unmodified) carries no separate triggering-actor identity for the connector to reuse, and extending it would mean modifying Phase 2's synchronization framework — out of scope. Using the bare `feed_id` (already a 26-character ULID) fits the column exactly and remains a real, unique, directly-queryable identity — every ingestion batch this connector produces is still exactly traceable back to the one `Feed` that triggered it. An earlier draft used a `"system:stix_taxii_connector:" + feed_id` prefix, which overflowed the column and was caught by the PostgreSQL integration suite (`StringDataRightTruncationError`) before this report was written — see §7. |
| 8 | **`ReferenceDataSource.STIX_TAXII_FEED` is an additive enum value on an existing, unmodified Python `StrEnum`.** | `reference_data_ingestion.source_system`/`vulnerabilities.source_system` are plain `VARCHAR` columns (migration `0035`), not a database `ENUM` type — confirmed by reading the migration directly before making this change. Adding a new member is therefore a zero-migration, purely additive Python-level change; it exists so vulnerability records ingested via a generic STIX/TAXII collection are never misattributed to `NVD_CVE` (a feed that was not actually queried). |
| 9 | **Object-count and nesting-depth validation is shared, not duplicated, between raw STIX bundles and already-JSON-decoded TAXII envelopes.** | A TAXII `GET /collections/{id}/objects` response is `{"objects": [...], "more": bool}` — already valid JSON by the time `httpx` decodes it, so re-serializing it to bytes just to re-run `load_stix_container()`'s byte-level checks would be wasteful and would duplicate the count/depth logic in two places. `stix_parser.py` exposes `validate_object_list()` (object-count cap + nesting-depth cap only, no byte/JSON-decode step) as the single function both `load_stix_container()` (raw bundle path) and `StixTaxiiFeedConnector._fetch_and_parse_all()` (TAXII envelope path) call. |

---

## 3. Repository-First Research (what was read before writing code)

Per instruction, the following were read completely before any code was written:

- `docs/architecture/m22/m22_architecture_freeze.html` (authoritative spec)
- `docs/architecture/m22/m22_hardening_review.html` (STIX/TAXII-specific P0/P1 findings — SSRF,
  object-graph explosion, external-reference URLs, missing ACL)
- `docs/M22_PHASE1_THREAT_INTEL_FOUNDATION_REPORT.md`
- `docs/M22_PHASE2_FEED_SYNCHRONIZATION_FOUNDATION_REPORT.md`
- M22 Phase 1 implementation in full: `domain/threat_intel/reference_data_*.py`,
  `attack_technique_entity.py`, `vulnerability_entity.py`, `reference_data_repository.py`,
  `application/threat_intel/reference_data_admin_service.py`
- M22 Phase 2 implementation in full: `application/threat_intel/feed_connector.py`,
  `feed_sync_orchestration_service.py`, `feed_sync_worker.py`,
  `domain/threat_intel/feed_value_objects.py`
- `infrastructure/credential_resolver.py` / `application/contracts.py` (`CredentialResolverPort`)
- `infrastructure/threat_intel/http_client.py`, `ip_classification.py` (existing SSRF/HTTP patterns)
- `application/validation_execution/network_boundary.py`, `network_adapters.py` (the codebase's most
  advanced existing SSRF/pivot-defense reference implementation)
- `application/platform/metrics_abstraction.py`, `runtime_container.py` (metrics/DI conventions)
- `core/exceptions.py` (exception hierarchy conventions)
- `app.py` (startup-hook wiring conventions)
- `backend/pyproject.toml` (ruff/mypy config, pytest config)

No architecture was invented. Every naming, layering, SSRF-defense, and testing decision either
reuses an existing pattern already in the repository or directly implements a named Hardening Review
finding.

---

## 4. Files Added / Modified

### New files

| File | Purpose |
|---|---|
| `backend/src/redforge/domain/threat_intel/stix_exceptions.py` | STIX parsing/validation domain exceptions (container-too-large, malformed, nesting-too-deep, object-count-exceeded, malformed-object, invalid-STIX-ID). |
| `backend/src/redforge/domain/threat_intel/stix_value_objects.py` | `StixId` value object (validated `{type}--{uuid}` shape). |
| `backend/src/redforge/domain/threat_intel/stix_objects.py` | Flat dataclasses for the 4 supported STIX object types plus `StixExternalReference`/`StixKillChainPhase`. |
| `backend/src/redforge/domain/threat_intel/stix_parser.py` | STIX 2.1 container/object parser with size/count/depth caps; `load_stix_container()`, `validate_object_list()`, `parse_object()`. |
| `backend/src/redforge/infrastructure/threat_intel/taxii_client.py` | TAXII 2.1 client: SSRF-safe HTTP, `TaxiiAuth`, discovery, collection listing/reading, paginated object retrieval. |
| `backend/src/redforge/application/threat_intel/stix_reference_data_mapper.py` | Application-layer ACL: STIX dataclasses → Phase 1 `TacticInput`/`TechniqueInput`/`RelationshipInput`/`VulnerabilityInput`. |
| `backend/src/redforge/application/threat_intel/stix_taxii_connector.py` | `StixTaxiiFeedConnector` — the `FeedSyncExecutor` implementation: config resolution, auth building, discovery, fetch/parse/map/upsert, metrics. |
| `backend/tests/domain/test_stix_domain.py` | 46 domain unit tests (`StixId`, container/object-list validation, per-type parsing, dispatch). |
| `backend/tests/unit/test_stix_reference_data_mapper.py` | 18 unit tests (tactic/technique/relationship/vulnerability mapping, sub-techniques, unmapped-item handling). |
| `backend/tests/unit/test_taxii_client.py` | 33 unit tests (SSRF gate, auth, discovery, collections, object pagination, transport failures). |
| `backend/tests/unit/test_stix_taxii_connector.py` | 41 unit tests (config resolution, auth building, API-root resolution, fetch/parse caps, `execute()` end-to-end with fakes, registry integration). |
| `backend/tests/integration/test_m22_stix_taxii_pg.py` | 8 PostgreSQL integration tests (end-to-end sync, incremental sync, idempotency, error handling incl. SSRF, authentication, architecture-regression). |
| `docs/M22_PHASE3_STIX_TAXII_INTEGRATION_REPORT.md` | This report. |

### Modified files

| File | Change |
|---|---|
| `backend/src/redforge/domain/threat_intel/reference_data_value_objects.py` | Added `ReferenceDataSource.STIX_TAXII_FEED` (additive `StrEnum` member — no migration, `source_system` is `VARCHAR`). |
| `backend/src/redforge/app.py` | Registered `StixTaxiiFeedConnector` against `FeedSourceKind.STIX_TAXII_PULL` in `_start_feed_sync_scheduler()`'s startup hook — the only change to production wiring this phase makes. |
| `docs/PROJECT_CONTEXT.md` | Added the M22 Phase 3 milestone row; updated the "Last verified"/test-baseline header. |

**No file belonging to Phase 1 or Phase 2's actual implementation was modified.** The only
Phase-1-owned file touched is the additive enum change above; the only Phase-2-owned file touched is
the startup-wiring registration call in `app.py` (a one-time `registry.register(...)` call, not a
change to any Phase 2 class or function body).

---

## 5. Database Schema

**No migration was added.** Phase 3 introduces no new tables and no new columns:

- STIX/TAXII objects are mapped directly into Phase 1's existing 4 reference-data tables
  (`attack_tactics`, `attack_techniques`, `attack_technique_relationships`, `vulnerabilities`) via the
  existing, unmodified `ReferenceDataAdminService` — Phase 3 adds no second persistence path.
- Synchronization bookkeeping (checkpoints, run history, retry counters) uses Phase 2's existing
  `feeds`/`feed_sync_runs` tables (migration `0036`) — unchanged.
- The one data-model change (`ReferenceDataSource.STIX_TAXII_FEED`) is a Python-level `StrEnum`
  addition; `vulnerabilities.source_system`/`reference_data_ingestion.source_system` are `VARCHAR`
  columns (confirmed in migration `0035`), so no `ALTER TYPE` or migration is needed.

Migration verification performed anyway, to confirm zero regression:

```
alembic upgrade head        (0 → 0036, clean, empty scratch database)
alembic downgrade 0034      (0036 → 0035 → 0034, clean)
alembic upgrade head        (0034 → 0035 → 0036, clean)
```

All three steps completed with zero errors.

---

## 6. Connector Configuration

`StixTaxiiFeedConnector` is registered against `FeedSourceKind.STIX_TAXII_PULL`. Per-feed behavior is
driven entirely by `Feed.connector_config` (JSON, opaque to Phase 2, interpreted only by this
connector) and `Feed.credential_ref` (resolved via the existing `CredentialResolverPort` — no secret
material ever stored in `connector_config`):

| `connector_config` key | Required | Meaning |
|---|---|---|
| `api_root_url` | One of this or `discovery_url` | Direct TAXII API Root URL — skips discovery. |
| `discovery_url` | One of this or `api_root_url` | TAXII discovery endpoint — the connector resolves the default (or first) API Root from it. |
| `collection_id` | Yes | The TAXII collection to poll. |
| `auth_scheme` | No (default `"none"`) | One of `none` / `basic` / `bearer`. |
| `username` | Required if `auth_scheme=basic` | Basic-auth username (password comes from `credential_ref`). |
| `page_limit` | No (default `100`, max `1000`) | TAXII pagination page size. |

Authentication secrets (Basic password, Bearer token) are always resolved at execution time via
`CredentialResolverPort.resolve(credential_ref)` — never read from `connector_config` — reusing the
exact `EnvironmentCredentialResolver` pattern already used by Phase 2/Phase 1's own credential
handling. `TaxiiConnectorConfigError` (a `ValidationError`) is raised for any missing/invalid
configuration before a single network call is made.

Two module-level ceilings bound every sync attempt regardless of server behavior:
`MAX_PAGES_PER_SYNC_ATTEMPT` and `MAX_TOTAL_OBJECTS_PER_SYNC_ATTEMPT` — a misbehaving or malicious
TAXII server that never sets `more: false` cannot make a single sync attempt run unbounded.

---

## 7. A Real Defect Found and Fixed During This Phase's Own Testing

While writing the PostgreSQL integration suite, the very first end-to-end run failed with
`StringDataRightTruncationError: value too long for type character varying(26)` on
`platform_audit_log.actor_id`. Investigation traced this to `platform_audit_log.actor_id` being
`VARCHAR(26)` — exactly the width of a ULID — and confirmed Phase 2's own
`_SCHEDULER_ACTOR_ID = "system:feed_sync_scheduler"` string is *exactly* 26 characters, evidently
sized deliberately to that column. The connector's first draft used
`f"system:stix_taxii_connector:{feed_id}"` for the `ReferenceDataAdminService` audit calls it makes on
every batch upsert — a 26-character `feed_id` ULID appended to any non-empty prefix necessarily
overflows the 26-character column. Fixed by using the bare `feed_id` as the actor identity (Decision 7,
§2) — no schema change, no Phase 1/Phase 2 code touched, fix confined entirely to
`stix_taxii_connector.py` and its own unit test's assertion. Caught entirely by this phase's own
integration tests before this report was written; not a review finding.

---

## 8. Quality Gates — Results

All gates were run against this exact working tree, uncommitted, per instruction.

### Ruff

```
python3 -m ruff check .
```

Result: **Clean on every file added or modified this phase.** The only findings anywhere in the
repository are 5 pre-existing, unrelated findings in two untouched M21-era test files
(`tests/application/test_investigation_correlation.py`, `tests/domain/test_investigation_domain.py`)
— confirmed via `git status`/`git diff` that this phase never touched either file.

### Mypy

```
python3 -m mypy src/redforge
```

Result: **Success: no issues found in 789 source files.** Zero errors, including every new/modified
Phase 3 file. The only diagnostic anywhere is one pre-existing, unrelated missing third-party stub
(`maxminddb`, in `infrastructure/threat_intel/providers/maxmind_geolite_local.py`) — not a file this
phase touched.

### Unit / Domain / Application tests

```
python3 -m pytest tests/unit tests/domain tests/application -q \
  --ignore=tests/unit/test_aws_cloud_adapter.py --ignore=tests/unit/test_ldap_directory_adapter.py
```

Result: **3,685 passed**, 0 failed. (The two ignored files fail to *collect* — not to pass/fail — in
this environment because the optional `boto3`/`ldap3` packages are not installed; this is a
pre-existing environment characteristic unrelated to Phase 3.) Of the 3,685, **138** are new this
phase:

| File | New tests |
|---|---|
| `tests/domain/test_stix_domain.py` | 46 |
| `tests/unit/test_stix_reference_data_mapper.py` | 18 |
| `tests/unit/test_taxii_client.py` | 33 |
| `tests/unit/test_stix_taxii_connector.py` | 41 |
| **Total** | **138** |

Coverage: `StixId` shape validation; container byte-size/JSON-decode/structure/object-count/nesting-depth
caps; per-type parsing (`attack-pattern`, `x-mitre-tactic`, `relationship`, `vulnerability`) including
malformed-field rejection; parser dispatch and `is_supported_type()`; tactic/technique/relationship/
vulnerability mapping including sub-technique parent resolution, tactic-shortname→ID resolution, and
unmapped/malformed-item isolation; TAXII SSRF gate (scheme rejection, private/loopback/link-local/
metadata IP rejection via mocked DNS, no-redirect enforcement, oversized-response rejection);
`TaxiiAuth` header/httpx-auth construction for `none`/`basic`/`bearer`; discovery, collection listing,
collection reading, and paginated object retrieval against `httpx.MockTransport`; transport-level
failure handling (401/403, 3xx, 5xx, malformed JSON, oversized body); connector configuration
resolution and validation; auth building with credential-resolver integration; API-root resolution
(direct URL vs. discovery, default vs. first-available); fetch/parse/map/upsert flow including
pagination aggregation, the total-object and page ceilings, and per-item failure isolation; the full
`execute()` method against fake collaborators (config errors, unreadable collections, empty
collections, checkpoint provenance, successful-upsert counting, mixed success/failure counting,
metrics recording, Basic/Bearer credential resolution and failure); and `FeedConnectorRegistry`
integration (Protocol conformance, register/retrieve, other source kinds remain unregistered).

### PostgreSQL integration tests

Against a real PostgreSQL instance (`localhost:5432`):

```
python3 -m pytest tests/integration/test_m22_feed_sync_pg.py \
                   tests/integration/test_m22_reference_data_pg.py \
                   tests/integration/test_m22_stix_taxii_pg.py -q
→ 80 passed
```

**M22 Phase 3 proof** (`test_m22_stix_taxii_pg.py`, run against the M22 Phase 2 proof database
`redforge_m22_feed_sync_proof_test`, already at head `0036` — no new proof database was needed since
Phase 3 adds no schema): **8 passed**, covering:

- End-to-end synchronization: a real `StixTaxiiFeedConnector` + real `TaxiiClient` (against
  `httpx.MockTransport` simulating a TAXII server) + real `FeedSyncOrchestrationService`, fetching a
  batch of 3 STIX objects (tactic, technique, vulnerability) and confirming all 3 are mapped and
  persisted into the real `attack_tactics`/`attack_techniques`/`vulnerabilities` tables, with the
  `FeedSyncRun` recording `items_fetched=3`/`items_processed=3`.
- Incremental synchronization: the second `trigger_sync` attempt against the same feed sends the
  first attempt's completion checkpoint as the TAXII `added_after` query parameter — verified by
  inspecting the actual outgoing request the mock server received.
- Idempotency: re-syncing byte-identical STIX content across two separate `trigger_sync` attempts
  converges on exactly one row (`unchanged`, not a duplicate insert).
- Error handling: an unreadable TAXII collection fails the `FeedSyncRun` honestly (status `FAILED`,
  populated `error_message`, no partial reference-data writes); a genuinely SSRF-unsafe endpoint
  (resolving to a private/loopback address, checked against the *real* DNS resolver, not a mock) is
  rejected by `validate_ssrf_safe()` before any TAXII request is attempted.
- Authentication: a Bearer credential is resolved via `EnvironmentCredentialResolver` and forwarded as
  the `Authorization` header on every request the mock TAXII server receives; a missing
  `credential_ref` for a `bearer`-scheme feed fails the run with a clear configuration error before
  any network call.
- No architecture regression: other `FeedSourceKind` values remain unregistered and continue to fail
  honestly with `UnknownFeedConnectorError` — proving Phase 2's registry seam needed zero
  modification to accept this real connector.

**M22 Phase 2 regression** (`test_m22_feed_sync_pg.py`): **33 passed**, unchanged, confirming Phase 3
introduces zero regression to the feed-synchronization platform itself.

**M22 Phase 1 regression** (`test_m22_reference_data_pg.py`): **39 passed**, confirming Phase 3's use
of `ReferenceDataAdminService` introduces zero regression to the reference-data foundation. (This
proof database's own migration state had drifted stale in the working environment — `attack_techniques`
and other Phase 1/2 tables were absent despite `alembic_version` claiming head `0036` — and was
restored via a clean `DROP DATABASE` + recreate + `alembic upgrade head` before this phase's
verification run; this was a pre-existing environment-state issue unrelated to any Phase 3 code
change, not a defect introduced this phase.)

### Migration verification

```
alembic upgrade head          (0 → 0036, clean, empty scratch database)
alembic downgrade 0034        (0036 → 0035 → 0034, clean)
alembic upgrade head          (0034 → 0035 → 0036, clean)
```

Confirms migration reversibility is unaffected — Phase 3 makes no migration change to verify beyond
this round-trip re-confirmation.

---

## 9. Test Baseline Summary

| Suite | Count | Result |
|---|---|---|
| Non-integration (unit + domain + application), excl. optional-dependency files | 3,685 collected | All pass (138 new this phase) |
| M22 Phase 3 PostgreSQL integration | 8 | All pass |
| M22 Phase 2 PostgreSQL integration (regression check) | 33 | All pass, unchanged |
| M22 Phase 1 PostgreSQL integration (regression check) | 39 | All pass, unchanged |
| Ruff | — | Clean on all Phase 3 files; 5 pre-existing unrelated findings in untouched M21 test files |
| Mypy (`src/redforge/`) | — | Clean: 0 errors in 789 source files (1 pre-existing unrelated `maxminddb` stub gap disclosed, not in scope) |

---

## 10. Documentation Updated

- `docs/PROJECT_CONTEXT.md` — added the M22 Phase 3 milestone row to the Completed Milestones table;
  updated the "Last verified" line and test-baseline header.
- This report (`docs/M22_PHASE3_STIX_TAXII_INTEGRATION_REPORT.md`).

---

## 11. Explicit Confirmation of Stop Conditions

- Phase 3 only was implemented: TAXII 2.1 client, discovery, authentication, incremental
  synchronization via Phase 2's checkpoints, STIX 2.1 parsing/validation, mapping into the Phase 1
  reference-data model, a real `FeedSyncExecutor` connector registered in production wiring, error
  handling, retry integration (reused, not reimplemented), structured logging, metrics, audit events,
  and configuration.
- No Threat Fusion, Attack Path Engine, Investigation-context integration, or frontend code was
  written.
- Phase 2's synchronization framework (`FeedSyncOrchestrationService`, `FeedAdminService`,
  `FeedQueryService`, the scheduler worker, migration `0036`) was not modified — the only Phase-2-owned
  change is a single connector-registration call added to `app.py`'s existing startup hook.
- Phase 1's reference-data foundation was not modified beyond one additive `StrEnum` member.
- Ruff, Mypy, unit tests, PostgreSQL integration tests, and migration verification were all run, with
  results reported above.
- Documentation was updated.
- This implementation report was produced.
- **No commit was made. No push was made.** The working tree is left exactly as-is, awaiting review.
