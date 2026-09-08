# Runbook: IOC Intelligence (`ioc_intelligence`, M51.2)

Operational reference for the IOC Intelligence capability — the first
of RedForge's nine M51 Native Threat Intelligence bounded contexts to
reach production-release closure (M51 Slice 2, hardened in Slice 2.1).
Describes the actual current implementation only; nothing here is
aspirational.

**Slice 2.1 (this revision)** closed the four remaining production
blockers Slice 2 left open: real server-side search/filter/sort across
the entire dataset (§2 item 3, §12), a formalized global-evidence
policy (§4), an in-process TTL expiry scheduler (§2 item 7, §11), and
scale/E2E verification (§13). See §13 for the full verification record
and final acceptance answers.

---

## 1. Architecture ownership

- **Bounded context**: `backend/src/ioc_intelligence/` — domain,
  application, infrastructure, and API layers, following the same
  Clean Architecture shape as every other M51 context
  (`threat_actor_intel`, `attack_pattern_intel`, etc.).
- **Aggregate**: `IOC` (`domain/aggregates/ioc.py`) — a canonical
  observable indicator (IP, domain, URL, hash), owning its own
  lifecycle (`ACTIVE`/`EXPIRED`/`SUPERSEDED`/`REVOKED`), epistemic
  state (`OBSERVATION` → `EVIDENCE` → `CORROBORATED`/`VALIDATED` /
  `DISPUTED` / `REFUTED` / `HISTORICAL` / `RETIRED`), source
  attributions, and evidence citations.
- **Persistence**: PostgreSQL, migration `0160_ioc_intelligence_foundation.py`
  (part of the linear chain, currently at head `0168`). Three tables:
  `ioc_intelligence_iocs`, `ioc_intelligence_source_attributions`,
  `ioc_intelligence_evidence_citations`.
- **Frontend**: `frontend/src/app/(app)/ioc-intelligence/page.tsx` —
  the only M51 capability with a built operator UI as of this slice.
  Reachable directly, and via the Threat Intelligence shell
  (`/threat-intelligence`) sub-navigation.
- **Legacy integration**: read-only ACL adapters
  (`infrastructure/acl/legacy_ioc_observation_adapter.py`,
  `ioc_correlation_query_adapter.py`, `ioc_enrichment_query_adapter.py`)
  bridge from the pre-existing `redforge.domain.threat_intel` tables —
  these never write back to legacy tables, only read from them.
- **Not integrated (by design, deferred per ADR-M51.1-04/-05/-06)**:
  the platform `EventStore`/outbox and the Knowledge Graph. See
  §8 below.

## 2. Operator workflow

1. **Observe** an IOC — `POST /api/v1/iocs/observations/tenant` (any
   `ANALYST`+ role) or `/observations/global` (platform
   `PLATFORM_IOC_INTEL_MANAGE` only). Requires at least one source
   attribution (global) or one source attribution/evidence citation
   (tenant).
2. **Deduplication is automatic**: observing the same canonical value
   again (case/format-normalized) merges new provenance into the
   existing record instead of creating a duplicate — verified live via
   the UI (source count increments, no new row).
3. **View details** — click any row to open the detail drawer: full
   provenance, lifecycle/epistemic state, validity window, source
   attributions, evidence citations. A "History" section states
   honestly that change history is not exposed by the certified API —
   it does not fabricate one.
4. **Add source attribution / evidence citation** — via the drawer's
   action buttons. Evidence citations reference an existing
   `SecurityCondition` or `InvestigationCase` and are validated
   fail-closed (see §5).
5. **Lifecycle transitions** — Mark Expired, Supersede, Revoke,
   Refresh (reactivate). Supersede and Revoke require an explicit
   browser confirmation before submitting (added in Slice 2 — these
   are effectively terminal actions).
6. **Epistemic transitions** — Advance to Evidence, Dispute, Refute
   (Refute requires a typed reason). Every transition is validated
   against the closed state-machine (`EpistemicStatePolicy`) before
   persisting — an illegal transition is rejected with a specific
   error, never silently accepted or silently dropped.
7. **Maintenance sweep** (Slice 2; automated in Slice 2.1) —
   `POST /api/v1/iocs/maintenance/expire-lapsed` (platform authority
   only). Transitions every `ACTIVE` IOC whose `valid_until` has
   already passed to `EXPIRED`, across all tenants. Idempotent — safe
   to call repeatedly (a re-run finds nothing left to expire), and safe
   under concurrent/overlapping calls (see §11). As of Slice 2.1 this
   also runs automatically on an in-process periodic schedule
   (`ioc_expiry_scheduler`, default every 300s) — the endpoint remains
   available for a manual trigger or an external cron/k8s CronJob, and
   calls the exact same application-service method the scheduler does.

## 3. Permissions / RBAC matrix

All enforcement is backend-authoritative (`redforge/api/security.py`);
frontend show/hide is UX only. Exact `Permission`/`PlatformPermission`
enum values (`redforge.domain.identity.value_objects`,
`redforge.domain.platform_identity.value_objects`):

| Action | Tenant permission | Platform permission (global) |
|---|---|---|
| Read (list/get) | `ioc_intel:read` | `platform:ioc_intel:read` |
| Observe | `ioc_intel:observe` | `platform:ioc_intel:manage` |
| Mutate (source/evidence/lifecycle/epistemic) | `ioc_intel:manage` | `platform:ioc_intel:manage` |
| Maintenance sweep | — (platform only) | `platform:ioc_intel:manage` |

Every organization membership role (`OWNER`, `ADMIN`,
`SECURITY_MANAGER`, `ANALYST`, `MEMBER`, `VIEWER`) is granted
`ioc_intel:read`. `MEMBER` and above additionally get `observe`/`manage`
per the role-permission map — `VIEWER` is read-only by design. Platform
authority is **never** derivable from any organization role, however
senior (verified: `require_platform_permission` resolves exclusively
from a persisted `PlatformAssignment` row, never from a JWT `org`/`role`
claim).

## 4. Tenant vs. global semantics

- `tenant_id = NULL` means a genuine **global**, platform-curated
  record — never a "not yet assigned" sentinel.
- Two partial unique indexes enforce identity correctly:
  `uq_ioc_intelligence_iocs_global_identity` (`WHERE tenant_id IS NULL`)
  and `uq_ioc_intelligence_iocs_tenant_identity`
  (`WHERE tenant_id IS NOT NULL`) — verified live against PostgreSQL:
  two global rows with the same `(ioc_type, normalized_value)` collide;
  two tenant rows in the *same* tenant collide; two tenant rows in
  *different* tenants with the same value do **not** collide (each
  tenant has its own independent identity space).
- A tenant can never read or mutate another tenant's IOC — verified via
  automated tests (`TestTenantIsolation`) and manually in-browser (a
  cross-tenant lookup 404s, not 403 — no existence is leaked).
- Global evidence citations are **rejected outright** — this is a
  **formalized, deliberate, permanent product/domain policy**
  (`GlobalEvidencePolicy` / `GlobalEvidenceCitationNotSupportedError`,
  M51.2 Slice 2.1), not an interim gap. It is Option B of the two
  choices considered (see below), and repository-first investigation
  confirmed it is the only architecturally sound one:
  - The canonical `evidence` bounded context (`backend/src/evidence/`)
    requires a real, non-nullable `tenant_id` on every aggregate
    (`ExecutionEvidence`, `EvidenceChain`) and asserts it on every
    mutating method — there is **no** platform/global-owned Evidence
    concept anywhere in that domain model today.
  - `ioc_intelligence`'s evidence citations don't even reference that
    context directly — they reference `SecurityCondition`/
    `InvestigationCase` (via `IIocEvidenceValidationPort` ->
    `SqlAlchemyEvidenceEntityExistenceService`), which are themselves
    tenant-owned by construction (the existence check requires a real
    `organization_id`).
  - No other bounded context in the platform has already solved
    "a global/platform-owned record citing tenant-scoped evidence" —
    `ioc_intelligence` (and `threat_actor_intel`, which has the
    identical shape) are the only two contexts that attempt real
    fail-closed evidence verification at all; every other
    reference-data context with an `add_evidence_citation` method
    (`malware_intel`, `campaign_intel`, `infrastructure_intel`,
    `intelligence_relationships`) accepts any citation string
    unconditionally, sidestepping the problem rather than solving it.
  - **Option A (build a real ACL adapter) was rejected**: it would
    require inventing a currently-nonexistent platform/global-owned
    `SecurityCondition`/`InvestigationCase` (or canonical Evidence)
    concept — a new cross-context modeling change, not a guard
    removal, and not something any part of the domain model today
    supports safely.
  - Global provenance remains fully evidence-first — just via
    `source_attributions` (real, closed-vocabulary provider claims)
    instead of a citation the platform cannot verify. If a future
    slice introduces genuine platform-scoped Evidence ownership (a
    prerequisite that does not exist today), this policy would be the
    one place to revisit.
  - Verified: `tests/ioc_intelligence/domain/test_policies.py::
    TestGlobalEvidencePolicy` (the policy in isolation) and
    `TestGlobalEvidenceCitationFailsClosed` in
    `test_ioc_application_service.py` (both call sites) — both pass.

## 5. Evidence and source-attribution behavior

- **Source attributions** carry `source_system` (a closed provider
  vocabulary), `external_id`, `observed_at`, `weight_applied`,
  `confidence` (`low`/`medium`/`high`/`very_high`) — real values from a
  real provider claim, not free text.
- **Evidence citations** (tenant-scoped only, see §4) reference an
  existing `SecurityCondition` or `InvestigationCase` by id. Validated
  **fail-closed**: a malformed reference, an unsupported entity type,
  or a reference to a nonexistent/cross-tenant entity is rejected —
  verified by reading the ACL adapter and by dedicated tests.
- Confidence and weight are never averaged or silently reconciled
  across sources — each attribution is preserved individually; the
  aggregate does not compute a derived "trust score" beyond the
  explicit epistemic-state ladder.

## 6. Lifecycle and epistemic semantics (do not conflate)

- **Lifecycle** = is this record still the one to trust operationally:
  `ACTIVE` → `EXPIRED` / `SUPERSEDED` / `REVOKED`, or back to `ACTIVE`
  via Refresh (reactivate). All transitions gated by
  `IocLifecyclePolicy`.
- **Epistemic state** = how much do we trust the *claim itself*:
  `OBSERVATION` → `EVIDENCE` → `CORROBORATED`/`VALIDATED`, with
  `DISPUTED` and terminal `REFUTED`/`HISTORICAL`/`RETIRED` off-ramps.
  Gated by `EpistemicStatePolicy` — e.g. `EVIDENCE → DISPUTED` directly
  is **not** a legal transition (confirmed live: the API returns
  `409 Invalid epistemic-state transition evidence -> disputed`, not a
  silent no-op or a fabricated success).
- These two axes are independent — an `ACTIVE` IOC can be
  `DISPUTED`, and a `REVOKED` IOC keeps whatever epistemic state it had
  at revocation.

## 7. Ingestion / orchestration behavior

`application/services/ioc_ingestion_orchestrator.py` bridges the
legacy `threat_intel` observation/enrichment/correlation ports into
real `IOC` observations. Per-candidate error isolation: one bad
candidate's failure is recorded in `IngestionResult.errors` and does
not abort the batch. Idempotent on retry: `_merge_new_provenance`'s
`dedup_key` check means re-ingesting the same candidate does not
create duplicate attributions.

**Known metric caveat**: `IngestionResult.attributions_added` reports
the IOC's *total* current attribution count after the call, not the
count of attributions newly added this run. Read it as "total sources
now on record," not "sources added this batch."

## 8. Observability

- **Platform-wide, automatic** (applies to every IOC route with no
  extra wiring): Prometheus RED metrics via `PrometheusMiddleware`
  (`http_requests_total`, `http_request_duration_seconds`,
  `http_exceptions_total`, labeled by method/normalized-path/status),
  scraped at `/metrics`; structured per-request logs
  (`RequestLoggingMiddleware`); a request/correlation id bound to every
  log line automatically for the request's lifetime
  (`CorrelationMiddleware`).
- **IOC-specific business events** (added Slice 2, API layer,
  `api/v1/iocs.py`): `ioc_observed`, `ioc_source_attribution_added`,
  `ioc_evidence_citation_added`, `ioc_lifecycle_transitioned`,
  `ioc_epistemic_transitioned`, `ioc_refreshed`, `ioc_superseded`,
  `ioc_revoked`, `ioc_disputed`, `ioc_refuted`,
  `ioc_expiry_sweep_completed` — each logs `ioc_id`, `tenant_id` (or
  `"global"`), and the specific target value where relevant (e.g.
  `target_lifecycle`). **Never** logs evidence citation content, source
  attribution payloads, or a refute reason (free-text, potentially
  sensitive analyst commentary).
- **Domain event publishing** is best-effort only
  (`infrastructure/events/structlog_event_publisher.py`): a publish
  failure is logged as a warning and swallowed, not raised. This
  context has no transactional outbox — a genuinely durable/replayable
  event stream would require the platform's existing outbox pattern
  (precedent: `automated_action`), which is explicitly out of scope for
  this slice (see §10, Known limitations).

## 9. Common failure modes and recovery

| Symptom | Cause | Fix |
|---|---|---|
| `422` on observe/transition with a message naming a field | Invalid enum value (`ioc_type`, `confidence`, `target_lifecycle`, `target_state`, or a `lifecycle`/`epistemic_state` filter) | Fixed in Slice 2 — this used to be an unhandled 500; check the exact allowed values in `iocIntelligence.ts`'s `IOC_*_VALUES` exports |
| `404` on `GET /iocs/{id}` | Malformed id (not a UUID), or a real id belonging to a different tenant | Both cases return 404 identically by design — no existence is leaked across tenants |
| `409 Optimistic lock conflict on IOC ...` | A concurrent writer already updated this record since you loaded it | Reload the record (the frontend does this automatically) and retry the specific mutation against the current state |
| `409` with a message like `Invalid lifecycle transition X -> Y` or `Invalid epistemic-state transition X -> Y` | The requested transition is not legal from the record's current state — **not** a concurrency issue | Check the current lifecycle/epistemic state in the detail view and pick a legal target; do not blindly retry |
| `403` on `/observations/global` or `/maintenance/expire-lapsed` | Caller lacks `platform:ioc_intel:manage` | No organization role satisfies this — requires a real `PlatformAssignment`; see `docs/RUNBOOK_PLATFORM_SUPER_ADMIN_BOOTSTRAP.md` for how platform authority is granted |
| Global evidence citation rejected with `422` | Global IOCs cannot carry evidence citations (Slice 2 fix — see §4) | Use `source_attributions` for global provenance instead |
| `alembic upgrade head` fails at `0160` | Should not happen — verified clean from an empty database, and via isolated downgrade/upgrade around this revision | If it does, check for a stale `ioc_intelligence_*` table left by a prior partial migration and drop it manually before retrying |

## 10. Migration / upgrade notes

- Migration `0160` is a pure additive foundation migration (3 new
  tables, no changes to any existing table).
- Migration `0168` (Slice 2.1) adds exactly two composite indexes
  (`ix_ioc_intelligence_iocs_tenant_lifecycle`,
  `ix_ioc_intelligence_iocs_tenant_valid_until`) to the existing
  `ioc_intelligence_iocs` table — no new table, no column change, no
  data migration. Added on measured `EXPLAIN ANALYZE` evidence (see
  §13), not speculatively.
- Verified against real PostgreSQL 16: clean upgrade from empty,
  isolated `downgrade 0159` → `upgrade 0160` → `upgrade head` cycle,
  and the two partial unique indexes behave exactly as designed
  (NULL-safe, no false-positive or false-negative collisions). `0168`
  itself verified with an isolated `downgrade 0167` → `upgrade head`
  cycle against the same database.
- No data migration/backfill is needed for this table set (it did not
  exist before `0160`).

## 11. Deployment prerequisites

- PostgreSQL, migrated to at least `0160` (current repository head:
  `0168`).
- **New in Slice 2.1**: an in-process periodic scheduler
  (`ioc_expiry_scheduler`, registered in `redforge/app.py` next to
  every other platform scheduler) now runs the expiry sweep
  automatically — no separate deployment step is required to get
  automatic TTL enforcement; it starts with the API process itself.
  Optional tuning: `runtime_ioc_expiry_scheduler_poll_s` (a `Settings`
  attribute read via `getattr(..., default=300.0)`, matching every
  other scheduler's tuning convention in this codebase — set it only
  if the 300-second default poll interval needs to change for a given
  deployment). The `POST /iocs/maintenance/expire-lapsed` endpoint
  remains available for a manual trigger or an external cron/k8s
  CronJob and is fully redundant-safe with the scheduler (see §13,
  finding 3).
- No new external service dependency — nothing beyond the existing
  PostgreSQL database and the API process itself.

## 12. Known limitations (honest, not silently omitted)

- **No durable/transactional event bus** — domain events are
  best-effort logged only; a publish failure does not roll back the
  mutation and is not retried. Acceptable for the current scope
  (no consumer yet depends on IOC domain events); would need the
  platform's outbox pattern if that changes.
- **`IngestionResult.attributions_added`** is a total-count field, not
  a this-run delta — see §7.
- No Knowledge Graph integration exists for IOC entities (deliberately
  deferred platform-wide per ADR-M51.1-04/-05/-06 — out of scope for
  M51 generally, not specific to this capability).
- **Global evidence citations remain unsupported** — this is
  intentional, permanent product policy, not a limitation to close;
  see §4 for the full rationale.
- No pg_trgm/GIN trigram index exists for free-text `search` — measured
  unnecessary at the 50,000-row scale tested (§13); would need
  re-evaluation with real `EXPLAIN ANALYZE` evidence if a future
  tenant's dataset grows an order of magnitude larger and `search`
  latency is observed to degrade.

Closed in Slice 2.1 (previously listed here, now resolved — see §13
for verification): "list/search/filter is partially server-side" and
"no automated background scheduler for the expiry sweep."

## 13. M51.2 Slice 2.1 — production-closure verification record

This section records exactly what was verified, how, and the honest
result — not "flow available."

### 13.1 Server-side query capability

- `ListIocsQuery`/`IIocRepository.list_and_count`/`PgIocRepository`
  now support: free-text `search` (ILIKE over `normalized_value`,
  wildcard-escaped), `ioc_type`, `lifecycle`, `epistemic_state`,
  `validity` (`valid`/`lapsed`, time-based against `valid_until`, kept
  deliberately independent of `lifecycle`), `confidence` and
  `source_system` (both via `EXISTS` against `source_attributions` —
  an IOC matches if ANY attribution matches), a whitelisted `sort_by`
  (`created_at`/`updated_at`/`valid_until`/`ioc_type`/`lifecycle`/
  `epistemic_state` — never a raw client-supplied column name) and
  `sort_dir`, and real `limit`/`offset` pagination.
- **Real total count**: `PaginatedIocListResponse.total` is computed
  server-side from the same filtered query (via `func.count()` over
  the filtered subquery, before `limit`/`offset`) — `count` (this
  page's size) is kept alongside it for backward compatibility, but
  every UI/consumer should read `total` for "how many results in
  total." Filtering and sorting both apply before pagination; counts
  represent the filtered dataset, not a client-side tally.
- Tenant/global ownership scoping (`_tenant_filter`) is applied first,
  unconditionally, in every code path — none of the new filters can
  bypass it (verified:
  `TestListAndCount::test_tenant_scoping_still_enforced_under_every_new_filter`).
- SQL injection prevented by construction: `sort_by`/`sort_dir` are
  parsed through closed `IocSortField`/`SortDirection` enums (422 on
  anything else) and mapped to trusted SQLAlchemy column objects via a
  fixed dict — no string ever reaches `ORDER BY` directly.
- Frontend (`frontend/src/app/(app)/ioc-intelligence/page.tsx`) no
  longer does ANY client-side filtering/sorting — every filter,
  the free-text search (debounced 300ms), and the sort selector are
  real query parameters sent to the backend; the "(this page)" labels
  that previously qualified type/search/sort were removed from every
  operation that is now genuinely dataset-wide (the three lifecycle-
  breakdown KPI tiles — Active/Expired/Disputed — remain honestly
  labeled "(this page)" since no backend aggregate endpoint computes
  those specific breakdowns across the full dataset; this was true
  before Slice 2.1 too and is unchanged).
- Verified live in the browser (real backend + real PostgreSQL, no
  mocks): observed a tenant IOC, confirmed `Total Matching Results`
  reflected the real server total, typed a search term and confirmed
  the network request was a real
  `GET /api/v1/iocs?search=...&sort_by=...&sort_dir=...` call (not a
  client-side filter), and confirmed the result matched.

### 13.2 Global evidence policy

Formalized as `GlobalEvidencePolicy` (Option B — see §4 for the full
rationale and why Option A was rejected). Verified: dedicated unit
tests (`TestGlobalEvidencePolicy`), the existing application-service
tests (`TestGlobalEvidenceCitationFailsClosed`), and live in the
browser — attempting to add an evidence citation to a real tenant IOC
with a nonexistent `SecurityCondition` id produced a real `422` from
the actual backend, surfaced honestly in the UI ("Evidence citation
failed validation for tenant ...").

The **successful** path (a genuinely existing `SecurityCondition`
citation persisting and being readable back) has no direct UI/API
entry point to fabricate one through the browser — `SecurityCondition`
rows are created only by RedForge's own M6/M7 network/cloud analyzers,
never by a client-facing create endpoint. This path is instead proven
by a dedicated, real-PostgreSQL integration test,
`tests/ioc_intelligence/infrastructure/test_real_evidence_acl.py`,
which creates a genuine `SecurityCondition` row (via the same
`TenantAssetService`/`TenantSecurityConditionService` real ingestion
path `threat_actor_intel`'s own certified evidence-ACL test already
uses), adds it as a tenant IOC's evidence citation through the real
`IOCApplicationService`, and reloads it from a fresh session to
confirm real persistence — plus a companion test proving a
cross-tenant citation (condition belongs to a different
`organization_id`) is correctly rejected.

### 13.3 TTL expiry — production operation

- `expire_lapsed_iocs` concurrency-hardened: a per-row `save()` failure
  (in production, an `OptimisticLockConflictError` from another
  overlapping sweep) is now caught and logged
  (`ioc_expiry_sweep_row_skipped`/`ioc_expiry_sweep_rows_skipped`), not
  raised past the sweep boundary — one contended row no longer aborts
  the rest of the batch. Verified with a fake repository whose
  `save()` is made to fail for one specific row
  (`test_one_rows_save_failure_does_not_abort_the_rest_of_the_batch`).
- Promoted to the platform's canonical in-process periodic-runner
  pattern (`TenantPeriodicRunner`, `per_tenant=False` — the same shape
  already used by `regulatory_notification_scheduler`/
  `reporting_scheduler`/`incident_scheduler`/`playbook_scheduler`),
  registered as `ioc_expiry_scheduler` in `redforge/app.py`'s lifespan,
  with the matching shutdown hook. No claim/lease table was added —
  evaluated and rejected as unnecessary ceremony for this specific job
  shape (a global, non-per-tenant, already-idempotent bulk operation)
  once the per-row OCC handling above was fixed; the existing
  `row_version` optimistic-concurrency check already gives the same
  safety guarantee a claim/lease table would, for materially less
  complexity.
- Verified real, live, in the running application (not just tests):
  starting the backend produced
  `lifecycle_hook_start name=ioc_expiry_scheduler phase=startup` ->
  `ioc_expiry_scheduler_started`, and the scheduler's first tick
  executed immediately and logged the real SQL query it issued
  (`SELECT ... FROM ioc_intelligence_iocs WHERE lifecycle = 'active'
  AND valid_until IS NOT NULL AND valid_until < ...`).
- Verified idempotent-and-safe-under-repeat-triggers against real
  PostgreSQL: `test_expiry_sweep_repeat_and_overlapping_triggers_stay_safe`
  runs the sweep via two independent sessions back-to-back and asserts
  the row converges to exactly one real transition
  (`row_version == 2`, `lifecycle == EXPIRED`), never corrupted or
  double-applied.
- The endpoint (`POST /iocs/maintenance/expire-lapsed`) still requires
  `PLATFORM_IOC_INTEL_MANAGE` — only a real, persisted
  `PlatformAssignment` satisfies this, never an organization role,
  matching every other platform-gated route in this codebase; this is
  unchanged by Slice 2.1 and remains the only way to invoke it
  manually or from an external scheduler.
- Failures ARE observable: per-row skips are logged individually
  (warning) and summarized (info, with `skipped_count`/
  `expired_count`); the route itself logs
  `ioc_expiry_sweep_completed`/the scheduler tick logs
  `ioc_expiry_scheduler_tick_completed` — both only when
  `expired_count > 0`, to avoid log noise on a no-op tick.

### 13.4 Scale verification

Seeded 50,000 synthetic `ioc_intelligence_iocs` rows (20 synthetic
tenant UUIDs + a global bucket, realistic distribution across
`ioc_type`/`lifecycle`/`epistemic_state`/`valid_until`) plus 50,000
matching `ioc_intelligence_source_attributions` rows, directly via SQL
(no ORM overhead, purely for seeding speed) against the real
PostgreSQL 16 instance, then `ANALYZE`d both tables.

Measured via `EXPLAIN (ANALYZE, BUFFERS)` against one ~2,400-row
tenant partition:

| Query shape | Before | After |
|---|---|---|
| Sort by `lifecycle` (tenant-scoped) | 25.1ms, ~7,900 rows filtered post-scan | 4.6ms, 0 rows filtered (new composite index) |
| Sort by `valid_until` (tenant-scoped) | 9-11ms, ~19,000 rows filtered post-scan | 2.2ms, 0 rows filtered (new composite index) |
| Sort by `ioc_type`/`epistemic_state`/`created_at`/`updated_at` | 1-3ms already (existing indexes sufficient) | unchanged — no new index added |
| Free-text `search` (ILIKE), tenant- or global-scoped | 0.9-4.5ms | unchanged — no new index added |
| Deep-offset pagination (offset 2,000 into a page) | — | 11.8ms |
| Unfiltered global-scope count | — | 0.7ms |

This is the evidence behind migration `0168`'s two new composite
indexes (`(tenant_id, lifecycle)`, `(tenant_id, valid_until)`) — added
only where measurement showed a real, growing-with-platform-size cost;
`ioc_type`/`epistemic_state`/`created_at`/`updated_at` sorts and
free-text search were measured fast already and got no new index.

Also verified programmatically against the real repository at this
50,000-row scale: paging through one tenant's entire ~2,428-row result
set 25-at-a-time (98 pages) produced zero duplicate or skipped rows,
and the reported `total` stayed identical across every page —
pagination is genuinely stable, not just "didn't crash."

Dataset size and all latency numbers above are real measurements
against this specific seeded dataset on this machine, not projected or
estimated figures — re-run `EXPLAIN ANALYZE` again before trusting
these numbers at a materially different scale or hardware.

### 13.5 Security regression

Re-ran the full `ioc_intelligence` test suite after every change in
this slice (240 tests: unit, application, and real-PostgreSQL
integration/API tests) — all passing throughout, including the
pre-existing tenant-isolation, RBAC, forged-header, malformed-id, and
optimistic-lock-conflict coverage this suite already carried before
Slice 2.1. Additionally ran the full sibling M51 bounded-context test
suites (`threat_actor_intel`, `attack_pattern_intel`, `campaign_intel`,
`intelligence_relationships`, `tool_intel`, `malware_intel`,
`infrastructure_intel`, `threat_report_intel` — 1,427 passed) and the
platform RBAC live-acceptance suite (18 passed) to confirm the shared
`redforge/app.py` and migration-chain edits caused no collateral
regression, plus a full-repository pytest pass (11,720 passed, 1,467
skipped, 5 pre-existing unrelated port-binding errors in
`test_validation_executions_m12/m13_isolation.py` — confirmed
unrelated to this slice: those fixtures bind a fixed local TCP port
and fail when something else on the machine already holds it,
independent of any file this slice touched).

New injection/abuse-surface tests added this slice:
`test_search_escapes_ilike_wildcards` (a literal `%`/`_` in `search`
must not behave as a wildcard), `test_invalid_sort_by_returns_422`,
`test_invalid_sort_dir_returns_422`, `test_invalid_ioc_type_filter_returns_422`,
`test_invalid_validity_filter_returns_422`,
`test_invalid_confidence_filter_returns_422` (all in
`test_iocs_api.py`) — every new query parameter fails closed (422),
never a raw 500 or a silently-ignored value.

### 13.6 Final acceptance

1. **Can an operator search/filter/sort the ENTIRE authorized IOC
   dataset correctly?** Yes — verified via real-Postgres repository
   tests, real-HTTP API tests, and a live browser session against the
   real backend; tenant scoping is enforced under every filter
   combination.
2. **Is global IOC evidence behavior intentional, secure, and
   documented?** Yes — formalized as `GlobalEvidencePolicy`
   (§4, §13.2), verified rejecting live in the browser against the
   real backend, documented here with the full architectural
   rationale and the specific future dependency that would be needed
   to lift it.
3. **Will expired IOCs actually be processed automatically/
   operationally in a real production deployment?** Yes — the
   `ioc_expiry_scheduler` starts with the API process itself (no
   separate deploy step), verified live (real startup log lines, real
   SQL issued on its first tick) and safe under repeat/overlapping
   triggers (§13.3).
4. **Was a real valid evidence citation added and persisted through
   the browser workflow?** Partially: the epistemic-state transition,
   search/filter/sort, and the invalid-evidence-rejection path were
   all verified live through the actual browser against the real
   backend and real PostgreSQL, with real reload/deep-link persistence
   confirmed. The specific "cite a genuinely existing SecurityCondition"
   sub-case has no browser-reachable way to create that prerequisite
   record (§13.2) and is instead proven by a dedicated real-PostgreSQL
   integration test — not a mock, but not a browser click either. This
   is disclosed here rather than glossed over.
5. **Are tenant/global security boundaries still proven?** Yes —
   unchanged tenant-isolation guarantees, re-verified passing after
   every change in this slice, plus new tests proving no new filter
   parameter creates a cross-tenant leak.
6. **Are performance/query plans acceptable at the tested dataset
   size?** Yes at 50,000 rows / ~2,400 rows per tenant (§13.4) — all
   measured query shapes execute in under 12ms, including deep-offset
   pagination. Not tested, and not claimed, at a materially larger
   scale.
7. **Is the capability deployable and operable without developer
   intervention?** Yes — the scheduler requires no deployment change
   (starts with the API process); the manual/external-cron trigger
   path remains available and unchanged; migration `0168` is a plain
   additive index migration with a verified clean upgrade/downgrade
   cycle.

**IOC INTELLIGENCE PRODUCTION CERTIFIED**, with one disclosed,
narrowly-scoped verification gap (§13.2/finding 4 above: the
successful-evidence-citation path was proven by integration test, not
a browser click, because no UI path exists anywhere in the product to
create the prerequisite record) — not a blocker to the four assigned
production blockers, all four of which are closed and verified above.
