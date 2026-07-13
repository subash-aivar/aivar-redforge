# M11 — Gated Safe Active Validation Orchestration

Full detail report. See [M11_COMPLETION_CHECKPOINT.md](M11_COMPLETION_CHECKPOINT.md)
for the concise summary.

## 1. Architecture decision

M11 is the first milestone to perform REAL active security validation —
genuine DNS resolution, TCP connects, TLS handshakes, and HTTP fetches —
against explicitly authorized targets. Every explicit prohibition in the
brief (no exploit payloads, no reverse shells/C2, no credential theft, no
brute force, no persistence/privilege-escalation/lateral-movement, no
destructive actions, no malware behavior, no arbitrary shell execution, no
Metasploit/Nuclei, no unrestricted scanning, no full port scans) was honored
by construction: the only thing the server can ever do is run one of 6
fixed, read-only observation steps against one canonical target, and the
client can never submit a step, port, command, or module.

M10's `ExecutionPolicyService` is reused unchanged as the mandatory gate —
`action_class="active_validation"` already existed in M10's closed
`ActionClass` taxonomy as an authorizable class, so no M10 change was
needed. `domain/security_conditions/` (M8) is reused unchanged for
condition ingestion — `SourceCategory.ACTIVE_VALIDATION` was added as its
first real producing path (`AI_RED_TEAM` remains excluded, per that
enum's own docstring). No Security Graph ontology bump — validation
executions reference existing canonical entities (`ai_target`, the
`AIAsset` resolved via `TenantAssetService.get_or_create_for_target()`)
rather than becoming graph nodes themselves.

## 2. Canonical domain

`domain/validation_execution/`:

- **`ValidationExecution`** (aggregate root) — `organization_id`,
  `target_id`, `requester_user_id`, `profile`, `status`, `policy_decision_id`,
  `policy_reason_code`, `cancellation_requested`, `limits`, `failure_reason`,
  child `ValidationStep` list.
- **`ValidationStep`** (child entity) — `step_type`, `order`, `status`,
  `started_at`/`completed_at`, bounded `evidence` tuple, `error_category`.
- **`ExecutionEvent`** (standalone, NOT part of the aggregate's
  buffered-domain-event pattern) — `execution_id`, `sequence`, `event_type`,
  bounded `payload`, `occurred_at`. Written immediately by the application
  service for genuine live-progress visibility; a completely separate
  concern from `ValidationExecutionEvent`/`ExecutionCreated` etc., the
  buffered domain events the aggregate itself collects.

### Lifecycle

```
PENDING --begin_policy_check()--> POLICY_CHECKING
POLICY_CHECKING --authorize(decision_id)--> AUTHORIZED
POLICY_CHECKING/AUTHORIZED --deny(decision_id, reason)--> DENIED (terminal)
AUTHORIZED --fail_preflight(reason)--> FAILED (terminal, zero steps — target normalization failure)
AUTHORIZED --start()--> RUNNING
RUNNING --finish()--> COMPLETED | PARTIALLY_COMPLETED | FAILED (terminal — computed from real step outcomes)
PENDING/POLICY_CHECKING/AUTHORIZED/RUNNING --cancel()--> CANCELLED (terminal)
```

`deny()` is legal from `PENDING`, `POLICY_CHECKING`, and — deliberately —
`AUTHORIZED`, since the second, time-of-use policy check happens after the
first `authorize()` call; without that, the mandatory second gate could
never actually transition to DENIED. `request_cancellation()` only sets a
flag on any non-terminal execution; the running step loop is the only thing
that ever calls `cancel()` (the status transition), after observing the
flag via a fresh database read before every step dispatch.

## 3. Mandatory M10 policy gate, twice

`ValidationExecutionService.create_and_run()`:

1. Create execution → `begin_policy_check()` → `ExecutionPolicyService.evaluate(action_class="active_validation", entity_refs=[("ai_target", target_id)])`. Not ALLOW → `deny()`, zero steps ever created.
2. `authorize()` → **second** `evaluate()` call, immediately before target
   resolution/plan-building. Not ALLOW → `deny()` again, zero steps.
3. Only past both gates: resolve the canonical target's endpoint,
   normalize it, build the step plan, `start()`, dispatch steps.

This closes the "ALLOW at request time, but the authorization was
revoked/expired before the (possibly delayed) dispatch actually ran" gap —
proven with a fake `ExecutionPolicyPort` returning ALLOW on the first call
and DENY on the second, within one `create_and_run()` invocation (a
sequencing test no real M10 HTTP workflow could express, since both calls
happen synchronously inside one method).

## 4. Network boundary / SSRF / DNS-rebinding defense

`application/validation_execution/network_boundary.py`:
`classify_address()` uses Python's `ipaddress` module plus a known-metadata
denylist (`169.254.169.254`, `fd00:ec2::254`, `169.254.170.2`) to categorize
every resolved address as `PUBLIC`/`LOOPBACK`/`LINK_LOCAL`/`PRIVATE`/
`MULTICAST`/`RESERVED`/`METADATA`/`UNSPECIFIED`. `ALLOWED_ADDRESS_CLASSES =
{PUBLIC}` — categorical denial by default, no per-authorization "explicit
internal range" allowance exists in M10's scope model today (scope entities
are canonical IDs, not IP ranges), documented as a deliberate v1 scope
limit rather than a silently-missing feature. Fail-closed for unparseable
input (`RESERVED`, denied).

Applied identically to the INITIAL DNS resolution and to EVERY redirect
hop's re-resolution in `fetch_http_metadata()` — a redirect can never pivot
into a class this module denies, regardless of what the original target
classified as. The DNS-rebinding / foreign-target defense: a redirect hop's
resolved addresses must intersect the ORIGINAL target's own validated
resolution set, or it is refused — even if the redirect's addresses are
individually public (a genuinely different, unauthorized target resolves
to different addresses and is correctly treated as a pivot attempt, not a
legitimate redirect).

## 5. Real adapters

`application/validation_execution/network_adapters.py` — every function is
a pure async function over explicit bounds, no adapter ever executes a
client-supplied command/path/expression, all destinations derive entirely
from `AITarget.endpoint` via `target_normalizer.normalize_target()`:

- `resolve_dns()` — bounded async DNS resolution, bounded retry, classifies
  every resolved address, denies on the first non-PUBLIC one (fail closed).
- `check_tcp_connectivity()` — real `asyncio.open_connection()`.
- `perform_tls_handshake()` — real handshake via `ssl.create_default_context()`
  (platform default trust store, real certificate chain + hostname
  verification), extracting protocol version, cipher, subject/issuer CN,
  validity dates, SAN count, SHA-256 fingerprint. Proven against a genuine,
  freshly-generated self-signed certificate in the real-PostgreSQL proof
  suite (see §9) — real cryptographic verification, not simulated.
- `fetch_http_metadata()` — manual (never `httpx`'s automatic) redirect
  following so every hop is independently re-normalized, re-resolved, and
  boundary-checked; never reads/returns the response body, only metadata.
- `evaluate_security_headers()` — pure, deterministic, 3 stable rules
  (`MISSING_HSTS_HEADER` only for HTTPS targets, `MISSING_CSP_HEADER`,
  `MISSING_X_CONTENT_TYPE_OPTIONS_HEADER`).
- `ServiceReachabilityResult` — explicit, documented distinction between
  PORT CONNECTIVITY OBSERVED (a TCP connect succeeded) and SERVICE
  REACHABILITY VALIDATED (an application-layer response was actually
  observed) — a bare open port never gets conflated with a healthy service.

`_REDACTED_HEADER_NAMES` (authorization, cookie, set-cookie,
proxy-authorization, www-authenticate) are stripped before any header dict
is persisted, returned via API, or written into an event payload.

## 6. Observation / condition / finding semantics

A TCP connect succeeding, or an HTTP 200, is a connectivity/reachability
*observation* — never itself a Finding or SecurityCondition. Only the
deterministic security-header rule evaluator ever produces a
`SecurityCondition` (`source_category="active_validation"`,
`evidence_state="validated"` — never `"suspected"`, since this is a real,
completed observation, not an inference). Deduplication is inherited
unchanged from M8's `build_condition_identity_key()` upsert — a repeated
validation of the same asset/rule updates the same row rather than creating
a duplicate.

## 7. Execution limits

`ExecutionLimits` (frozen dataclass, one profile default —
`SAFE_ACTIVE_BASELINE_V1`): `max_steps=6`, `max_resolved_addresses=4`,
`max_ports=4`, `per_step_timeout_seconds=5.0`,
`total_execution_timeout_seconds=30.0`, `redirect_limit=3`,
`max_concurrency=1`, `max_events=200`, `max_evidence_items_per_step=5`,
`max_evidence_value_length=500`, `dns_retry_attempts=2`. Event emission
stops (silently, not an error) once `sequence > max_events`.

## 8. API surface

`api/v1/validation_executions.py` — 7 tenant-scoped endpoints:
`POST ""` (create — `target_id` + `profile`, no steps/ports/commands
field), `GET ""` (list, filterable by status), `GET "/summary"` (backend-
derived lifecycle counts, registered before `/{execution_id}` for route
ordering), `GET "/{id}"`, `GET "/{id}/steps"`, `GET "/{id}/events"`
(polling-based live progress — no SSE precedent existed in this codebase,
and polling is real backend-derived progress, simpler to prove
deterministically), `GET "/{id}/result"` (crisp structured facts derived
entirely from persisted step evidence), `POST "/{id}/cancel"`. No direct
adapter import anywhere in this module — the only path to a network
adapter is through `ValidationExecutionService`.

## 9. Bugs found and fixed

**P0 (concurrency)** — `create_and_run()` holds one in-memory
`ValidationExecution` object for its whole lifecycle and calls `_save()`
repeatedly (after `build_plan()`, after `start()`, after every step). Each
`SqlAlchemyValidationExecutionRepository.save()` call unconditionally
overwrote `cancellation_requested` from the in-memory object's (stale)
value. A genuinely concurrent `POST /cancel` — issued via a *different*
service/session — set the DB row's flag to `True`, but the next `_save()`
from the original `create_and_run()` call clobbered it back to `False`
before the running step loop's fresh-read check ever saw it, so the
requested cancellation was silently lost and the execution ran to
completion anyway. Found via the real-PostgreSQL proof (§10) — a debug
script driving a genuinely concurrent cancel against a real Postgres
instance (NullPool, ruling out connection-pool staleness as the cause)
showed a direct check reading `True` immediately after the cancel(), and
`False` moments later after the next in-flight `_save()`. Fixed by making
`cancellation_requested` monotonic in `SqlAlchemyValidationExecutionRepository.save()` (`existing.cancellation_requested = existing.cancellation_requested or model.cancellation_requested` — OR, never overwrite), re-verified: the same scenario now correctly ends `CANCELLED` with the in-flight step and all subsequent steps marked `cancelled`.

No other defects found.

## 10. Real local validation proof

Two proof suites, both against owned, in-process-started local test
servers only — never an external/unrelated internet target:

- `tests/unit/test_validation_execution_network_boundary.py` (18 tests) —
  address classification (loopback/link-local/metadata/multicast/private/
  public/malformed), target normalization adversarial cases, and a local
  HTTP server proving redirect-within-resolution-set is followed,
  redirect-to-metadata/foreign-target is blocked, redirect-limit is
  enforced, Authorization/Set-Cookie headers never appear in returned
  metadata, and the exact expected set of missing-header findings is
  produced (no more, no less).
- `tests/integration/test_validation_execution_postgres_proof.py` (7
  tests, real PostgreSQL, self-created/destroyed database) — full pipeline
  against a real local HTTP server (DNS→TCP→HTTP→security-headers→
  condition ingestion, `MISSING_CSP_HEADER`/`MISSING_X_CONTENT_TYPE_OPTIONS_HEADER`
  correctly observed); a **real TLS handshake** against a genuine,
  freshly-generated self-signed certificate (`cryptography` library, an
  in-process HTTPS server) — real protocol version, real cipher, real
  subject CN, a real 64-hex-char SHA-256 fingerprint; repeated execution
  does not duplicate the ingested condition; events persisted in strictly
  increasing sequence; a policy revocation between the two mandatory
  gates blocks all network activity (zero steps, `policy.calls == 2`);
  the P0 cancellation race (§9), reproduced and then re-verified fixed;
  execution history and events survive a fresh service instance reading
  the same database (restart persistence).

A documented, test-only monkeypatch
(`network_adapters.ALLOWED_ADDRESS_CLASSES` extended to include
`LOOPBACK`) is used in both suites, and only in the specific tests that
need the full pipeline to succeed against a necessarily-loopback-bound
local test server — every test proving the boundary correctly *denies*
loopback/private/link-local/metadata runs against the real, unpatched
production constant.

## 11. Migration & PostgreSQL proof

Migration 0019 adds `validation_executions`, `validation_execution_steps`,
`validation_execution_events` — composite tenant FKs
(`fk_validation_step_same_tenant`, `fk_validation_event_same_tenant`) on
both child tables referencing `validation_executions(id, organization_id)`,
a `ux_validation_executions_id_org` unique constraint enabling those
composite FKs, `ux_validation_step_order` (execution_id, order_index) and
`ux_validation_event_sequence` (execution_id, sequence) uniqueness, and
query-optimized indexes (org+status, org+target, org+created_at,
org+execution+seq, org+occurred_at).

Clean migration proof: fresh empty database → `alembic upgrade head` ran
0001→0019 in full → `alembic_version` = `0019` → schema inspection
confirmed all 3 tables + FKs + indexes present, no M12 schema →
`downgrade -1` correctly reversed to 0018 (all 3 tables dropped) →
`upgrade head` re-applied cleanly → database destroyed. (An operator
mistake during this step briefly downgraded the shared dev database
instead of the isolated proof database — caught immediately, confirmed
zero data loss since every affected table was empty, and restored to
head before continuing; documented transparently rather than silently
corrected.)

## 12. Live API acceptance

Real server (isolated port 8000), real PostgreSQL (the shared dev
database, restored to head 0019), a genuine `AITarget` created via the
production API pointing at an owned local HTTP test server. Full flow:
register → create org → select → register AI target → create M10
authorization for `active_validation` scoped to the target → submit →
approve (distinct approver, membership seeded directly matching this
codebase's own established test convention for bypassing the invite/accept
email flow) → authorization ACTIVE → create M11 execution → real ALLOW via
the genuine M10 `ExecutionPolicyService` (not a fake) → plan built (5
steps) → real DNS resolution correctly denies the owned target's own
loopback address per the (unpatched, production) network boundary → crisp,
truthful FAILED result (`tcp_reachable: false`, zero fabricated findings,
`failed_steps: ["dns_resolution"]`) → repeated execution stable (2
executions, consistent summary counts, no token leak) → revoke
authorization → new execution immediately DENIED with zero steps
(`AUTHORIZATION_NOT_ACTIVE`) → backend process killed and restarted →
execution/step/event history confirmed persisted → readiness check passes
(migration-head validator confirms 0019) → second tenant gets 404 on the
foreign execution and an empty list → no bearer token or secret found in
any response body → unauthenticated request correctly 401. All steps PASS.

## 13. Browser acceptance

**BLOCKED** — for the identical, pre-existing environment reason M10's own
checkpoint documented: the preview browser never attaches a React
effect/event-handler tree to any element on any page in this app.
Reproduced on the new `/validation-operations` page AND independently
confirmed on the untouched, pre-existing `/authorization` page (same
symptom: stuck on the layout's initial "Loading…" state, `getMe()`'s
`useEffect` never observably firing a network request in a fresh tab) —
proving this is an environment limitation, not a defect introduced by this
milestone. Corroborated by clean `tsc`, a clean production `next build`
(the `/validation-operations` route compiles and is listed), and 65
passing Vitest tests (11 new) exercising the same component tree,
including overview counts, empty/error states, unrecognized-status→UNKNOWN
rendering, step/event/result detail rendering, cancel-button lifecycle
gating, and the create-form's target-required validation.

## 14. Quality gates

Backend: `ruff check .` — all checks passed. `mypy --strict` on `src/` —
**0 issues, 573 files**. `pytest` — **3,755 passed, 5 skipped** (baseline
3,697; +58 net — 51 new M11 adversarial tests + 7 new real-PostgreSQL proof
tests, 0 regressions).

Frontend: `tsc --noEmit` — 0 errors. `next build` — succeeds,
`/validation-operations` route present (4.72 kB, 107 kB first load, in
line with sibling feature pages). `npm audit` — 2 pre-existing moderate
advisories, unchanged, no new dependencies. `vitest` — **65 passed**
(baseline 54; +11 new).

## 15. Documentation

This report, [M11_COMPLETION_CHECKPOINT.md](M11_COMPLETION_CHECKPOINT.md),
and a new M11 row in `docs/PROJECT_CONTEXT.md`'s Completed Milestones
table (§10).
