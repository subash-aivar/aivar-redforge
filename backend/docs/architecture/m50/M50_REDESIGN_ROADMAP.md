# M50 Redesign Roadmap — Vulnerability Engine Consolidation

Status: **APPROVED — planning document, no code changes**
Date: 2026-07-30
Builds on (frozen, not re-litigated): `backend/docs/architecture/m50/M50_ARCHITECTURE_AUDIT_ADR.md`

This document supersedes the original M50A "new Vulnerability Management
bounded context" milestone, which the user has cancelled. It does not
overwrite either existing M50 document. It re-verifies the audit's
load-bearing claims directly against current source (Section 0) and then
lays out the full implementation roadmap, split into six single-responsibility
milestones M50A–M50F.

---

## 0. Re-verification of audit claims against current source (2026-07-30)

All claims below were independently re-checked, not assumed from the audit.

| Claim | Audit said | Re-verified now | Status |
|---|---|---|---|
| `vulnerability` migrations | 0054–0057 | `ls migrations/versions/ \| grep -i vulnerab` → `0054_vulnerability_foundation.py`, `0055_vulnerability_sources.py`, `0056_vulnerability_lifecycle.py`, `0057_vulnerability_read_models.py`, plus `0087_analytics_vulnerability_events.py` (an analytics-context migration that references vulnerability events, not a `vulnerability`-schema migration — does not change ownership) | **Confirmed** |
| Alembic head | not explicitly stated as a number, but audit predates `risk_engine`/`attack_surface_management` work | Current highest version file: `0157_attack_surface_management_foundation.py` (with `0156_risk_engine_foundation.py` immediately prior). Both are untracked/uncommitted in the working tree per `git status`. Next available migration number for any M50 scanning-domain work is **0158**. | **Confirmed, updated** — audit did not need to state a number since Phase 1 makes no migrations; this roadmap needs it for M50C and records it here. |
| Zero cross-imports, `vulnerability` ↔ `vulnerability_engine` | none in either direction | `grep -rn "from vulnerability_engine\|import vulnerability_engine" src/` outside `src/vulnerability_engine/` itself: zero hits. `grep -rn "vulnerability_engine" src/vulnerability/`: zero hits. `grep -rln "from vulnerability\.\|import vulnerability\." src/vulnerability_engine/` (excluding self): zero hits. `grep -rln "...vulnerability_engine" tests/` outside `tests/vulnerability_engine/`: zero hits. | **Confirmed** |
| `ScanJob`/`ScanPolicy`/`ScanTarget` exist and are non-trivial | genuine scan lifecycle/scheduling domain, no equivalent in `vulnerability` | File sizes: `domain/aggregates/scan_job.py` 261 lines, `scan_policy.py` 120 lines, `scan_target.py` 179 lines, `scan_provider_registration.py` 203 lines (794 lines total across the four aggregates), plus `domain/value_objects/scan_window.py` (31 lines), 4 command modules, 4 query modules, 4 DTO modules, 9 port interfaces (`i_scan_dispatcher`, `i_scan_execution_provider`, `i_scan_job_registry`, `i_scan_monitor`, `i_scan_provider_registry`, `i_scan_reader`, `i_scan_scheduler`, `i_scan_target_registry`, `i_scan_writer`), 3 in-memory registries, and 4 application services (`scan_orchestration_service.py`, `scan_provider_service.py`, `scan_target_application_service.py`, `scan_target_inventory_service.py`), 4 event modules. `vulnerability/domain/` has no `scanning/` or equivalent subpackage — confirmed absent. | **Confirmed** |
| No worker/scheduler registration for either package | not explicitly checked by audit | `find . -iname "*worker*" -o -iname "*celery*"` across the repo returns worker modules for `integration_hub`, `analytics`, `automated_action`, `reporting`, `replay`, `network_monitoring`, `ml_pipeline`, `credential_vault`, `autonomous_intelligence` — **none** for `vulnerability` or `vulnerability_engine`. Neither package has a background job/worker registration today. | **New finding, does not change the plan** — scan orchestration will need a worker/scheduler eventually (M50C scope), but there is nothing pre-existing to migrate or break. |
| `vulnerability`'s existing directory conventions for a provider-registry-like subpackage | audit referenced `domain/providers/{registry,adapter}.py` as the "normalize-and-ingest pattern" | Confirmed present: `src/vulnerability/domain/providers/{__init__.py, adapter.py, normalized_finding.py, registry.py}`. `src/vulnerability/domain/` top-level packages are: `aggregates/, entities/, events/, exceptions/, ports/, prioritization/, providers/, repositories/, value_objects/`. `infrastructure/persistence/` has `models/`, `repositories/`, `unit_of_work.py`. `api/v1/` has `lifecycle.py, platform.py, prioritization.py, sources.py, vulnerabilities.py`. These are the conventions M50B/M50C must match. | **Confirmed, used as the target-shape reference** |
| Uncommitted working tree state | not applicable — audit is read-only | `git status --short` shows modified `backend/pyproject.toml`, `backend/src/redforge/api/v1/__init__.py`, `backend/src/redforge/app.py`, plus untracked `backend/docs/architecture/m48/`, `backend/docs/architecture/m50/`, `backend/src/attack_surface_management/`, `backend/src/risk_engine/`, migrations 0156/0157, and their test trees — all from prior, unrelated milestone work (M48/risk_engine/attack_surface_management), not from this task. Branch is `main`. | **Noted for context; no action taken, nothing touched by this task** |

**Discrepancy check requested by the task brief:** none found. Every load-bearing
claim in the audit ADR holds under direct re-verification. The one addition is
the concrete current alembic head (**0157**, next free number **0158**) and the
confirmation that no worker/scheduler infrastructure exists yet for either
package — neither changes the audit's conclusions or this plan's structure.

---

## 1. Package ownership matrix

| Package | Role after consolidation | Domain | Application | Infrastructure | API | Fate |
|---|---|---|---|---|---|---|
| `src/vulnerability/` | **Sole canonical owner** of vulnerability lifecycle (CVE/CVSS/EPSS/KEV definitions, per-asset instances, remediation, exceptions, evidence, sources) **and**, after M50C, scan orchestration | Gains `domain/scanning/` subpackage | Gains scanning commands/queries/dtos/services | Gains scanning PG models/repositories/migration(s) starting at `0158` | Gains a new `scanning.py` (or similarly named) route module, mounted alongside existing 5 | **Kept, extended** |
| `src/vulnerability_engine/` | Deprecated duplicate, scan-orchestration source material only until ported | Frozen at M50A, deleted at M50F | Frozen at M50A, deleted at M50F | Already empty (no change) | Already empty (no change) | **Deleted (M50F)** |
| `redforge.domain.threat_intel.vulnerability_entity` (M22) | Untouched — different bounded concern (global CVE reference catalog, not tenant aggregate) | N/A | N/A | N/A | N/A | **Out of scope, no action** |

---

## 2. Aggregate ownership matrix — final disposition

| Aggregate / concept | Current owner(s) | Final disposition | Milestone |
|---|---|---|---|
| `Vulnerability` (CVE/CVSS/EPSS/KEV definition, tenant-scoped lifecycle) | `vulnerability.domain.aggregates.vulnerability` | **Keep** — sole canonical implementation, no change | — |
| `VulnerabilityInstance` (per-asset occurrence) | `vulnerability.domain.aggregates.vulnerability_instance` | **Keep** | — |
| `RemediationPlan` / `RemediationTask` / `RemediationVerification` | `vulnerability.domain.aggregates.remediation_plan` | **Keep** | — |
| `VulnerabilityException` (risk acceptance) | `vulnerability.domain.aggregates.vulnerability_exception` | **Keep** | — |
| `VulnerabilityEvidence` | `vulnerability.domain.aggregates.vulnerability_evidence` | **Keep** | — |
| `VulnerabilitySource` (feed registration) | `vulnerability.domain.aggregates.vulnerability_source` | **Keep** | — |
| `VulnerabilityDefinition` (duplicate CVE/CVSS/EPSS/KEV record) | `vulnerability_engine.domain.aggregates.vulnerability_definition` | **Delete** — fully superseded by `vulnerability.Vulnerability`, zero unique capability, zero persisted data, zero consumers | Marked deprecated M50A, deleted M50F |
| `AssetVulnerability` (duplicate per-asset correlation) | `vulnerability_engine.domain.aggregates.asset_vulnerability` | **Delete** — fully superseded by `vulnerability.VulnerabilityInstance` | Marked deprecated M50A, deleted M50F |
| `ScanProviderRegistration` | `vulnerability_engine.domain.aggregates.scan_provider_registration` | **Port** — adjacent-not-identical to `VulnerabilitySource`; folded into the new `vulnerability/domain/scanning/` subpackage as the scan-provider-registration piece of scan orchestration (kept distinct from `VulnerabilitySource`, not merged into it — merging two aggregates with different lifecycle triggers, one passive-feed and one active-scan, would itself be new domain modeling, out of scope for a consolidation milestone) | Ported M50B, wired M50C |
| `ScanJob` | `vulnerability_engine.domain.aggregates.scan_job` | **Port** — the clearest non-duplicated capability in the whole audit | Ported M50B, wired M50C |
| `ScanPolicy` | `vulnerability_engine.domain.aggregates.scan_policy` | **Port** | Ported M50B, wired M50C |
| `ScanTarget` | `vulnerability_engine.domain.aggregates.scan_target` | **Port**, referencing `vulnerability.Vulnerability`/`VulnerabilityInstance` by ID only, not by object graph | Ported M50B, wired M50C |
| `VulnerabilityAsset` (asset fingerprinting) | `vulnerability_engine.domain.aggregates.vulnerability_asset` | **Defer / flag, do not port in M50** — per audit Section 6 Phase 2, this must be evaluated against whichever asset/inventory bounded context is canonical (`inventory`, `attack_surface_management`) before porting, to avoid creating a *third* duplicate of asset modeling. Left inside `vulnerability_engine` until that separate, out-of-scope architecture question is resolved; if `vulnerability_engine` is deleted (M50F) before that resolution, its `VulnerabilityAsset` code is preserved via git history and this document's line-item reference, not by keeping the package around indefinitely. | Explicitly out of scope for M50A–F; flagged for a future milestone |

---

## 3. Migration dependency graph

```
M50A (freeze/declare)
   │  no schema changes — documentation only
   ▼
M50B (port scan domain, no wiring)
   │  no schema changes — domain/application code only, no migrations,
   │  no infrastructure/API yet — new code is inert, unreachable
   ▼
M50C (wire scan orchestration: infra + API)
   │  migration 0158_vulnerability_scanning_foundation.py (new tables:
   │  scan_job, scan_policy, scan_target, scan_provider_registration,
   │  under the existing "vulnerability" Postgres schema, following the
   │  0054–0057 partitioning/tenant-isolation conventions)
   │  → depends on 0157_attack_surface_management_foundation.py being
   │    the current head at execution time; if other milestones land
   │    migrations between now and M50C execution, renumber 0158 to
   │    whatever the actual head + 1 is at that time — never hardcode
   │    a stale number into a real migration file
   ▼
M50D (deprecation marking + compatibility notes on vulnerability_engine)
   │  no schema changes
   ▼
M50E (final pre-deletion verification gate)
   │  no schema changes — re-run cross-import grep, confirm M50C tests
   │  green, confirm no new consumers appeared since M50A
   ▼
M50F (delete vulnerability_engine)
   │  no schema changes — vulnerability_engine never had migrations,
   │  so there is nothing to drop; deleting the package deletes only
   │  Python source and its own test tree
```

**Key dependency rule:** M50C's migration must not be written/numbered until
M50C actually executes, because this is a live monorepo where other
milestones (e.g. a hypothetical M51) may land migrations after 0157 before
M50C starts. The number **0158 is a snapshot as of 2026-07-30**, not a
reservation.

---

## 4. Backward compatibility plan

- **No dual-write, no data backfill, no cutover window is required anywhere
  in this roadmap.** This is the single biggest simplifying fact confirmed
  by both the audit and this re-verification: `vulnerability_engine` has
  zero persisted rows (no migrations ever existed for it) and zero live API
  consumers (no router ever mounted it). There is no "old data" to migrate
  and no "old traffic" to redirect.
- The only artifacts with any external-facing shape are `vulnerability_engine`'s
  337 unit tests, which exercise in-memory registries directly — these are
  test-only consumers, not production consumers, and are deleted alongside
  the package in M50F.
- For the **ported** scan-orchestration domain (M50B/M50C), "backward
  compatibility" doesn't apply in the conventional sense (nothing depended
  on the old, unwired `vulnerability_engine.ScanJob` in production) — but
  **contract preservation** does apply within the port itself: M50B must
  preserve `ScanJob`/`ScanPolicy`/`ScanTarget`/`ScanProviderRegistration`'s
  existing public method signatures, state-machine transition tables, and
  event names verbatim during the copy, so that the 337 existing unit tests
  for these four aggregates can be **re-pointed** (import path changed,
  assertions unchanged) at the ported code in `vulnerability/domain/scanning/`
  as a regression check, rather than rewritten from scratch. This is the
  practical mechanism for proving the port didn't silently change behavior.
- Tenant isolation must be preserved exactly: every ported aggregate already
  carries `TenantMismatch`-style guards in `vulnerability_engine`; M50B must
  confirm these map onto `vulnerability`'s existing tenant-scoping convention
  (the same `organization_id`-bearing pattern used by `Vulnerability`/
  `VulnerabilityInstance`) rather than inventing a second tenant-scoping
  mechanism.

---

## 5. Deprecation strategy

- **M50A** marks `vulnerability_engine.domain.aggregates.{VulnerabilityDefinition,
  AssetVulnerability}` (the two truly duplicated, not-worth-porting aggregates)
  as deprecated/do-not-extend via docstring annotation and a top-of-file
  comment block referencing this roadmap and the audit ADR. No code deletion,
  no behavior change, tests keep passing exactly as-is.
- **M50A** also corrects the misleading `vulnerability_engine/__init__.py`
  docstring identified by the audit (it currently calls `vulnerability` "the
  unrelated... scaffold package," which is backwards — `vulnerability` is
  the mature, mounted implementation). The audit explicitly flagged this as
  a "1-line doc fix... not part of this read-only audit's deliverable" —
  M50A is the correct milestone to actually make that fix, since M50A is no
  longer read-only-only, it is the first real step of the consolidation.
- **M50D** marks the *entire remaining* `vulnerability_engine` package
  (everything not yet ported by M50B/M50C — i.e., `VulnerabilityDefinition`,
  `AssetVulnerability`, and any leftover scan-domain scaffolding not cleanly
  removable in M50B) as deprecated at the package level: a top-level
  `DEPRECATED.md` note is **not** created (the task constraint allows only
  one new file for this whole roadmap effort, already spent on this
  document) — instead, deprecation is recorded by editing existing
  docstrings only, plus this roadmap document serving as the durable record.
- **No compatibility shim is needed.** Given zero current importers
  (re-confirmed in Section 0), there is no call site anywhere that would
  need a shim, adapter, or re-export to keep functioning. A shim would be
  manufacturing complexity to protect against a consumer that does not
  exist.
- **Grace period:** one sprint between M50D (deprecation marking complete)
  and M50E (verification gate) purely for human review/objection, matching
  the audit's own recommendation. This is a human-process control, not a
  technical migration window.

---

## 6. Rollback strategy per phase

| Milestone | What could go wrong | Rollback |
|---|---|---|
| **M50A** | Docstring edits accidentally break an import (e.g. a stray syntax error in a comment block) | `git revert` the single commit; zero functional code touched, so risk of needing rollback is near-zero. Tests would catch it immediately (337 `vulnerability_engine` tests + 519 `vulnerability` tests both still run). |
| **M50B** | Ported scan aggregates diverge from source behavior (state machine, event names, tenant guards) during the copy | New code lives in an entirely new `vulnerability/domain/scanning/` subpackage, unreferenced by anything else in the app (no wiring yet per M50B scope) — `git revert`/delete the new subpackage; nothing else in `vulnerability` or `vulnerability_engine` was modified, so there is no ripple effect. |
| **M50C** | New migration `0158` has a schema defect (bad index, wrong partition key, tenant-isolation gap), or new API routes break the mounted router, or new services have bugs reachable in production | Standard alembic `downgrade` for `0158` (write its `downgrade()` to drop exactly what `upgrade()` created — same discipline as 0054–0057). API routes: unmount the new route module from `redforge/api/v1/__init__.py` (one-line revert) without touching the other 5 already-mounted `vulnerability` route modules. Since this is the first milestone with real production surface area, it is the one milestone that needs a real regression gate (full `vulnerability` + new scanning test suite green, plus a manual smoke test of the new endpoints) before being considered done — not just a doc/code review. |
| **M50D** | Deprecation docstrings/annotations are wrong or overly aggressive (e.g. accidentally marking something still in active use) | Re-verify against Section 0's grep results before marking; if wrong, revert the docstring edit commit. No functional risk since nothing is deleted or disabled at this stage. |
| **M50E** | Verification gate incorrectly concludes "safe to delete" when a new consumer appeared between M50A and M50E (e.g. another team started experimenting with `vulnerability_engine` mid-roadmap) | This is precisely what the gate exists to catch — re-run the full cross-import grep from Section 0 as a hard gate, not a formality. If it finds a new hit, M50E halts and does not proceed to M50F; the new consumer must be resolved (migrated to `vulnerability` or explicitly re-scoped) before deletion proceeds. No code changes happen in M50E itself, so there's nothing to roll back — it either passes or blocks. |
| **M50F** | Deletion turns out to be premature (some overlooked consumer, or the one-sprint grace period surfaces a legitimate objection) | Because this is a git-tracked monorepo, the entire `vulnerability_engine` package and its test tree are recoverable via `git revert` of the single deletion commit, or `git checkout <pre-M50F-commit> -- backend/src/vulnerability_engine backend/tests/vulnerability_engine`. Recommend the deletion commit be a single, isolated commit (no other changes bundled in) specifically so this revert is clean. |

---

## 7. Risk assessment per phase (concrete, not generic)

- **M50A (freeze/declare):** Risk is near-zero — docstring/comment-only
  changes. The one concrete risk: if the docstring correction to
  `vulnerability_engine/__init__.py` is done carelessly and the file has
  any executable top-level code beyond the module docstring (needs
  confirming at implementation time — not verified in this pass since it's
  out of scope for a planning document to read every line), a bad edit
  could break `import vulnerability_engine` and fail all 337 of its tests.
  Mitigation: run the `vulnerability_engine` test suite immediately after
  the docstring edit, before considering M50A done.

- **M50B (port scan domain, no wiring):** Concrete risk is **silent
  behavioral drift** during the copy — e.g. the ported `ScanJob` state
  machine allows a transition the original didn't, or an event field gets
  renamed inconsistently with `vulnerability`'s existing event-naming
  convention (audit noted `vulnerability`'s events are like
  `VulnerabilityDiscovered`/`VulnerabilityEnriched` — past-tense, no
  redundant prefix — while `vulnerability_engine`'s scan events need
  checking against that same convention at port time). Mitigation: re-point
  the existing scan-domain unit tests at the new location unchanged (per
  Section 4) as a mechanical drift detector — if ported code still passes
  tests written against the *original* behavior, drift risk is low. A
  second concrete risk: **tenant-isolation regression** if the port doesn't
  correctly carry over `TenantMismatch` guards into `vulnerability`'s
  tenant-scoping convention. Mitigation: this is exactly why M50B explicitly
  does not include wiring — an isolated, unreferenced subpackage cannot leak
  cross-tenant data in production regardless of internal bugs, because
  nothing can reach it yet.

- **M50C (wire scanning: infra + API + migration):** This is the
  highest-risk milestone in the roadmap, the first one touching production
  schema and a mounted router. Concrete risks: (1) migration `0158`
  colliding with a migration number claimed by concurrent unrelated work —
  mitigation: re-check the actual head immediately before writing the
  migration, not rely on this document's snapshot of 0157; (2) new scan
  orchestration endpoints needing background job/worker infrastructure that
  doesn't exist yet for either `vulnerability` or `vulnerability_engine`
  (confirmed in Section 0) — this is genuinely new infrastructure work, not
  a port, and should be scoped carefully within M50C or split into its own
  sub-step so "wiring" doesn't silently balloon into unplanned scheduler
  design; (3) `ScanTarget` referencing `Vulnerability`/`VulnerabilityInstance`
  by ID risks an accidental foreign-key/ORM relationship being added instead
  of a true opaque-reference (the audit's own convention, matching
  `attack_surface_management`↔`risk_engine`) — mitigation: code review
  specifically checking for this before merge.

- **M50D (deprecation marking):** Risk is a false-positive deprecation
  (marking something still needed). Mitigation: gate on Section 0's grep
  results, re-run fresh at M50D execution time since time will have passed
  since this document was written.

- **M50E (verification gate):** Risk is a false-negative gate (concluding
  "clear to delete" when it isn't). Mitigation: this milestone's entire
  purpose is being a hard, mechanical, re-run-the-grep gate — treat any
  ambiguity as a block, not a judgment call, consistent with the audit's
  evidentiary style.

- **M50F (delete):** Concrete risk is deleting the still-unresolved
  `VulnerabilityAsset` aggregate (Section 2) before its cross-context
  question (inventory/attack_surface_management overlap) is resolved
  elsewhere, permanently losing that modeling reference except via git
  history. Mitigation: this roadmap explicitly does not require `M50F` to
  wait on that unrelated resolution (git history is a sufficient safety
  net, and keeping a whole package alive indefinitely for one unmigrated
  aggregate has its own cost), but the M50F commit message must explicitly
  note `VulnerabilityAsset` is not yet superseded anywhere, only preserved
  in history, so a future asset-modeling effort knows to look at this
  specific commit rather than assuming a clean prior migration exists.

---

## 8. Milestone breakdown — M50A through M50F

**M50A — Freeze, declare, and correct the misleading docstring.**
In scope: mark `vulnerability_engine.domain.aggregates.{VulnerabilityDefinition,
AssetVulnerability}` (and their value objects/events) as deprecated/do-not-extend
via docstring/comment annotation only; fix the `vulnerability_engine/__init__.py`
docstring that incorrectly calls `vulnerability` an "unrelated... scaffold
package"; formally record in code comments that `vulnerability` (M27) is the
canonical bounded context. Out of scope: any code deletion, any new domain
code, any wiring, any migration, touching `ScanJob`/`ScanPolicy`/`ScanTarget`/
`ScanProviderRegistration` (those are untouched until M50B). Gate: full
`vulnerability` (519 tests) and `vulnerability_engine` (337 tests) suites
still green after the docstring edits; no import errors.

**M50B — Port scan-orchestration domain code, no wiring.**
In scope: copy `ScanJob`, `ScanPolicy`, `ScanTarget`, `ScanProviderRegistration`
(domain aggregates + their value objects, events, ports, commands, queries,
DTOs, application services, and in-memory registries) from `vulnerability_engine`
into a new `vulnerability/domain/scanning/` subpackage (mirroring
`vulnerability`'s existing top-level domain layout: `aggregates/`,
`value_objects/`, `events/`, plus an application-layer equivalent under
`vulnerability/application/scanning/` if that split matches existing
`vulnerability` application-layer conventions — confirm exact placement
against `vulnerability/application/`'s current structure at implementation
time), adjusting only what's needed to fit `vulnerability`'s tenant-scoping
and event-naming conventions and to reference `Vulnerability`/
`VulnerabilityInstance` by ID only (opaque reference, no object graph).
Re-point the existing scan-domain unit tests at the new location as a
mechanical drift check. Out of scope: any Postgres model, repository,
migration, API route, or router mounting (the ported code remains completely
unreferenced by the running application — this is a pure code-relocation
milestone); touching `VulnerabilityDefinition`/`AssetVulnerability` (those
are deleted, not ported, in M50F); resolving `VulnerabilityAsset`'s
inventory/ASM overlap (explicitly deferred). Gate: ported test suite passes
unchanged against the new location; `vulnerability`'s existing 519 tests
still pass untouched; zero new import edges into `vulnerability_engine`
from `vulnerability`.

**M50C — Wire scan orchestration into infrastructure and API.**
In scope: add SQLAlchemy ORM models and Postgres repositories for the M50B-ported
aggregates under `vulnerability/infrastructure/persistence/`, following the
same patterns as the existing 6 repositories; write migration
`NNNN_vulnerability_scanning_foundation.py` (number = current alembic head + 1
at execution time, snapshotted as 0158 as of this writing) creating the
necessary tables under the existing `vulnerability` Postgres schema with
tenant-isolation indexes matching 0054–0057's conventions; add a new API
route module (e.g. `vulnerability/api/v1/scanning.py`) exposing scan
job/policy/target/provider endpoints, and mount it in
`redforge/api/v1/__init__.py` alongside the existing 5 `vulnerability`
route modules. Any background job/scheduler infrastructure genuinely
required for scan execution (none currently exists for either package, per
Section 0) is in scope here but should be scoped narrowly — reuse whatever
worker/scheduler pattern another mature context already uses (e.g.
`analytics`'s or `reporting`'s scheduler-worker pattern) rather than
inventing a new one. Out of scope: touching `VulnerabilityDefinition`/
`AssetVulnerability`/anything else still inside `vulnerability_engine`;
`VulnerabilityAsset`. Gate: new migration applies cleanly with a working
`downgrade()`; new endpoints pass integration tests with a live DB session
(the thing `vulnerability_engine`'s tests could never do); full regression
suite green; manual smoke test of at least one full scan-job lifecycle
through the new API.

**M50D — Mark `vulnerability_engine` deprecated at the package level; add compatibility notes.**
In scope: once M50C confirms the scan-orchestration capability now lives
natively in `vulnerability`, mark the *entire remaining* `vulnerability_engine`
package (everything not ported: `VulnerabilityDefinition`, `AssetVulnerability`,
and any scan-domain scaffolding intentionally left behind by M50B, e.g. if
`VulnerabilityAsset` fingerprinting code remains) as deprecated via
docstring/comment annotations referencing this roadmap and stating the
package is scheduled for deletion; no compatibility shim is created (Section
5 — none is needed, zero current importers). Out of scope: any deletion, any
new code, any wiring changes to the now-live M50C scanning API. Gate: grep
re-confirms zero cross-importers before and after the docstring pass;
`vulnerability_engine`'s remaining tests still pass unchanged (deprecation
markers must not be load-bearing / must not change runtime behavior).

**M50E — Final verification gate before deletion.**
In scope: re-run the full cross-import grep from Section 0 (`from
vulnerability_engine`/`import vulnerability_engine` across `src/` and
`tests/` outside the package's own tree) as a hard pass/fail gate; confirm
M50C's ported scanning capability has its own passing test suite
independent of `vulnerability_engine`; confirm the one-sprint human-review
grace period (Section 5) has elapsed with no objections raised. Out of
scope: any code changes whatsoever — this is a read-only checkpoint
milestone, structurally identical in spirit to the original M50 audit. If
the gate fails (new consumer found, ported tests not green, or an open
objection), M50E blocks and the roadmap halts at this milestone until
resolved — M50F does not proceed. Gate: this milestone's own pass/fail
determination, documented explicitly (a short addendum note, not a new
top-level file, appended to this roadmap or recorded in the M50F commit
message) is the gate for M50F.

**M50F — Delete `vulnerability_engine`.**
In scope: delete `backend/src/vulnerability_engine/` and
`backend/tests/vulnerability_engine/` in a single, isolated commit
referencing this roadmap and the original audit ADR; commit message must
explicitly note that `VulnerabilityAsset` (Section 2) was not ported and is
only recoverable via git history, for the benefit of any future
asset-modeling effort. Out of scope: any other changes bundled into the
same commit (keep it a clean, revertable, single-purpose deletion); any
further changes to `vulnerability` (it is already complete as of M50C). Gate:
M50E passed cleanly; full regression suite green after deletion (proves
nothing outside the deleted package silently depended on it); this is the
terminal milestone of the M50 roadmap.

---

## Discrepancy note

No discrepancies were found between the audit ADR's claims and current
source. All figures (test counts referenced structurally, migration numbers,
zero cross-imports, aggregate file existence) were independently
re-confirmed in Section 0. The only additions beyond the audit are the
concrete current alembic head (0157, snapshot as of 2026-07-30) and the
observation that no worker/scheduler infrastructure exists yet for either
package — both are additive precision, not corrections, and do not change
the audit's conclusions or this roadmap's structure.
