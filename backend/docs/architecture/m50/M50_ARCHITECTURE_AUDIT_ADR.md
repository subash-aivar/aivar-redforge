# M50 ADR — Canonical Vulnerability Ownership Review (Deep Audit)

Status: **DECIDED — M50 REDEFINED as consolidation, not new domain work**
Date: 2026-07-30
Supersedes-context-of: `backend/docs/architecture/m50/M50A_ADR.md` (prior, high-level
finding — not overwritten, read here as background; this ADR independently
re-verifies and extends it with full ownership matrices, dependency graph,
ratio evidence, and a migration strategy).

## 0. Scope of this audit

Full read of every `.py` file under `backend/src/vulnerability/` (133 files) and
`backend/src/vulnerability_engine/` (109 files), every migration under
`backend/src/redforge/infrastructure/database/migrations/versions/` matching
`vulnerabilit*`, the app's router registration
(`backend/src/redforge/api/v1/__init__.py`), and a repo-wide grep for
`from vulnerability`, `import vulnerability`, `from vulnerability_engine`,
`import vulnerability_engine`. A third, related package —
`redforge.domain.threat_intel.vulnerability_entity` — was discovered during
the grep pass and is included for completeness even though it was not named
in the M50A brief.

---

## 1. Repository ownership matrix

| Package | Milestone tag (from own docstrings) | Files | Domain | Application | Infrastructure | API |
|---|---|---|---|---|---|---|
| `backend/src/vulnerability/` | M27 (Phases 1, 2, 4, 5 — per migrations 0054–0057) | 133 `.py` | Full (6 aggregates, 8 entities, 10 VO modules, 6 event modules) | Full (commands/queries/dtos/services/projections) | Full: 6 SQLAlchemy models, 6 Postgres repositories, `unit_of_work.py`, event publishers, graph write adapter, blob store | Full: `api/v1/{vulnerabilities,lifecycle,prioritization,sources,platform}.py`, mounted |
| `backend/src/vulnerability_engine/` | M46A–F (per `__init__.py` and aggregate docstrings) | 109 `.py` | Full (7 aggregates, VO modules for cve/cvss/epss/kev/etc, event modules) | Full (commands/queries/dtos/services), but registries are **in-memory only** | **Empty** — `infrastructure/__init__.py` is 6 lines, no models, no repositories, no migrations | **Empty** — `api/__init__.py` is 5 lines, no routers, not mounted |
| `redforge.domain.threat_intel.vulnerability_entity` (M22) | M22 Phase 1 | 1 file (55 lines) | Single frozen dataclass `Vulnerability` — explicitly a **global, tenant-agnostic reference-data entity**, not a tenant aggregate | Wired into `redforge/api/v1/threat_intel_reference_data.py`, `threat_intel.py` sync jobs | Migration 0035 (`threat_intel_reference_data`), referenced again in 0037/0039 | Mounted: `threat_intel_reference_data_router`, `feed_sync_router` |

**Evidence for the infrastructure/API gap in `vulnerability_engine`:**
- `backend/src/vulnerability_engine/infrastructure/__init__.py` — 6 lines, package marker only, no submodules exist on disk.
- `backend/src/vulnerability_engine/api/__init__.py` — 5 lines, package marker only, no submodules exist on disk.
- `backend/src/redforge/api/v1/__init__.py:95,157` imports and mounts `vulnerability.api.v1.router` (`from vulnerability.api.v1 import router as vulnerability_router` / `router.include_router(vulnerability_router, tags=["vulnerabilities"])`). No `vulnerability_engine` import appears anywhere in `backend/src/redforge/api/v1/__init__.py` (verified by grep — zero hits).
- No migration file under `migrations/versions/` references `vulnerability_engine`, `VulnerabilityDefinition`, or `AssetVulnerability` (verified by grep across all versions files — zero hits). By contrast, migrations `0054_vulnerability_foundation.py`, `0055_vulnerability_sources.py`, `0056_vulnerability_lifecycle.py`, `0057_vulnerability_read_models.py` all create tables in a `vulnerability` Postgres schema for the `vulnerability` package.
- `vulnerability_engine`'s own registries are named `in_memory_*_registry.py` (7 of them, e.g. `in_memory_asset_vulnerability_registry.py`, `in_memory_vulnerability_definition_registry.py`) — there is no Postgres-backed alternative anywhere in the package.

**Test coverage (ground truth via `def test_` count, not file count):**
- `backend/tests/vulnerability/`: 519 test functions.
- `backend/tests/vulnerability_engine/`: 337 test functions, all exercising in-memory registries/services/aggregates in isolation — none exercise a router or a live DB session (no `TestClient`/`AsyncClient` usage found in that test tree, consistent with there being no API to test).

---

## 2. Aggregate ownership matrix

| Concept | `vulnerability` (M27) | `vulnerability_engine` (M46) | Same real-world responsibility? |
|---|---|---|---|
| Canonical vulnerability/CVE definition | `Vulnerability` aggregate — `backend/src/vulnerability/domain/aggregates/vulnerability.py` (411 lines). Lifecycle `DISCOVERED→ENRICHED→ACTIVE→{DEPRECATED,ARCHIVED}` enforced via `_ALLOWED_TRANSITIONS` state machine (lines 44–66); raises `InvalidStateTransition`/`TenantMismatch`/`InvalidArgument`; holds `CvssV3Score`/`CvssV4Score`/`EpssScore`/`KevRecord`, `ExploitMaturity`, fixed/affected version ranges, SBOM component metadata; emits `VulnerabilityDiscovered`, `VulnerabilityEnriched`, `KevStatusChanged`, `ExploitMaturityEscalated`, `VulnerabilityReferenceMerged`. | `VulnerabilityDefinition` aggregate — `backend/src/vulnerability_engine/domain/aggregates/vulnerability_definition.py` (259 lines). Its own docstring: *"the canonical, purely-declarative vulnerability intelligence record... Deliberately metadata-only: never calls an external feed, never syncs against NVD/EPSS/KEV..."* Has `DefinitionLifecycleState`, `TenantMismatch`, `InvalidDefinitionTransition`; holds `CveId`, `CvssScore`/`CvssVector`, `EpssScore`, `KevStatus`, vendor/product refs, affected/fixed versions; emits `VulnerabilityDefinitionRegistered/Updated/Deprecated`. | **Yes.** Same shape (CVE/CVSS/EPSS/KEV metadata, tenant-scoped, lifecycle state machine, own event stream). `VulnerabilityDefinition`'s "purely declarative, no scan/no feed/no correlation" framing narrows *behavior* but not *data ownership* — it is still a second, independently-persisted (if it were persisted) source of truth for what a CVE record looks like for a tenant. |
| Per-asset occurrence / assessment | `VulnerabilityInstance` — `backend/src/vulnerability/domain/aggregates/vulnerability_instance.py`, plus `RemediationPlan`, `RemediationTask`, `RemediationVerification` for SLA/patch/verification tracking. | `AssetVulnerability` — `backend/src/vulnerability_engine/domain/aggregates/asset_vulnerability.py` (226 lines). Docstring: *"the normalized correlation of one `VulnerabilityAsset` + one `VulnerabilityDefinition`... own per-correlation lifecycle (open → resolved → reopened), suppression, remediation-tracking metadata."* States `CorrelationLifecycleState`, events `CorrelationCreated/VulnerabilityResolved/VulnerabilityReopened/VulnerabilitySuppressed/VulnerabilityUnsuppressed/ObservationUpdated`. | **Yes.** Both model "this CVE, observed on this asset, with an open/resolved/reopened-shaped disposition and remediation tracking." |
| Risk acceptance | `VulnerabilityException` aggregate (`vulnerability/domain/aggregates/vulnerability_exception.py`). | Not present as a distinct aggregate; `RemediationState`/suppression fields on `AssetVulnerability` partially cover it. | Partial overlap — `vulnerability` has a dedicated aggregate, `vulnerability_engine` folds a subset into `AssetVulnerability`. |
| Evidence | `VulnerabilityEvidence` aggregate + `IEvidenceBlobStore` port + `InMemoryEvidenceBlobStore` infra. | Not present. | No overlap (gap in `vulnerability_engine`, not duplication). |
| Vulnerability source / feed registration | `VulnerabilitySource` aggregate, `api/v1/sources.py`. | `ScanProviderRegistration` aggregate — conceptually adjacent (registers a *scan provider*, not a *feed source*) but overlapping in intent (both answer "where did this vulnerability data come from"). | Adjacent overlap, not identical. |
| Scan orchestration | No scan-execution aggregate in `vulnerability` (it consumes provider adapters via `domain/providers/registry.py` + `adapter.py`, a normalize-and-ingest pattern, not a scan scheduler). | `ScanJob`, `ScanPolicy`, `ScanTarget` aggregates — genuine scan lifecycle/scheduling domain. | **No overlap** — this is `vulnerability_engine`'s one clearly non-duplicated responsibility. |
| Asset representation | Not modeled (consumes asset ids by reference only). | `VulnerabilityAsset` aggregate — asset fingerprinting for scan targeting. | No overlap with `vulnerability`, but potentially overlaps `attack_surface_management`/`inventory` bounded contexts (out of this audit's scope to resolve, flagged only). |

**Invariant/lifecycle depth comparison:** both aggregates enforce real invariants (state-machine transition tables, `TenantMismatch` guards, immutable value objects) — this is **not** a case of one side being a anemic stub. Both are legitimate DDD aggregates. The duplication is at the *bounded-context* level, not a quality gap in one implementation.

---

## 3. Dependency graph

```
                         redforge.api.v1.router (mounted, live)
                                  │
                                  ▼
                     vulnerability.api.v1.router  ──────────────┐
                                  │                              │
                                  ▼                              │
                  vulnerability.application.* (commands/         │
                  queries/services/projections)                  │
                                  │                               │
                                  ▼                               │
                  vulnerability.domain.* (6 aggregates)           │
                                  │                               │
                                  ▼                               │
      vulnerability.infrastructure.persistence (6 PG repos,       │
      6 ORM models) ──▶ Postgres schema "vulnerability"           │
      (migrations 0054, 0055, 0056, 0057)                         │
                                  │                               │
                                  ▼                               │
      vulnerability.infrastructure.graph.security_graph_write_    │
      adapter ──▶ Security Graph (shared, cross-context)          │
                                                                   │
      vulnerability.infrastructure.acl.degraded_signal_adapters   │
      (ACL to external signal ports) ◀── shared kernel only ──────┘

      ── no import edge exists between `vulnerability` and `vulnerability_engine`
         in either direction (grep-verified: zero hits both ways) ──

   vulnerability_engine.domain.* (7 aggregates)
                │
                ▼
   vulnerability_engine.application.* (commands/queries/services)
                │
                ▼
   vulnerability_engine.application.registry.in_memory_*_registry.py
   (7 in-memory registries — dead end, nothing downstream)

                ✗ no vulnerability_engine.infrastructure submodules
                ✗ no vulnerability_engine.api submodules
                ✗ not imported by redforge.api.v1.__init__
                ✗ not imported by any migration
                ✗ not imported by any other bounded context (grep-verified)

   redforge.domain.threat_intel.vulnerability_entity.Vulnerability
   (frozen dataclass, global/tenant-agnostic CVE reference row)
                │
                ▼
   redforge.api.v1.threat_intel_reference_data.py (mounted)
                │
                ▼
   Postgres (migration 0035_threat_intel_reference_data, referenced
   again by 0037_threat_fusion, 0039_investigation_integration)
```

**Adjacency list (import edges, source → target, grep-verified):**
- `redforge.api.v1` → `vulnerability.api.v1` (live, mounted)
- `redforge.api.v1` → `threat_intel_reference_data` → `redforge.domain.threat_intel.vulnerability_entity` (live, mounted)
- `vulnerability.*` → `vulnerability_engine.*`: **none**
- `vulnerability_engine.*` → `vulnerability.*`: **none**
- `redforge.api.v1` → `vulnerability_engine.*`: **none**
- any other `src/` package → `vulnerability_engine.*`: **none** (only `backend/tests/vulnerability_engine/*` imports it)
- `vulnerability.*` → unrelated contexts (`attack_surface_management`, `risk_engine`, `cloud_security`, `findings`, `exposure`): none found directly in domain/application; `vulnerability.infrastructure.acl.degraded_signal_adapters` is the one deliberate ACL seam to external signal ports (by design, matching the `attack_surface_management`/`risk_engine` opaque-reference convention).

**Conclusion of graph analysis:** `vulnerability_engine` is a fully isolated island — it has never been wired to the running application at any layer above its own domain/application code, and no other package in the 40+-context monorepo depends on it.

---

## 4. Duplicate responsibility table

| Concept | Canonical owner | Duplicate owner | Why duplication exists | Intentional or accidental? |
|---|---|---|---|---|
| CVE/CVSS/EPSS/KEV vulnerability definition | `vulnerability.domain.aggregates.Vulnerability` (M27, mounted, persisted, 6 PG tables, API-reachable) | `vulnerability_engine.domain.aggregates.VulnerabilityDefinition` (M46A, unmounted, unpersisted) | Two separate milestone efforts (M27 vs M46A–F) modeled the same CVE-record concept independently. | **Accidental.** `vulnerability_engine/__init__.py` docstring literally says: *"Does not import from... the unrelated `vulnerability` scaffold package"* — this mischaracterizes `vulnerability` as a "scaffold" when in fact `vulnerability` is the fully-built, production-wired implementation and `vulnerability_engine` is the one with no infrastructure/API layer. That mislabeling is direct evidence the M46A author was not aware `vulnerability` was already the mature implementation. |
| Per-asset vulnerability occurrence | `vulnerability.domain.aggregates.VulnerabilityInstance` (persisted via `pg_vulnerability_instance_repository.py`, partitioned table per migration 0054) | `vulnerability_engine.domain.aggregates.AssetVulnerability` (no repository, no table) | Same milestone-independence cause as above. | Accidental — same evidence. |
| CVSS scoring value objects | `vulnerability.domain.value_objects.scores.{CvssV3Score,CvssV4Score,EpssScore}` | `vulnerability_engine.domain.value_objects.{cvss.py,epss.py}` | Both packages reimplemented CVSS/EPSS parsing/validation independently rather than sharing a kernel VO. | Accidental — no shared-kernel CVSS type exists in `redforge.shared` for either to reuse from; both built their own. |
| KEV (CISA Known Exploited Vulnerabilities) status | `vulnerability.domain.value_objects.references.KevRecord` | `vulnerability_engine.domain.value_objects.kev.KevStatus` | Same. | Accidental. |
| Vulnerability source/provider registration | `vulnerability.domain.aggregates.VulnerabilitySource` + `domain/providers/{registry,adapter}.py` | `vulnerability_engine.domain.aggregates.ScanProviderRegistration` | Conceptually adjacent, not identical (feed source vs. scan provider) — closer to a genuine boundary difference than the CVE/instance duplication above. | Ambiguous / partially intentional — `ScanProviderRegistration` is oriented around active scanning, `VulnerabilitySource` around passive feed ingestion. This pair is the weakest evidence of accidental duplication in the table. |
| Global CVE reference catalog | `redforge.domain.threat_intel.vulnerability_entity.Vulnerability` (M22) | — | This is a **third**, deliberately distinct concept: a tenant-agnostic, globally-seeded NVD/EPSS/KEV catalog row, explicitly documented as *not* an aggregate ("Hardening Review's reclassification... away from 'aggregate'") and carrying no `organization_id`. | **Intentional and non-duplicative** — it answers "what does NVD say about CVE-X globally," while `vulnerability.Vulnerability` answers "how is tenant Y tracking CVE-X in their environment" (tenant-scoped, stateful lifecycle). Flagged here only because it shares the name `Vulnerability` and a grep for the term surfaces it; it is not part of the M27/M46 duplication problem and needs no remediation. |

**Git history check:** `git log --oneline -- backend/src/vulnerability backend/src/vulnerability_engine` returns only 2 commits touching either path (`db14d4c feat(platform): complete enterprise platform milestones M37-M47`, `0afbae7 fix(platform): complete post-M47 stabilization sprint`) — both are large squashed multi-milestone commits, not a granular per-milestone history. This confirms the two packages were squash-committed together with no visible sequencing signal (e.g. no commit shows one being built "in light of" the other), consistent with the accidental-duplication reading above rather than a visible, deliberate migration commit trail.

---

## 5. Canonical ownership recommendation

**`vulnerability` (M27) is the canonical bounded context for vulnerability lifecycle management.** Basis:

1. **Persistence ownership** — `vulnerability` has 4 applied migrations (0054–0057) creating a dedicated `vulnerability` Postgres schema with partitioned tables, tenant-isolation indexes, and read-model projections. `vulnerability_engine` has zero migrations and zero ORM models; it cannot persist anything beyond process memory.
2. **API ownership** — `vulnerability.api.v1.router` is mounted in `redforge/api/v1/__init__.py:157` and reachable over HTTP (5 route modules: vulnerabilities, lifecycle, prioritization, sources, platform). `vulnerability_engine` has no router at all.
3. **Reference count** — zero other bounded contexts import `vulnerability_engine`; `vulnerability` is imported by the top-level API composition root, i.e. by the application itself.
4. **Maturity signal** — `vulnerability` has infrastructure adapters for events (`composite_event_publisher.py`, `structlog_event_publisher.py`), an ACL layer to degraded external signals, a Security Graph write adapter, evidence blob storage, and a full unit-of-work — the complete Clean Architecture ring. `vulnerability_engine` stops at domain+application with in-memory registries standing in for infrastructure, which its own docstring says is deliberate ("M46A scope is domain + application architecture only... no real infrastructure, and no HTTP API").
5. **Test volume** — 519 vs 337 test functions; `vulnerability`'s tests include integration-shaped coverage of repositories/projections that `vulnerability_engine`'s cannot have (nothing to integrate against).

**`vulnerability_engine`'s one non-duplicated asset worth preserving:** the `ScanJob`/`ScanPolicy`/`ScanTarget` scan-orchestration aggregates and their events. `vulnerability` has no equivalent scan-scheduling domain model — it ingests already-produced findings via `domain/providers/adapter.py` rather than owning scan execution. This is a genuine, non-overlapping capability gap in `vulnerability` that `vulnerability_engine` fills on paper (though, again, with no infrastructure/API behind it yet).

---

## 6. Migration strategy (architecture only — no code)

### Phase 1 — Freeze and declare (low risk, immediate)
- Formally declare `vulnerability` (M27) the canonical bounded context for CVE/CVSS/EPSS/KEV vulnerability-definition and per-asset-instance lifecycle in this ADR (done, below).
- Freeze `vulnerability_engine.domain.aggregates.{VulnerabilityDefinition, AssetVulnerability}` and their value objects/events as **deprecated, do-not-extend**. Leave the code in place (tests keep passing, nothing is deleted) — this is a documentation-only phase, matching the read-only nature of this audit.
- Correct the misleading docstring in `vulnerability_engine/__init__.py` (currently calls `vulnerability` "the unrelated... scaffold package") in a follow-up ticket — this is a 1-line doc fix but is explicitly *not* part of this read-only audit's deliverable and must not be done here.
- Risk: near zero — no running code path changes.

### Phase 2 — Extract and port the non-duplicated scan-orchestration capability (medium risk)
- Design (in a future milestone, not this one) a narrow port from `vulnerability_engine.domain.aggregates.{ScanJob, ScanPolicy, ScanTarget, ScanProviderRegistration}` into `vulnerability` as a new `vulnerability/domain/scanning/` subpackage, referencing existing `vulnerability.domain.aggregates.Vulnerability`/`VulnerabilityInstance` by ID only (matching the `attack_surface_management`↔`risk_engine` opaque-reference convention already used elsewhere in this repo).
- `VulnerabilityAsset` (asset fingerprinting) should be evaluated against whatever asset/inventory bounded context is canonical in this repo before porting — do not re-duplicate asset modeling a third time.
- Backward compatibility: since `vulnerability_engine` has no live API or persisted data, there are **no consumers to break** and **no data migration** is required for this phase — this is the single biggest risk-reducer in this whole strategy. A conventional "dual-write / backfill / cutover" playbook is unnecessary because one side of the duplication was never in production.
- Add integration/repository/API layers only for the newly-ported scanning subpackage, following `vulnerability`'s existing Postgres schema/migration conventions (next available migration number after the current head).

### Phase 3 — Retire `vulnerability_engine`
- Once Phase 2 confirms nothing else references `vulnerability_engine` (re-run this audit's grep as a gate check), delete `backend/src/vulnerability_engine/` and `backend/tests/vulnerability_engine/` in a dedicated milestone commit with an explicit ADR reference back to this document.
- Deprecation window: since there are no external consumers (no mounted API, no persisted rows, no cross-context importers), a compatibility/dual-run period is not architecturally necessary — the only "consumers" are its own 337 unit tests, which get deleted with it. Recommend a short (one sprint) grace period purely for human review/objection, not for technical migration.
- Risk assessment: **low**. The absence of any persisted data, live API surface, or external importer is the deciding factor — this is closer to deleting dead code than migrating a live subsystem. The only real risk is losing the scan-orchestration domain modeling *before* Phase 2 has ported what's worth keeping — hence Phase 2 must complete and be verified before Phase 3 executes.

---

## 7. Updated recommendation for what M50 should become

The original M50A brief (build a new `vulnerability_management` domain modeling `Vulnerability`/`VulnerabilityAssessment`/CVSS/CVE/severity) is **confirmed still wrong** by this deeper audit, for the same reason M50A's own ADR flagged and more: that data model already exists live, twice. Nothing in this deeper pass changes that conclusion — it only adds precision (persistence/API mount evidence, aggregate-by-aggregate comparison, dependency graph, test-count ratios) confirming `vulnerability` is unambiguously canonical and `vulnerability_engine` is unambiguously the unwired duplicate, not a close call requiring further human tie-breaking on *which* side is canonical (M50A left that question open; this audit closes it).

**M50 should be redefined as:**

> **M50 — Vulnerability Engine Consolidation.** Execute Phase 1 (freeze/declare, this ADR) now. Scope a follow-up milestone (M50B or similar) to execute Phase 2 (port `ScanJob`/`ScanPolicy`/`ScanTarget` scan-orchestration modeling into `vulnerability/domain/scanning/` with ID-only references to existing `Vulnerability`/`VulnerabilityInstance` aggregates, plus new persistence/API layers for it) and Phase 3 (delete `vulnerability_engine` once Phase 2 is verified complete and the cross-reference grep confirms zero remaining importers).

No new `Vulnerability`/`VulnerabilityAssessment`/CVSS/CVE/severity domain modeling should be scoped under any milestone name — that responsibility is permanently owned by `vulnerability.domain.aggregates.{Vulnerability, VulnerabilityInstance}`.

---

## Final conclusion

`M50 ARCHITECTURE REQUIRES REDESIGN`

Recommended replacement scope for M50: **Phase 1 of the consolidation strategy in Section 6 (freeze `vulnerability_engine` as deprecated/do-not-extend, canonicalize `vulnerability`)** now, with Phase 2 (port scan-orchestration capability) and Phase 3 (delete `vulnerability_engine`) scoped as explicit follow-up milestones — not the original M50A scope of building a new vulnerability domain package, which duplicates live, already-canonical code in `backend/src/vulnerability/`.
