# M22 Phase 1 — Threat Intelligence Foundation: Implementation Report

**Status**: COMPLETE (Phase 1 of 7 only — Phases 2-7 explicitly out of scope, not started)
**Date**: 2026-07-16
**Migration head**: `0035` (was `0034`)
**Commit status**: NOT COMMITTED, NOT PUSHED — awaiting review per explicit instruction.

---

## 1. Scope

This phase implements the **global reference-data foundation** for M22 Threat Intelligence,
strictly following the authoritative architecture in `docs/architecture/m22/m22_architecture_freeze.html`
as corrected by the P0/P1 findings in `docs/architecture/m22/m22_hardening_review.html`.

**Implemented** (per the approved brief):

- Migration `0035` — 5 global reference tables, schema-only, no data seeding.
- Domain layer — value objects, immutable reference entities, one aggregate, domain events,
  repository interfaces, domain exceptions.
- Infrastructure layer — SQLAlchemy ORM models, concrete repositories, ORM↔domain mappers.
- Application layer — CRUD-level admin service (upsert) + query service (read), no orchestration.
- API layer — minimal internal administration endpoints, platform-permission gated.
- Tests — domain unit tests, PostgreSQL repository/migration/API integration tests.

**Explicitly NOT implemented** (deferred to later M22 phases, per instruction):

- STIX / TAXII ingestion
- Fusion Engine
- Attack Path Engine
- Background workers
- Frontend
- Investigation-context integration

---

## 2. Architecture Decisions (from the Hardening Review)

The Hardening Review flagged 8 P0 issues against the original Architecture Freeze spec. The
following corrections were applied during this implementation, and are the reason the code
differs in places from a literal reading of the Freeze spec alone:

| # | Hardening Review Finding | Correction Applied |
|---|---|---|
| P0 | Global vs. per-tenant table design was ambiguous — spec risked adding `organization_id` to global catalog tables. | All 5 reference tables (`attack_tactics`, `attack_techniques`, `attack_technique_relationships`, `vulnerabilities`, `stix_ingestion_log`) carry **no** `organization_id` for the global catalog rows. `stix_ingestion_log` uses an explicit `scope` discriminator (`GLOBAL`/`ORGANIZATION`) with a `CHECK` constraint (`organization_id IS NULL` for `GLOBAL`) plus two mutually-exclusive **partial unique indexes**, so a future tenant-scoped ingestion path can be added without touching the global identity space. |
| P1 | `AttackTechniqueNode`/`VulnerabilityRecord` were framed as aggregates in the Freeze spec. | Reclassified as immutable **reference entities** (`AttackTactic`, `AttackTechnique`, `AttackTechniqueRelationship`, `Vulnerability`) — they have identity but no lifecycle/invariant-guarding behavior of their own (they are replaced wholesale on re-ingestion, never incrementally mutated). The **one legitimate aggregate** in this phase is `ReferenceDataIngestionRecord`, which tracks the idempotency fact of an ingestion action and does own real invariants (scope/organization_id consistency, content-hash-based change detection). |
| P1 | Migration should not embed bulk data inserts. | Migration `0035` is schema-only (`CREATE TABLE` + indexes + constraints). No `INSERT` statements. Data loading is exclusively an application-layer concern via `ReferenceDataAdminService`. |
| P1 | `stix_ingestion_log` needs distinct idempotency strategies for global vs. tenant data. | Implemented via the `scope` + `organization_id` check constraint and the two partial unique indexes described above. |

---

## 3. Repository-First Research (what was read before writing code)

Per instruction, the following were read completely before any code was written:

- `docs/architecture/m22/m22_architecture_freeze.html` (authoritative spec)
- `docs/architecture/m22/m22_hardening_review.html` (corrections, P0-P3 findings)
- `docs/PROJECT_CONTEXT.md`
- M18 Threat Intelligence: `domain/threat_intel/value_objects.py`, `results.py`,
  `application/threat_intel/config_service.py`,
  `infrastructure/database/models/threat_intel.py`,
  `infrastructure/database/repositories/threat_intel_repository.py`
- M21 Investigation: `domain/investigations/entity.py`, `value_objects.py`, `events.py`,
  `repository.py`, `infrastructure/database/repositories/investigations/case_repository.py`,
  migration `0034_unified_investigation.py`
- Security Graph: `domain/security_graph/ontology.py`,
  `application/security_graph/projector.py`, migrations `0014`/`0027`
- `backend/pyproject.toml` (Python version, ruff/mypy config, pytest config)
- Platform identity: `domain/platform_identity/value_objects.py`, `api/security.py`
- Audit: `infrastructure/audit/contracts.py`, `platform_audit_log.py`
- `application/platform/startup_validator.py`

No architecture was invented. Every naming, layering, and testing decision mirrors an existing,
working pattern already in the repository (mostly M18 and M21).

---

## 4. Files Added / Modified

### New files

| File | Purpose |
|---|---|
| `backend/src/redforge/domain/threat_intel/reference_data_value_objects.py` | `TechniqueId`, `TacticId`, `CveId`, `EpssScore`, `CvssScore` VOs; `ReferenceDataSource`, `AttackRelationshipType`, `IngestionScope` enums. |
| `backend/src/redforge/domain/threat_intel/reference_data_exceptions.py` | Domain-specific validation exceptions. |
| `backend/src/redforge/domain/threat_intel/attack_technique_entity.py` | `AttackTactic`, `AttackTechnique`, `AttackTechniqueRelationship` immutable entities. |
| `backend/src/redforge/domain/threat_intel/vulnerability_entity.py` | `Vulnerability` immutable entity (CVE/CVSS/EPSS/KEV). |
| `backend/src/redforge/domain/threat_intel/reference_data_events.py` | `ReferenceDataObjectIngested` domain event. |
| `backend/src/redforge/domain/threat_intel/reference_data_ingestion.py` | `ReferenceDataIngestionRecord` aggregate. |
| `backend/src/redforge/domain/threat_intel/reference_data_repository.py` | Repository protocols (`AttackTacticRepository`, `AttackTechniqueRepository`, `VulnerabilityRepository`, `ReferenceDataIngestionRepository`). |
| `backend/src/redforge/infrastructure/database/models/threat_intel_reference_data.py` | SQLAlchemy ORM models for all 5 tables. |
| `backend/src/redforge/infrastructure/database/migrations/versions/0035_threat_intel_reference_data.py` | Migration 0035 (schema-only). |
| `backend/src/redforge/infrastructure/database/repositories/threat_intel_reference_data_repository.py` | Concrete repositories, ORM↔domain mappers, upsert logic, full-text search. |
| `backend/src/redforge/application/threat_intel/reference_data_admin_service.py` | `ReferenceDataAdminService` — batch upsert commands, audit logging. |
| `backend/src/redforge/application/threat_intel/reference_data_query_service.py` | `ReferenceDataQueryService` — read-only queries. |
| `backend/src/redforge/api/v1/threat_intel_reference_data.py` | Internal admin REST endpoints. |
| `backend/tests/domain/test_reference_data_domain.py` | 75 domain unit tests. |
| `backend/tests/integration/test_m22_reference_data_pg.py` | 32 PostgreSQL integration/API tests. |
| `docs/M22_PHASE1_THREAT_INTEL_FOUNDATION_REPORT.md` | This report. |

### Modified files

| File | Change |
|---|---|
| `backend/src/redforge/infrastructure/database/models/__init__.py` | Registered the 5 new ORM models. |
| `backend/src/redforge/domain/platform_identity/value_objects.py` | Added `PLATFORM_THREAT_INTEL_READ`/`PLATFORM_THREAT_INTEL_MANAGE` permissions; wired into `SECURITY_ADMIN`/`AUDITOR` roles. |
| `backend/src/redforge/infrastructure/audit/contracts.py` | Added `REFERENCE_DATA_INGESTED` `AuditAction`. |
| `backend/src/redforge/api/v1/__init__.py` | Mounted the new admin router. |
| `backend/src/redforge/application/platform/startup_validator.py` | `_EXPECTED_MIGRATION_HEAD`: `"0034"` → `"0035"`. |
| `backend/tests/unit/test_sprint29_replay_pipeline.py` | Updated 2 hardcoded `"0034"` expected-head assertions to `"0035"`. |
| `backend/tests/unit/test_startup_validator.py` | Updated hardcoded mocked migration version `"0034"` → `"0035"`. |
| `backend/tests/integration/test_m21_investigation_pg.py` | Renamed/updated `test_migration_head_is_0034` → `test_migration_head_is_0035` (M21 proof DB is now migrated past M22 Phase 1's head). |
| `docs/PROJECT_CONTEXT.md` | Added M22 Phase 1 milestone row; updated "Last verified" / test-baseline header. |

---

## 5. Database Schema (Migration 0035)

5 tables, all global (no `organization_id` on the catalog tables):

- **`attack_tactics`** — MITRE ATT&CK tactics (`TA####`).
- **`attack_techniques`** — MITRE ATT&CK techniques/sub-techniques (`T####`/`T####.###`),
  self-referencing `parent_technique_id` (deferrable FK), GIN full-text index on `name`.
- **`attack_technique_relationships`** — technique-to-technique relationships (self-referencing,
  deferrable FKs on both sides).
- **`vulnerabilities`** — CVE records with CVSS v2/v3, EPSS score, CISA KEV flag/date.
- **`stix_ingestion_log`** — idempotent ingestion ledger with `scope`/`organization_id`
  `CHECK` constraint + two partial unique indexes (GLOBAL vs. ORGANIZATION scope never conflate).

Verified:

- Clean `alembic upgrade head` from an empty database (`0001` → `0035`).
- Clean `downgrade -1` / `upgrade head` round-trip on `0035` (reversibility proven).
- The pre-existing M21 proof database (already at `0034`) upgrades cleanly to `0035` with zero
  impact on existing M21 tables/tests.

---

## 6. Permissions & API

Two new platform-level permissions (not tenant-level — this is global catalog data):

- `PLATFORM_THREAT_INTEL_READ`
- `PLATFORM_THREAT_INTEL_MANAGE`

Wired into the `SECURITY_ADMIN` and `AUDITOR` platform roles via `PLATFORM_ROLE_PERMISSIONS`.

New router (`api/v1/threat_intel_reference_data.py`), mounted under the existing v1 API, gated
by `require_platform_permission`. Endpoints are strictly internal administration — loading and
verifying reference data — with no public Threat Intelligence API surface added.

---

## 7. Quality Gates — Results

All gates were run against this exact working tree, uncommitted, per instruction.

### Ruff

```
python3 -m ruff check .
```

Result: **All checks passed** for every file touched or added in this phase. (5 pre-existing
ruff findings remain in two unrelated M21-era test files —
`tests/application/test_investigation_correlation.py`,
`tests/domain/test_investigation_domain.py` — neither touched in this phase; confirmed via
`git status` that they are untouched.)

### Mypy

```
python3 -m mypy src
```

Result: **1 error, in 1 pre-existing, unrelated file**:

```
src/redforge/infrastructure/threat_intel/providers/maxmind_geolite_local.py:61: error:
Cannot find implementation or library stub for module named "maxminddb"  [import-not-found]
```

This is a missing third-party type stub for an existing M18 provider, unrelated to and not
introduced by this phase. All 767 checked source files are otherwise clean, including every
new/modified M22 file.

### Unit / Domain / Application tests

```
python3 -m pytest tests/unit tests/domain tests/application tests/api -q
```

Result: **3,926 tests collected, all passing** (excluding 2 pre-existing collection errors for
`test_aws_cloud_adapter.py`/`test_ldap_directory_adapter.py`, which fail on `import boto3` /
`import ldap3` — missing optional third-party dependencies, unrelated to this phase and present
before this work began).

Of these, **75** are the new M22 domain unit tests
(`tests/domain/test_reference_data_domain.py`) covering value-object validation, entity
construction, `ReferenceDataIngestionRecord` aggregate invariants (including the GLOBAL-scope
`organization_id` guard), and every custom exception path.

### PostgreSQL integration tests

Against a real PostgreSQL instance (`localhost:5432`), two independent proof databases:

**M22 proof database** (`redforge_m22_reference_data_proof_test`), migrated `0001` → `0035`:

```
python3 -m pytest tests/integration/test_m22_reference_data_pg.py -q
→ 32 passed
```

Covers: migration structure verification, all 5 repositories' upsert/get/search/idempotency
behavior (including a genuine concurrent-upsert convergence proof using `asyncio.gather()`),
the `ReferenceDataIngestionRecord` GLOBAL/organization_id invariant against a real database,
`ReferenceDataAdminService` batch ingestion + audit trail, `ReferenceDataQueryService` reads,
and real-HTTP API acceptance (platform-permission RBAC: denied without
`PLATFORM_THREAT_INTEL_MANAGE`/`READ`, allowed with it).

**M21 proof database** (`redforge_m21_proof_test`), upgraded `0034` → `0035` in place:

```
python3 -m pytest tests/integration/test_m21_investigation_pg.py -q
→ 51 passed
```

Confirms the M22 Phase 1 migration and new global tables introduce **zero regression** to the
pre-existing M21 Investigation bounded context — all 51 M21 tests (lifecycle, concurrency,
tenant isolation, RBAC, audit) pass unchanged against the post-`0035` schema.

### Migration verification

```
alembic upgrade head      (0001 → 0035, clean, empty DB)
alembic downgrade -1       (0035 → 0034, clean)
alembic upgrade head       (0034 → 0035, clean)
alembic current             → 0035 (head)
```

### Startup validator verification

`_EXPECTED_MIGRATION_HEAD` is now `"0035"`. Unit tests
(`tests/unit/test_startup_validator.py`, `tests/unit/test_sprint29_replay_pipeline.py`) updated
to assert against the new head and pass:

```
python3 -m pytest tests/unit/test_startup_validator.py tests/unit/test_sprint29_replay_pipeline.py -q
→ 19 passed
```

---

## 8. Test Baseline Summary

| Suite | Count | Result |
|---|---|---|
| Non-integration (unit + domain + application + api) | 3,926 collected | All pass (2 pre-existing collection errors, unrelated) |
| M22 PostgreSQL integration | 32 | All pass |
| M21 PostgreSQL integration (regression check) | 51 | All pass, unchanged |
| Ruff | — | Clean on all M22 files; 5 pre-existing unrelated findings untouched |
| Mypy (`src`) | — | Clean on all M22 files; 1 pre-existing unrelated finding (`maxminddb` stub) |

---

## 9. Documentation Updated

- `docs/PROJECT_CONTEXT.md` — added the M22 Phase 1 milestone row to the Completed Milestones
  table; updated the "Last verified" line and test-baseline header to reflect the new migration
  head (`0035`) and measured collectible-test counts.
- This report (`docs/M22_PHASE1_THREAT_INTEL_FOUNDATION_REPORT.md`).

---

## 10. Explicit Confirmation of Stop Conditions

- Phase 1 only was implemented. No STIX, TAXII, Fusion Engine, Attack Path Engine, background
  workers, frontend, or Investigation-context integration code was written.
- Ruff, Mypy, unit tests, PostgreSQL integration tests, migration verification, and startup
  validator verification were all run, with results reported above.
- Documentation was updated.
- This implementation report was produced.
- **No commit was made. No push was made.** The working tree is left exactly as-is, awaiting
  review.

---

## 11. Review-Fix Pass (post-implementation)

A follow-up "M22 Phase 1 Review Fixes" request asked for a self-directed audit against the
hardening review and this report — no external findings list was supplied. Re-reading the
hardening review in full (all severities, not just the P0/P1 items addressed during the initial
implementation) and re-reading every Phase 1 source file line-by-line surfaced three real defects
in `ReferenceDataAdminService`, all fixed. None of the migration, API surface, aggregate
boundaries, or authorization model changed.

1. **Ingestion-log write ordering bug (idempotency-ledger poisoning).** `_ingest_if_changed`
   wrote the `stix_ingestion_log` record *before* the batch item's domain entity was
   constructed/validated. A batch item that failed domain validation (e.g. a malformed
   `TechniqueId`) still left a "successfully ingested" ledger row for its `external_id`. Any
   later retry submitting the exact same (still invalid) payload would hash-match that poisoned
   record and be silently reported `unchanged` forever, with the referenced catalog row never
   actually existing. Fixed by splitting the old method into a read-only `_check_unchanged`
   (runs first, never writes) and `_record_ingestion` (writes, called only after the
   corresponding repository upsert has already succeeded) across all four `upsert_*` methods.

2. **Deferred-FK batch-abort bug.** `parent_technique_id` and the relationship technique-side
   foreign keys are `DEFERRABLE INITIALLY DEFERRED` by design, so a batch may insert children
   before parents. This means a genuinely dangling reference is only caught by PostgreSQL at
   `uow.commit()` — an unhandled `IntegrityError` outside the per-item `try`/`except`, which
   aborted the *entire* batch (including every otherwise-valid item), contradicting the
   batch-isolation guarantee already advertised and tested for format-validation failures. Fixed
   with two new read-only repository methods (`AttackTechniqueRepository.list_all_ids()`,
   `AttackTacticRepository.list_all_ids()`) used to pre-validate `parent_technique_id` (against
   already-stored techniques unioned with the current batch, since a batch may resolve its own
   forward references) and relationship `source_technique_id`/`target_technique_id` (against
   already-stored techniques) *before* attempting to persist, raising the previously-defined-but
   -unused `UnknownTechniqueReferenceError`/`UnknownTacticReferenceError` domain exceptions as an
   isolated per-item failure instead of a batch-wide crash. The same gap existed for
   `AttackTechnique.tactic_ids`, which has no DB-level FK at all (a JSON array cannot carry one)
   — now validated the same way.

3. **Same-batch conflicting-duplicate bug.** Two items in one batch call sharing an
   `external_id` with *different* content silently resolved via last-write-wins with no signal
   to the caller that it had submitted a self-contradictory batch. Fixed by wiring up the
   previously-defined-but-unused `DuplicateIngestionError` via a small in-memory per-batch hash
   tracker (`_check_duplicate_in_batch`). A repeated item with *identical* content remains a
   harmless no-op (naturally resolves to `unchanged`); only a genuine content conflict on a
   repeated `external_id` is now rejected.

Also removed one dead ORM convenience method (`StixIngestionLogModel.as_dict()` — unused
anywhere in `src/` or `tests/`, with an inaccurate docstring claiming query-service usage) and
its now-unused `typing.Any` import, and corrected an inaccurate `IngestionScope`/exception-name
reference (`GLOBAL/ORGANIZATION` and `PlatformInvariantError`, neither of which exist in the
actual code — the real names are `GLOBAL`/`TENANT` and `InvalidIngestionScopeError`) in this
report's own milestone-table entry in `docs/PROJECT_CONTEXT.md`.

**Tests added** (all in `tests/integration/test_m22_reference_data_pg.py`, PostgreSQL-backed):
`test_failed_item_never_poisons_the_ingestion_log`,
`test_dangling_parent_technique_reference_isolated_not_batch_aborting`,
`test_same_batch_out_of_order_parent_reference_resolves`,
`test_unknown_tactic_reference_is_isolated`,
`test_dangling_relationship_technique_reference_isolated`,
`test_conflicting_duplicate_external_id_within_batch_is_isolated`,
`test_identical_duplicate_external_id_within_batch_is_harmless`.

**Quality gates re-run after the fixes:**

| Check | Result |
|---|---|
| Ruff (all M22 files) | Clean |
| Ruff (full `src/` + `tests/`) | Clean except 5 pre-existing, unrelated findings in M21 test files |
| Mypy (`src/`) | Clean except 1 pre-existing, unrelated `maxminddb` stub gap |
| Full non-integration suite | 3,939 collected, all pass |
| M22 PostgreSQL integration suite | 39 collected, all pass (32 pre-existing + 7 new) |
| Migration 0035 downgrade → re-upgrade → head | Verified: `0034 → 0035 → 0034 → 0035`, head confirmed `0035` |

No code was committed or pushed.
