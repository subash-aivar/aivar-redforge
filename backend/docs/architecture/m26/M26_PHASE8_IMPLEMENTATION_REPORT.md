# M26 Phase 8 — Enterprise Cloud Security Platform Integration Layer

## Scope delivered

Phase 8 **integrates, validates, hardens, and operationalizes** Phases 1–7. It is **not** a new security capability and deliberately **deviates from** the freeze/plan Phase 8 (dashboards, workers, attack-path ACLs).

Delivered:

- Domain aggregate `OrchestrationRun` + step results / events / repository protocols
- Migration `0053` (`cloud_orchestration_runs`, `cloud_platform_validation_reports`)
- Separate application services: orchestrator, lifecycle, sync, validation, health/readiness, observability, facade
- HTTP APIs under `/api/v1/cloud-foundation/platform/*`
- DI wiring that injects existing Phase 1–7 services (no business-logic duplication)
- ≥250 parametrized tests (unit / API / integration)

## Explicit non-goals (honored)

- No workers / schedules / dashboards / attack paths / AI security / auto remediation
- No new bounded contexts
- No ontology bump (`ONTOLOGY_VERSION` remains **12**)
- No re-implementation of CSPM engine, risk formula, or ontology pair tables

## Architecture conformance

| Layer | Location |
|-------|----------|
| Domain | `domain/cloud_security/platform/` |
| Application | `application/cloud_security/platform/` (separate services + `CloudPlatformService` facade) |
| Infrastructure | `infrastructure/cloud_security/platform/` + models in `cloud_security.py` |
| Persistence | Alembic `0053_cloud_orchestration_runs.py` |
| API | `api/v1/cloud_platform.py` |
| DI | `get_cloud_platform_service` in `api/dependencies.py` |

### Orchestration pipeline

`CloudPlatformOrchestrator` calls injected ports only:

1. Discover assets → 2. Discover identity → 3. Evaluate CSPM → 4. optional K8s → 5. optional runtime ingest → 6. Calculate risk

- **Idempotent:** each invoke creates a new run record; underlying services upsert
- **Partial failures:** per-step catch/record/continue unless `fail_fast=True`
- **Observability:** `operation_id`, step timers, structlog context (no secrets)
- **Audit trail:** persisted orchestration runs (operational audit)

### Health / validation packages

`foundation`, `inventory`, `identity`, `cspm`, `kubernetes`, `runtime`, `risk`, `security_graph`, `compliance`

Validation checks: migration head **0053**, ontology **12**, CSPM policies ≥25, `RiskWeightProfile.default()` sums to 1.0, module importability, optional table probes.

## API (`/api/v1/cloud-foundation`)

| Method | Path | Permission |
|--------|------|------------|
| GET | `/platform/health` | ORG_READ |
| GET | `/platform/health/{package}` | ORG_READ |
| GET | `/platform/readiness` | ORG_READ |
| GET | `/platform/summary` | ORG_READ |
| POST | `/platform/validate` | ORG_MANAGE |
| GET | `/platform/validate/report` | ORG_READ |
| POST | `/platform/orchestrate` | ORG_MANAGE |
| GET | `/platform/runs` | ORG_READ |
| GET | `/platform/runs/{run_id}` | ORG_READ |
| GET | `/platform/sync/status` | ORG_READ |
| GET | `/platform/diagnostics` | ORG_READ |

## Validation results

| Check | Result |
|-------|--------|
| Ruff (Phase 8 surface) | Pass |
| Mypy `--strict` (Phase 8 packages) | Pass |
| Phase 8 unit + API | **352 passed** |
| Phase 8 integration (with `TEST_DATABASE_URL`) | **7 passed** |
| Broader `tests/unit/cloud_security` + `tests/api/cloud_security` | **903 passed** |
| Alembic | Head **0053** |
| OpenAPI | **11** `/cloud-foundation/platform/*` paths |
| Startup | Healthy; platform routes **401** without auth |
| Policy loading | **41** CSPM policies load |
| Risk calculation | Deterministic engine smoke OK |
| Ontology | `ONTOLOGY_VERSION = 12` (unchanged) |
| Startup validators | `_EXPECTED_MIGRATION_HEAD = "0053"` |

Suite paths:

- `tests/unit/cloud_security/platform/`
- `tests/api/cloud_security/test_cloud_platform_api.py`
- `tests/integration/cloud_security/test_platform_migration.py`
- `tests/integration/cloud_security/test_platform_repositories.py`

**Total Phase 8 tests with DB: 359** (352 + 7).

## Performance notes

- Health matrix uses import probes; readiness optional single-session table count (avoids N+1)
- `bulk.paginate_offset` / `chunk_ids` document batch org-wide orchestration without redesign
- Orchestration is synchronous and bounded by existing discovery/CSPM/risk call latency
- List-runs uses limit/offset pagination (max size 200)

## Security hardening

- All run/report queries filter `organization_id`
- UUID path/body validation via FastAPI/Pydantic
- Sync status omits `credential_reference_id`; logs never include secrets
- Orchestration runs = operational audit trail

## Known limitations

1. **K8s discover** requires `include_k8s=True` and a working kubernetes service / inventory; optional by default
2. **Runtime ingest** only runs when `include_runtime=True` and events are supplied
3. **Organization-wide** orchestration iterates accounts serially (documented batch helpers; no worker fan-out)
4. **Graph projection** step name exists in the enum for future use; pipeline relies on existing services’ own ACLs rather than a separate PROJECT_GRAPH step
5. **Validation migration check** asserts expected head constant; live alembic head remains a startup concern
6. Test directory `tests/.../platform/` has no `__init__.py` to avoid clash with stdlib `platform`

## Deviations from freeze/plan P8

| Freeze/plan P8 | USER Phase 8 (this delivery) |
|----------------|------------------------------|
| Materialized dashboard views | Not implemented |
| `CloudRiskCalculationWorker` / schedules | Not implemented |
| Live AttackPath / TI / Exposure ACLs | Not implemented (stubs remain) |
| Dashboard HTTP routes | Platform health/validate/orchestrate instead |

## Future extension points

- Optional `PROJECT_GRAPH` pipeline step wrapping existing graph ACLs
- Parallel account fan-out via workers (out of Phase 8 scope)
- Restore `attack_path` weight when AttackPath ACL is live
- Persist richer validation reports / SLO metrics into diagnostics
- Dashboard MVs can consume orchestration run history as an operational signal

## Test counts + deviations summary

| Metric | Value |
|--------|-------|
| Unit + API | 352 |
| Integration | 7 |
| Combined Phase 8 | **359** |
| Broader cloud_security regression | 903 |
| Ontology bump | **None** (stays at 12) |
| Commit/push | **Not performed** (per mission) |

---

## Stop condition

Phase 8 (and M26 integration layer) implementation is complete. **No commit. No push.** Waiting for final architecture review.
