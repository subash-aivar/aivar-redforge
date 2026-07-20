# M26 Phase 7 — Cloud Risk Correlation Engine Implementation Report

## Scope delivered

Phase 7 wires the already-complete risk domain (`domain/cloud_security/risk/`) into persistence, application services, HTTP APIs, and ontology projection. Calculation is synchronous (no workers / schedules). Attack-path analysis is explicitly a metadata stub (`attack_path` dimension score = 0, weight = 0).

## Ontology v12

- `ONTOLOGY_VERSION = 12`
- Node kinds: `RISK`, `RISK_FACTOR`, `RISK_EXPOSURE`
- Edge kinds:
  - `HAS_RISK` — `asset` / `cloud_resource` → `RISK` (ownership; preferred over `INDICATES`)
  - `HAS_FACTOR` — `RISK` → `RISK_FACTOR`
  - `HAS_EXPOSURE` — `RISK` → `RISK_EXPOSURE`
- Projection only — no graph traversal / attack-path walks

## Persistence (migration 0052)

Schema `cloud_security`:

| Table | Role |
|-------|------|
| `cloud_risk_scores` | Current score per `(organization_id, cloud_asset_id)`; JSONB components/evidence/history/exceptions/weight_profile/calculation_version |
| `cloud_risk_history` | Append-only history rows |
| `cloud_risk_factors` | Per-dimension factor records |
| `cloud_risk_exposures` | Derived exposure snapshot (unique org+asset) |
| `cloud_risk_assessments` | Batch assessment run records |

Startup validators expect head `0052`.

## Application

| Module | Responsibility |
|--------|----------------|
| `snapshot_builder` | `RiskEvidenceCollector` / `RiskSnapshotBuilder` — CSPM severities, IAM privilege, K8s score, runtime severities, `NormalizedConfig` exposure, TI stub=0 |
| `correlation_service` | Engine → dimensions + `CloudRiskFactor`s |
| `aggregation_service` | Org summary / top-N |
| `calculation_pipeline` | Asset / account / org / batch / incremental; idempotent current-score upsert |
| `calculation_service` | Facade for API |
| `projection_service` + `RiskGraphACL` | Best-effort security graph projection |
| `history_service` | Append-only history |

Signals are **read** from existing CSPM / IAM / K8s / runtime / inventory repos — never duplicated.

## API (`/api/v1/cloud-foundation`)

| Method | Path | Permission |
|--------|------|------------|
| POST | `/risk/calculate` | ORG_MANAGE |
| POST | `/risk/recalculate-organization` | ORG_MANAGE |
| GET | `/risk/scores` | ORG_READ |
| GET | `/risk/scores/{risk_id}` | ORG_READ |
| GET | `/risk/by-asset/{asset_id}` | ORG_READ |
| GET | `/risk/summary` | ORG_READ |
| GET | `/risk/history` | ORG_READ |
| GET | `/risk/top` | ORG_READ |
| GET | `/risk/factors` | ORG_READ |

## Explicit non-goals (unchanged)

- No workers / scheduled jobs
- No attack-path analysis
- No dashboards / auto remediation / AI security / privilege-escalation analytics
- No duplicate CSPM/IAM/K8s/runtime storage

## Deviations / notes

1. **`INTERNET` exposure label** — engine accepts `PUBLIC`/`INTERNET` strings on snapshots; inventory `NetworkExposure` enum has `PUBLIC` (not `INTERNET`). Exposure ACL maps `PUBLIC` → `internet_exposure=True`.
2. **IAM privilege signal** — highest privilege among principals on the same cloud account (not per-asset binding); absent principals → `NONE`.
3. **K8s score** — loaded when asset type/tags suggest a cluster; otherwise `None` → dimension 0.
4. **Runtime severities** — filtered from account events via `correlation_refs.cloud_asset_id`.
5. **Threat intel** — stub ACL always returns `0.0`.
6. **Compliance gap** — proxy from open finding count when no explicit loader is provided.
7. **History** — both JSONB history on the score row (domain aggregate) and append-only `cloud_risk_history` table are written.

## Validation results

| Check | Result |
|-------|--------|
| Ruff (Phase 7 surface) | Pass |
| Mypy `--strict` | Pass |
| Phase 7 pytest | **199 passed** (with `TEST_DATABASE_URL`) |
| Alembic | Head `0052` on `redforge` + `redforge_test` |
| OpenAPI | 9 `/cloud-foundation/risk/*` paths |
| Startup | Healthy; risk routes **401** without auth |
| Deterministic scoring | Same `RiskSignalSnapshot` → identical overall score |
| Ontology | `ONTOLOGY_VERSION = 12` |

Suite paths:
- `tests/unit/cloud_security/risk/`
- `tests/api/cloud_security/test_cloud_risk_api.py`
- `tests/integration/cloud_security/test_risk_migration.py`
- `tests/integration/cloud_security/test_risk_repositories.py`

---

## Remaining out of scope

- Attack-path generation / privilege-escalation analytics  
- Runtime detections  
- Cloud AI Security (plan Phase 7 elsewhere)  
- Dashboards / executive reporting  
- Scheduled workers (`CloudRiskCalculationWorker`)  
- Auto remediation  
- Live Threat Intel / Exposure Graph BC wiring (stubs return 0)

---

## Stop condition

Phase 7 implementation is complete. **No commit. No push.** Waiting for architecture review before Phase 8+.
