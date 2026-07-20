# M26 Phase 6 — Runtime Visibility Implementation Report

**Status:** Complete — awaiting architecture review  
**Date:** 2026-07-19  
**Scope:** Runtime event ingestion, normalization, soft inventory correlation, CSPM snapshot reuse, ontology v11, APIs  
**Not committed / not pushed**

---

## 1. Verdict

M26 Phase 6 delivers cloud runtime visibility as an inventory/observation layer: provider payloads normalize to `CloudRuntimeEvent`, persist with dedup, soft-correlate to existing inventory IDs, project to Security Graph, and optionally evaluate via the existing CSPM `PolicyEvaluationEngine` through `cspm_snapshot()`. No workers, detections, eBPF/Falco, risk engine, dashboards, or auto-remediation.

---

## 2. What Was Delivered

### 2.1 Domain (pre-existing — not redesigned)

`backend/src/redforge/domain/cloud_security/runtime/`

| Aggregate / VO | Role |
|---|---|
| `CloudRuntimeEvent` | Ingest + 64KB raw truncate + `cspm_snapshot()` |
| `RuntimeProcess` / `RuntimeNetworkConnection` / `RuntimeFileActivity` | Observation aggregates |
| `RuntimeIdentitySession` / `RuntimeExecutionContext` | Session/context aggregates |
| `RuntimeCorrelationRefs` | Soft refs to asset/IAM/workload/account/org |
| Repository Protocols | Including `save_batch → int` for dedup |

### 2.2 Ontology v11

`ONTOLOGY_VERSION = 11`

**Node kinds:** `RUNTIME_EVENT`, `RUNTIME_PROCESS`, `RUNTIME_CONNECTION`  
**Edge kinds:** `OBSERVED_ON`, `ASSOCIATED_WITH`, `ORIGINATED_FROM`  
**Pairs:** runtime → cloud_resource/asset/k8s_workload; runtime → identity/iam_role/service_identity; runtime → cloud_account  
Inventory projection only — no traversal.

### 2.3 Migration 0051

Schema `cloud_security`:

| Table | Notes |
|---|---|
| `cloud_runtime_events` | **PARTITION BY RANGE (event_time)**; monthly partitions (current ±1) + DEFAULT; unique `(organization_id, source, provider_event_id, event_time)` |
| `runtime_processes` | Linked by `runtime_event_id` |
| `runtime_network_connections` | |
| `runtime_file_activities` | |
| `runtime_identity_sessions` | |
| `runtime_execution_contexts` | |
| `runtime_artifacts` | Artifact store per event |

`_EXPECTED_MIGRATION_HEAD` bumped to `"0051"` in platform + credential_vault startup validators.

### 2.4 Infrastructure

`infrastructure/cloud_security/runtime/`:

- `mappings.py` — domain ↔ SQLAlchemy
- `repositories.py` — `PgRuntimeEventRepository.save_batch` with `ON CONFLICT DO NOTHING` (Core insert; avoids ORM `metadata` collision)
- `adapters/` — AWS CloudTrail, Azure Activity, GCP Audit, Kubernetes Audit (raw dicts only)
- `fake_adapter.py` — `FakeRuntimeSourceAdapter`
- `acl/runtime_graph_acl.py` — best-effort graph projection

### 2.5 Application

`application/cloud_security/runtime/`:

| Service | Responsibility |
|---|---|
| `RuntimeNormalizationService` | Raw / `RawRuntimeEvent` → domain bundles |
| `RuntimeCorrelationService` | Soft inventory refs only (no detections) |
| `RuntimeIngestionService` | Normalize → correlate → persist → project |
| `CspmRuntimePolicyInterface` | Reuse `PolicyEvaluationEngine` via `cspm_snapshot()` |
| `RuntimeQueryService` | list/get/summary |

### 2.6 API (`/api/v1/cloud-foundation`)

| Method | Path | Permission |
|---|---|---|
| POST | `/runtime/events/ingest` | ORG_MANAGE |
| GET | `/runtime/events` | ORG_READ |
| GET | `/runtime/events/{event_id}` | ORG_READ |
| GET | `/runtime/processes` | ORG_READ |
| GET | `/runtime/network-connections` | ORG_READ |
| GET | `/runtime/summary` | ORG_READ |

### 2.7 Security Graph projector

New `project_runtime_*` methods for nodes and edges (`OBSERVED_ON`, `ASSOCIATED_WITH`, `ORIGINATED_FROM`).

---

## 3. Validation

| Gate | Result |
|---|---|
| Ruff (Phase 6 surface) | Pass |
| Mypy `--strict` | Pass |
| Phase 6 pytest | **135 passed** (with `TEST_DATABASE_URL`) |
| Alembic | Head `0051`; round-trip 0051↔0050 covered |
| OpenAPI | Cloud-foundation runtime paths registered (`/runtime/events`, ingest, processes, connections, summary) |
| Startup | Healthy; `/api/v1/runtime/status` 200; cloud-foundation runtime routes **401** without auth |
| Ingestion + CSPM | `CloudRuntimeEvent.ingest` + `cspm_snapshot()` evaluates via shared `PolicyEvaluationEngine` |
| Ontology | `ONTOLOGY_VERSION = 11` |

| Suite | Approx |
|---|---|
| Unit + API | 133 |
| Integration | 2 |
| **Total Phase 6** | **135** |

---

## 4. Architecture Deviations

1. **Partition unique key:** PostgreSQL requires the partition key in unique indexes. Dedup unique is `(organization_id, source, provider_event_id, event_time)` — not `(org, source, provider_event_id)` alone. Same provider event with identical `event_time` still dedups; cross-time duplicates are not blocked.
2. **Workers:** Explicitly omitted (mission override). Ingest is API-triggered only.
3. **Detections:** No `SuspiciousActivityDetected`, brute-force, or attack-path logic. Correlation emits soft inventory refs only.
4. **eBPF / Falco / risk / dashboards / auto-remediation:** Out of scope per mission.
5. **SDK models:** Adapters accept in-memory raw dicts / lists; no boto3/Azure/GCP/k8s SDK types in the runtime package.

---

## 5. Explicit Out of Scope

- Workers / scheduled jobs  
- Detection rules / suspicious activity / brute-force / attack paths  
- eBPF / Falco / Sysdig / container runtime agents  
- Cloud Risk Engine  
- Dashboards  
- Auto remediation  
- Second policy engine (CSPM engine reused)  
- Graph traversal / attack-path analysis  
- Live CloudTrail/Activity/Audit streaming SDKs (dict adapters + Fake for CI)

---

## 6. Key Paths

```
backend/src/redforge/domain/cloud_security/runtime/
backend/src/redforge/application/cloud_security/runtime/
backend/src/redforge/infrastructure/cloud_security/runtime/
backend/src/redforge/infrastructure/cloud_security/acl/runtime_graph_acl.py
backend/src/redforge/api/v1/cloud_runtime.py
backend/src/redforge/infrastructure/database/migrations/versions/0051_cloud_runtime_events.py
backend/tests/unit/cloud_security/runtime/
backend/tests/api/cloud_security/test_cloud_runtime_api.py
backend/tests/integration/cloud_security/test_runtime_*.py
docs/architecture/m26/M26_PHASE6_IMPLEMENTATION_REPORT.md
```

---

## 7. Stop Condition

Phase 6 implementation is complete. **No commit. No push.** Waiting for architecture review before Phase 7+.
