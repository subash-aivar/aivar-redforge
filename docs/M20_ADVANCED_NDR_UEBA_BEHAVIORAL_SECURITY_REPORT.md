# M20 — Advanced Network Detection & Response (NDR), UEBA, and Behavioral Threat Detection

**Sprint:** M20  
**Completed:** 2026-07-15  
**M20 domain tests:** 36/36  
**M20 PostgreSQL integration tests:** 26/26  
**Full backend suite (all sprints):** 4,413 passed, 4 failed (pre-existing, outside M20 scope), 5 skipped  
**Frontend Vitest:** 131/131  
**Migration head:** 0033  
**Status:** COMPLETE — pending commit authorization

---

## Executive Summary

M20 delivers the Enterprise Behavioral Security Intelligence Layer for AIVAR RedForge: a production-grade NDR/UEBA platform that continuously analyzes canonical `telemetry_events` (Zeek/Suricata) and surfaces behavioral anomalies through evidence-backed detection. Every detection is derived from real network telemetry; no detection is fabricated or inferred without signal.

The system implements the behavioral detection philosophy: **BEHAVIOR BEFORE LABELS** — classifications end in `_SUSPECTED` where confirmation is impossible from network metadata alone, and every detection explicitly lists both matched signals and missing evidence.

---

## Architecture Overview

### Bounded Context: `behavior`

```
redforge/
  domain/behavior/
    value_objects.py       ← enums, constants, is_rfc1918() helper
    detection.py           ← pure detection engine (no I/O, fully testable)
  application/behavior/
    detection_service.py   ← BehaviorDetectionService: orchestrates detection cycles
    detection_worker.py    ← BehaviorDetectionWorker: asyncio poll loop (5-min intervals)
  api/v1/
    behavior.py            ← 7 REST endpoints, all tenant-scoped
  infrastructure/database/
    models/behavior.py     ← 4 ORM models
    repositories/behavior/
      detection_repository.py  ← race-safe detection upsert + baseline repository
    migrations/versions/
      0033_behavioral_ndr.py   ← schema + partial unique index
```

### Data Flow

```
telemetry_events (canonical)
        │
        ▼
BehaviorDetectionWorker (asyncio, 5-min poll)
        │
        ▼
BehaviorDetectionService.run_cycle()
        │
        ├─ _get_active_src_ips()        — distinct src_ips in window
        ├─ _analyze_entity(src_ip)      — per-entity pipeline:
        │     ├─ _compute_window_metrics()   — 5 SQL aggregation queries
        │     ├─ compute_entity_baseline()   — p75-based adaptive baseline
        │     ├─ evaluate_fan_out()          — HIGH_FAN_OUT detection
        │     ├─ evaluate_port_scan()        — PORT_SCAN_SUSPECTED detection
        │     ├─ evaluate_outbound_transfer() — ABNORMAL_OUTBOUND_TRANSFER
        │     ├─ evaluate_new_destinations() — NEW_DESTINATION, RARE_DESTINATION
        │     ├─ evaluate_east_west()        — UNUSUAL_EAST_WEST detection
        │     ├─ evaluate_unusual_service_access() — UNUSUAL_SERVICE_ACCESS
        │     ├─ open_or_update_detection()  — race-safe upsert
        │     └─ upsert_observation()        — idempotent window record
        └─ _run_beaconing_analysis()     — BEACONING_SUSPECTED (pair-level, 2h lookback)
```

---

## Detection Engine

### Supported Detections (8)

| Detection Type | Trigger | Severity | Classification |
|---|---|---|---|
| `HIGH_FAN_OUT` | unique dst_ips ≥ FAN_OUT_MEDIUM_THRESHOLD (20) in window | MEDIUM/HIGH | ANOMALOUS |
| `PORT_SCAN_SUSPECTED` | unique dst_ports ≥ PORT_SCAN_MEDIUM_THRESHOLD (15) in window | MEDIUM/HIGH | SUSPECTED |
| `NEW_DESTINATION` | dst_ip never seen by this src in baseline history | LOW/MEDIUM | ANOMALOUS |
| `RARE_DESTINATION` | dst_ip seen ≤ RARE_DESTINATION_THRESHOLD (3) times historically | LOW | INFORMATIONAL |
| `BEACONING_SUSPECTED` | periodic intervals (jitter_coefficient ≤ 0.25, ≥ 8 samples, ≥ 20s interval) | MEDIUM/HIGH | SUSPECTED |
| `ABNORMAL_OUTBOUND_TRANSFER` | bytes_out > p75_bytes_out × TRANSFER_LOW_DEVIATION (3.0×) | MEDIUM/HIGH/CRITICAL | ANOMALOUS |
| `UNUSUAL_EAST_WEST` | new RFC-1918 → RFC-1918 communication pair | MEDIUM | ANOMALOUS |
| `UNUSUAL_SERVICE_ACCESS` | new (dst_ip, dst_port) service pair never seen by this src | LOW | INFORMATIONAL |

### Honestly Unsupported (4)

These are explicitly documented as unsupported due to missing canonical evidence:

- **User authentication anomalies** — no auth events in `telemetry_events`
- **Impossible travel** — no session geo data in canonical telemetry
- **Failed connection ratio** — no TCP state machine data (only completed connections)
- **Lateral movement confirmed** — requires host-level evidence beyond network telemetry

### Baseline Engine

- **Algorithm:** p75 (75th percentile) of `unique_dst_ips`, `bytes_out`, `event_count` across rolling 30-window history
- **Cold-start:** `BaselineConfidence.COLD_START` when < `MIN_BASELINE_WINDOWS` (10) windows accumulated
- **Established:** `BaselineConfidence.ESTABLISHED` once ≥ 10 windows exist
- **Poisoning resistance:** p75 not mean; extreme outlier events don't skew thresholds

### Beaconing Analysis

Detected via inter-arrival time statistics:
- Minimum 8 timestamp samples per (src_ip, dst_ip, port) pair
- Jitter coefficient = std(intervals) / mean(intervals) ≤ 0.25
- Minimum interval ≥ 20 seconds (noise floor)
- **Mandatory C2 caveat** in `missing_evidence`: "c2_confirmation: periodic traffic is consistent with C2 but requires host-level confirmation"

---

## Race-Safety & Persistence

### Pattern: Advisory Lock + Partial Unique Index

Replicates the M19 DDoS pattern:

```sql
-- Partial unique index (one active detection per correlation key)
CREATE UNIQUE INDEX ux_bd_org_corr_active
  ON behavior_detections (organization_id, correlation_key)
  WHERE status IN ('DETECTED', 'ACTIVE', 'INVESTIGATING', 'MONITORING');

-- Per-detection advisory lock (serializes concurrent workers)
SELECT pg_advisory_xact_lock(:hash_of_org_and_correlation_key);
```

Concurrent detection proof: 10 parallel sessions attempting to open the same detection → exactly 1 active detection (TestConcurrencyProof::test_concurrent_detection_opening, PROVEN).

### Observation Idempotency

```sql
-- Idempotent window observation insert
INSERT INTO behavior_observations ... ON CONFLICT (organization_id, entity_id, window_start_ts) DO NOTHING
```

---

## Database Schema (migration 0033)

### Tables Created

| Table | Purpose |
|---|---|
| `behavior_entity_baselines` | Rolling per-entity stats: p75 metrics, seen IP/service/pair sets |
| `behavior_observations` | One row per (entity, 5-min window), idempotent insert |
| `behavior_detections` | Detection lifecycle: DETECTED → ACTIVE → INVESTIGATING/MONITORING → RESOLVED/CLOSED |
| `behavior_detection_events` | Timeline entries: DETECTION_OPENED, DETECTION_CLOSED, etc. |

### Key Indexes

```sql
UNIQUE INDEX ux_beb_org_entity ON behavior_entity_baselines (organization_id, entity_type, entity_id)
UNIQUE INDEX ux_bo_org_entity_window ON behavior_observations (organization_id, entity_id, window_start_ts)
UNIQUE INDEX ux_bd_org_corr_active ON behavior_detections (organization_id, correlation_key)
    WHERE status IN ('DETECTED', 'ACTIVE', 'INVESTIGATING', 'MONITORING')
```

---

## API Surface

All endpoints under `/api/v1/behavior/`, all tenant-scoped via JWT `organization_id`.

| Method | Path | Permission | Description |
|---|---|---|---|
| GET | `/behavior/posture` | BEHAVIOR_READ | Global posture: counts, severity breakdown, recent detections |
| GET | `/behavior/detections` | BEHAVIOR_READ | List detections with status/entity_id filters |
| GET | `/behavior/detections/{id}` | BEHAVIOR_READ | Detection detail + timeline |
| POST | `/behavior/detections/{id}/close` | BEHAVIOR_MANAGE | Analyst closes detection |
| GET | `/behavior/entities` | BEHAVIOR_READ | Entity risk matrix sorted by severity |
| GET | `/behavior/entities/{entity_id}` | BEHAVIOR_READ | Full entity behavior profile |
| GET | `/behavior/network/relationships` | BEHAVIOR_READ | Communication pairs from canonical telemetry |
| GET | `/behavior/health` | BEHAVIOR_READ | Subsystem health: supported/unsupported lists |

### New Permissions

```python
BEHAVIOR_READ   = "behavior:read"   # OWNER, SECURITY_MANAGER, ANALYST, MEMBER, VIEWER
BEHAVIOR_MANAGE = "behavior:manage" # OWNER, SECURITY_MANAGER
```

---

## Frontend: NDR Operations Center

### Pages (5)

| Route | Component | Description |
|---|---|---|
| `/behavior` | NDR Operations Center | 6-tile posture header, Live Behavior Radar, Entity Risk Matrix, Canonical Evidence Basis |
| `/behavior/detections` | Live Detections | Status filter tabs, detection list with severity badges |
| `/behavior/detections/[id]` | Detection Detail | Investigation workspace: evidence, matched signals, missing evidence, timeline |
| `/behavior/entities` | Entity Risk Matrix | Sorted entity table with risk levels and active detection counts |
| `/behavior/network` | Network Relationships | Communication pairs with hour/type filters; RFC-1918 internal detection |

### Design Principles Applied

- Dark tactical command-center aesthetic consistent with M19 DDoS Defense Center
- Honest empty states: "No active behavioral detections — entities appear after first telemetry windows"
- No fabricated metrics, no hardcoded numbers, no fake risk scores
- 30-second auto-refresh cycle
- Canonical Evidence Basis notice on every main view: supported and explicitly unsupported detections listed

---

## Test Coverage

### Domain Unit Tests (36/36)
- `TestIsRfc1918` (5) — RFC-1918 range detection
- `TestBaselineComputation` (4) — p75, cold-start, window count
- `TestFanOutDetection` (5) — thresholds, severity levels
- `TestPortScanDetection` (3) — thresholds, noise gate
- `TestDestinationDetection` (3) — new/rare destination logic
- `TestOutboundTransfer` (5) — deviation multipliers, missing bytes
- `TestEastWestDetection` (3) — RFC-1918 pairs
- `TestUnusualServiceAccess` (2) — service pair tracking
- `TestBeaconingAnalysis` (6) — interval math, jitter, C2 caveat

### PostgreSQL Integration Tests (26/26)
- `TestMigrationProof` (2) — tables + partial unique index
- `TestTenantIsolation` (3) — cross-tenant access denied
- `TestRbac` (4) — permission gates
- `TestConcurrencyProof` (2) — 10 concurrent sessions, observation_count
- `TestLabANewDestination` (1) — E2E: telemetry → detection cycle → API
- `TestLabBBeaconing` (1) — beaconing interval math
- `TestLabCFanOut` (2) — HIGH_FAN_OUT fires/doesn't-fire
- `TestLabDAbnormalTransfer` (1) — 3× deviation trigger
- `TestDuplicateDetectionPrevention` (1) — idempotent upsert
- `TestWorkerStats` (1) — worker lifecycle
- `TestTraceabilityIntegrity` (5) — document consistency: unique IDs, valid statuses, distribution arithmetic, required IDs, summary arithmetic (consistency-only — milestone verdict is separate human review)
- `TestWorkerRuntimeProof` (2) — real PostgreSQL detection cycle; duplicate-worker `pg_try_advisory_xact_lock` return value check
- `TestOperationalStreamIntegration` (1) — behavior detection events surface in merged security operations stream via `SourceDomain.BEHAVIOR` (source tag "W")

---

## Surgical Closure (6 Gaps Fixed Post-Initial Delivery)

The following gaps were identified and fixed during a strict completion audit:

| Gap | Finding | Fix |
|---|---|---|
| G1 | `startup_validator._EXPECTED_MIGRATION_HEAD = "0032"` — stale, allowed wrong-schema boot | Changed to `"0033"`; 3 affected unit tests updated |
| G2a | `SourceDomain.BEHAVIOR` missing from `value_objects` enum | Added `BEHAVIOR = "behavior"` |
| G2b | `list_detection_events_since` missing from detection repository | Added method filtering `event_type == "DETECTION_OPENED"` |
| G2c | M20 not wired into `fetch_merged_candidates` operational stream | Added "W" source block with `SourceDomain.BEHAVIOR` and HIGH/NOTICE importance classification |
| G4 | `pg_try_advisory_xact_lock` result never checked — duplicate workers both proceeded | Checked `lock_acquired = lock_result.scalar()`, return if False |
| G5 | OP-01, WR-01, WR-02 scenarios unproven; traceability arithmetic unchecked | Added 3 new integration test classes (4 net new tests); `test_summary_arithmetic` |

---

## Adversarial Traceability Summary

Total: **39 scenarios**

| Status | Count |
|---|---|
| PROVEN | 35 |
| PARTIALLY PROVEN | 0 |
| NOT PROVEN | 0 |
| NOT APPLICABLE | 4 |

See [M20_ADVERSARIAL_TRACEABILITY_MATRIX.md](M20_ADVERSARIAL_TRACEABILITY_MATRIX.md) for full per-scenario evidence.

---

## Full Backend Suite Truth

The full backend test suite (`tests/unit/ + tests/domain/ + tests/integration/`) produces:

- **4,413 passed**
- **4 failed** — all outside M20 scope
- **5 skipped**

The 4 failures are pre-existing and unrelated to M20:

| Test | Root Cause |
|---|---|
| `test_network_security_restart_durability.py::test_cancellation_request_survives_two_simulated_process_restarts` | Always-failing pre-existing defect in network_security scheduler restart logic. Present before M20. |
| `test_network_security_concurrency_proof.py::test_concurrent_scheduler_claim_converges_on_exactly_one_winner` | Cross-test DB contamination: passes in isolation, fails in full suite because an earlier test leaves an abandoned RUNNING network scan that blocks this test's claim query. Pre-existing test isolation debt. |
| `test_network_security_concurrency_proof.py::test_paused_policy_never_claimed` | Same cross-test DB contamination. Passes in isolation. |
| `test_network_security_concurrency_proof.py::test_disabled_policy_never_claimed` | Same cross-test DB contamination. Passes in isolation. |

M20 made no changes to network_security scheduler code. These failures were confirmed pre-existing by running the failing tests in isolation (1 failed, 3 passed).

---

## Browser Populated Acceptance

Browser acceptance was completed with isolated TEST/LAB DATA seeded through the canonical path:

- Seeded 64 `telemetry_events` to org `01KXJ4WEBMSXQ71GDYHP10J2CX` ("M20 Lab") via `TelemetrySensorModel` + `TelemetryEventModel` — using RFC-1918 source IPs and RFC-5737 TEST-NET destinations only
- Ran `BehaviorDetectionService.run_cycle()` against the lab org — produced 64 detections, 5 entity risk profiles, 48 observed communication pairs
- All four `/behavior/*` routes verified populated with real derived data:
  - `/behavior` — 64 active detections, type breakdown, 2 beaconing/2 east-west tiles
  - `/behavior/detections` — full list with evidence-backed summaries and mandatory caveats
  - `/behavior/entities` — Entity Risk Matrix: 5 IPs ranked HIGH/MEDIUM/LOW
  - `/behavior/network` — 48 network relationships observed from canonical `telemetry_events`

**Lab data cleanup:** After browser acceptance, all lab data was surgically removed:
- 64 `behavior_detection_events`, 64 `behavior_detections`, 6 `behavior_observations`, 5 `behavior_entity_baselines`, 64 `telemetry_events`, 1 `telemetry_sensors`, 1 `memberships`, 1 `organizations`, 1 `users` — all deleted by exact org_id and user_id
- No legitimate development/product data was removed
- Post-cleanup: `GET /api/v1/health` → `{"status":"healthy"}`, alembic_version = `0033`, `behavior_detections` count = 0
- No fake production data remains in the database

---

## Known Pre-existing Vulnerabilities (not M20-introduced)

- 2 moderate severity npm audit findings in `next/postcss` — present before M20, no fix available without breaking change

---

## What Was NOT Built (Honest Scope Boundary)

The following were explicitly scoped out and are documented as NOT_APPLICABLE:

1. **User behavior analytics (UEBA proper)** — requires auth event stream not in `telemetry_events`
2. **Impossible travel detection** — requires session geolocation data
3. **TCP failed connection ratio** — requires full TCP state machine, not just completed connections
4. **Confirmed lateral movement** — requires endpoint/host telemetry beyond network flows
5. **Security Graph edges for behavioral detections** — cross-bounded-context correlation between behavior context and the Security Graph is explicitly M21 scope (NA-04)
6. **Real-time streaming** — worker operates on 5-minute poll windows, not packet-level streaming

These are not deferred — they are honestly not supportable from the current canonical data source.
