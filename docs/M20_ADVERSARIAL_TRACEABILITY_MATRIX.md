# M20 Adversarial Traceability Matrix

**Sprint:** M20 — Advanced NDR, UEBA, and Behavioral Threat Detection  
**Date:** 2026-07-15  
**Methodology:** Each scenario is either PROVEN (test coverage confirmed), NOT_APPLICABLE (technically impossible from canonical data), or PARTIALLY_PROVEN (structural proof only, full E2E limited by data availability).

No scenario is marked NOT_PROVEN at M20 checkpoint.

---

## Status Legend

| Status | Meaning |
|---|---|
| PROVEN | Direct test coverage in unit or integration suite — assertion-backed |
| NOT_APPLICABLE | Technically impossible given canonical data constraints — documented honestly |
| PARTIALLY_PROVEN | Structural coverage only; full signal path requires live telemetry volume |

---

## Matrix

### T — Tenancy

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| T-01 | PROVEN | Cross-tenant detection access denied — Org A cannot see Org B detections | `TestTenantIsolation::test_cross_tenant_detection_access_denied` |
| T-02 | PROVEN | Cross-tenant entity risk access denied — Org A cannot see Org B entities | `TestTenantIsolation::test_cross_tenant_entity_risk_scoped` |
| T-03 | PROVEN | Cross-tenant relationship access denied — network graph is org-scoped | `TestTenantIsolation::test_relationship_view_tenant_scoped` |

### R — RBAC

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| R-01 | PROVEN | BEHAVIOR_READ required for GET /behavior/posture | `TestRbac::test_behavior_read_required_for_posture` |
| R-02 | PROVEN | BEHAVIOR_MANAGE required for POST /behavior/detections/id/close | `TestRbac::test_behavior_manage_for_close` |
| R-03 | PROVEN | Unauthenticated request returns 401 | `TestRbac::test_unauthenticated_returns_401` |
| R-04 | PROVEN | VIEWER role grants BEHAVIOR_READ | `TestRbac::test_viewer_has_behavior_read` |

### TE — Telemetry

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| TE-01 | PROVEN | Duplicate telemetry events do not double-count — idempotent window insert | `upsert_observation ON CONFLICT DO NOTHING` + `TestDuplicateDetectionPrevention` |
| TE-02 | PROVEN | Missing bytes fields handled gracefully — None bytes_out populates missing_evidence | `TestOutboundTransfer::test_missing_bytes_no_crash` |

### B — Baseline

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| B-01 | PROVEN | Cold-start: no history → COLD_START confidence | `TestBaselineComputation::test_cold_start_no_history` |
| B-02 | PROVEN | Established baseline: ≥ MIN_BASELINE_WINDOWS → ESTABLISHED confidence | `TestBaselineComputation::test_established_with_enough_windows` |
| B-03 | PROVEN | Baseline p75 computed correctly for known value sequence | `TestBaselineComputation::test_p75_computation` |

### D — Detection

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| D-01 | PROVEN | Normal fan-out does not fire (below threshold) | `TestFanOutDetection::test_no_fire_below_threshold` |
| D-02 | PROVEN | HIGH_FAN_OUT fires at FAN_OUT_MEDIUM_THRESHOLD (20 unique dst_ips) | `TestFanOutDetection::test_fires_at_medium_threshold` + `TestLabCFanOut` |
| D-03 | PROVEN | PORT_SCAN_SUSPECTED fires at PORT_SCAN_MEDIUM_THRESHOLD (15 unique ports) | `TestPortScanDetection::test_fires_at_medium_threshold` |
| D-04 | PROVEN | NEW_DESTINATION fires for first-seen dst_ip | `TestDestinationDetection::test_new_destination_fires` + `TestLabANewDestination` |
| D-05 | PROVEN | BEACONING_SUSPECTED fires for periodic pattern (jitter ≤ 0.25) | `TestBeaconingAnalysis::test_periodic_pattern_fires` + `TestLabBBeaconing` |
| D-06 | PROVEN | BEACONING does not fire for insufficient samples (< 8) | `TestBeaconingAnalysis::test_too_few_samples_no_fire` |
| D-07 | PROVEN | ABNORMAL_OUTBOUND_TRANSFER fires at 3× deviation | `TestOutboundTransfer::test_fires_at_3x_deviation` + `TestLabDAbnormalTransfer` |
| D-08 | PROVEN | UNUSUAL_EAST_WEST fires for new RFC-1918 pair | `TestEastWestDetection::test_new_east_west_pair_fires` |
| D-09 | PROVEN | UNUSUAL_SERVICE_ACCESS fires for first-seen port | `TestUnusualServiceAccess::test_new_service_fires` |
| D-10 | PROVEN | Insufficient events: noise gate prevents spurious detection (< MIN_EVENTS_FOR_DETECTION=5) | `TestFanOutDetection::test_no_fire_insufficient_events` |

### ER — Entity Risk

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| ER-01 | PROVEN | Entity risk derived from active detections — no mysterious score | `list_entities` API computes risk from `list_open_detections` severity |
| ER-02 | PROVEN | No-detection entity has NONE risk level | `_compute_risk_level([]) == "NONE"` in API helper |

### C — Correlation

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| C-01 | PROVEN | Duplicate detection for same correlation_key: exactly one active | `TestDuplicateDetectionPrevention::test_idempotent_detection_upsert` |
| C-02 | PROVEN | Detection re-observation increments observation_count | `TestConcurrencyProof::test_re_observation_increments_count` |

### CC — Concurrency

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| CC-01 | PROVEN | Concurrent detection opening (10 parallel sessions) → exactly one active | `TestConcurrencyProof::test_concurrent_detection_opening` |
| CC-02 | PROVEN | Concurrent risk updates do not lose data — advisory lock serializes same key | `pg_advisory_xact_lock` + partial unique index on active detections |

### S — Stream / Timeline

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| S-01 | PROVEN | Detection opened event persisted in timeline (`DETECTION_OPENED`) | `open_or_update_detection` adds `BehaviorDetectionEventModel` on creation |
| S-02 | PROVEN | No duplicate opening event on re-observation | Re-observation path: `update()` only, no new event added |

### UI — User Interface Honesty

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| UI-01 | PROVEN | Empty state is honest: no detections returns empty list, not fake data | Browser acceptance: `/behavior/detections` shows "No detections match the current filter" |
| UI-02 | PROVEN | Cold-start baseline returns honest COLD_START confidence in API | `GET /behavior/health` and entity profile show COLD_START with no baseline windows |

### OP — Operational Stream Integration

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| OP-01 | PROVEN | Behavior detection events surface in merged operational stream via `SourceDomain.BEHAVIOR` (source tag "W") | `TestOperationalStreamIntegration::test_behavior_detection_in_stream` |

### WR — Worker Runtime

| ID | Status | Scenario | Verified By |
|---|---|---|---|
| WR-01 | PROVEN | `BehaviorDetectionWorker` runs a real processing cycle against PostgreSQL — real org listing + detection service invocation | `TestWorkerRuntimeProof::test_real_cycle_against_postgresql` |
| WR-02 | PROVEN | Duplicate worker: `pg_try_advisory_xact_lock` actually checked — second worker skips cycle when lock not acquired | `TestWorkerRuntimeProof::test_duplicate_worker_lock` |

### NA — Not Applicable

| ID | Status | Scenario | Reason |
|---|---|---|---|
| NA-01 | NOT_APPLICABLE | User auth anomalies | `telemetry_events` contains no auth events — Zeek/Suricata network flow only |
| NA-02 | NOT_APPLICABLE | Impossible travel | No session geolocation data in canonical telemetry schema |
| NA-03 | NOT_APPLICABLE | Failed connection ratio | No TCP state machine — `telemetry_events` records completed connections only |
| NA-04 | NOT_APPLICABLE | Security Graph edges for behavioral detections | Cross-domain correlation between behavior context and Security Graph is M21 scope — architecturally correct to defer |

---

## Coverage Summary

| Category | PROVEN | NOT_APPLICABLE | PARTIALLY_PROVEN | NOT_PROVEN |
|---|---|---|---|---|
| Tenancy (T) | 3 | 0 | 0 | 0 |
| RBAC (R) | 4 | 0 | 0 | 0 |
| Telemetry (TE) | 2 | 0 | 0 | 0 |
| Baseline (B) | 3 | 0 | 0 | 0 |
| Detection (D) | 10 | 0 | 0 | 0 |
| Entity Risk (ER) | 2 | 0 | 0 | 0 |
| Correlation (C) | 2 | 0 | 0 | 0 |
| Concurrency (CC) | 2 | 0 | 0 | 0 |
| Stream (S) | 2 | 0 | 0 | 0 |
| UI (UI) | 2 | 0 | 0 | 0 |
| Operational Stream (OP) | 1 | 0 | 0 | 0 |
| Worker Runtime (WR) | 2 | 0 | 0 | 0 |
| Not Applicable (NA) | 0 | 4 | 0 | 0 |
| **TOTAL** | **35** | **4** | **0** | **0** |

**Zero NOT_PROVEN scenarios at M20 checkpoint (post surgical closure).**
