# M19 Advanced DDoS Defense Center — Architecture & Implementation Report

## Overview

M19 implements an enterprise-grade DDoS Defense Center for AIVAR RedForge.
All detection is evidence-based, deterministic, and explainable. No machine
learning, no fabricated telemetry, no fake metrics.

---

## Canonical Data Sources

| Source | Table | Availability |
|--------|-------|-------------|
| Bytes in/out | `telemetry_events.bytes_in`, `bytes_out` | Available (nullable) |
| Packets in/out | `telemetry_events.packets_in`, `packets_out` | Available (nullable) |
| Source IP | `telemetry_events.src_ip` | Available (nullable) |
| Destination IP/port | `telemetry_events.dst_ip`, `dst_port` | Available |
| Protocol | `telemetry_events.protocol` | Available |
| Suricata alert type | `telemetry_events.event_type = "suricata_alert"` | Available |
| Suricata signature | `telemetry_events.signature` | Available (nullable) |
| Event timestamp | `telemetry_events.event_ts` | Available (event-time, not ingestion-time) |

### Explicitly Unavailable Signals

The following signals are **not available** in the M18 telemetry schema.
Detections that would require them are documented as missing evidence:

- **TCP flag counters** — not stored in `telemetry_events`; detection cannot
  use SYN/ACK ratios from raw flag counts
- **True SYN/ACK ratio** — no TCP state machine data; SYN flood inference relies
  only on Suricata alert signatures matching `%syn%flood%` pattern
- **L7 request rates** — no HTTP method/URL field; application-layer flood
  detection is not implemented
- **Reflection/amplification confirmation** — no packet-size or directional data
  at required granularity

---

## Domain Model

### Protected Resources (`ddos_protected_resources`)
Tenant-scoped resources explicitly enrolled for DDoS monitoring.
- scope_type: `any`, `ip`, `subnet`, `service`
- criticality: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`
- monitoring_enabled: boolean

### Detection Policies (`ddos_detection_policies`)
Per-resource detection configuration.
- window_seconds (default: 60)
- quiet_period_windows (default: 3) — consecutive clean windows before RESOLVED
- mitigation_mode: `RECOMMEND_ONLY` (default) / `APPROVAL_REQUIRED` / `NOT_CONFIGURED`

### Observation Windows (`ddos_observation_windows`)
One row per completed time window per resource. Idempotent via
`ON CONFLICT DO UPDATE` on `(org, resource, window_start_ts)`.

### Incidents (`ddos_incidents`)
Correlated attack events. Lifecycle:
```
DETECTED → ACTIVE → ESCALATED → MITIGATING → MONITORING → RESOLVED → CLOSED
```
Version column for optimistic concurrency. Status transitions are versioned;
metric updates (peaks) are best-effort (last-writer-wins).

### Incident Events (`ddos_incident_events`)
Append-only timeline. Every status transition and escalation is recorded.

### Mitigation Recommendations (`ddos_mitigation_recommendations`)
PENDING → APPROVED / REJECTED. No execution adapter configured in M19.
Approval requires `DDOS_MITIGATION_APPROVE` permission.

---

## Aggregation Architecture

Window aggregation runs 5 parallel queries over `telemetry_events`:
1. Aggregate: `SUM(bytes_in)`, `SUM(bytes_out)`, `SUM(packets_in)`, `SUM(packets_out)`, `COUNT(*)`
2. Unique source IPs: `COUNT(DISTINCT src_ip)`
3. Unique destination ports: `COUNT(DISTINCT dst_port)`
4. Protocol distribution: `GROUP BY protocol`
5. Alert count: `WHERE event_type = 'suricata_alert'`
6. SYN pattern alert count: `WHERE signature ILIKE '%syn%flood%'`

All queries are bounded: `event_ts >= window_start AND event_ts < window_end`.
No unbounded scans. Cross-tenant isolation via `organization_id` filter.

---

## Baseline Architecture

`compute_baseline()` is a pure function computing p75 statistics over
a rolling 7-day history of `DDoSObservationWindowModel` rows.

### p75 Rationale
The 75th percentile is used instead of the mean to be robust against
occasional legitimate traffic spikes (marketing campaigns, scheduled jobs,
replication bursts). The mean would inflate under these conditions and
reduce the sensitivity of the deviation multiplier.

### Cold-Start Behavior
When fewer than `MIN_BASELINE_WINDOWS = 20` windows exist:
- Confidence: `COLD_START` (0 windows) or `INSUFFICIENT_DATA` (1–19 windows)
- Only static thresholds (from policy config) are used for detection
- If no static threshold configured: that signal cannot fire — detection is skipped
- "SUSPECTED" labels applied to all classifications under cold-start

---

## Detection Architecture

`evaluate_window()` is a pure function evaluating 7 independent signals:

| Signal | Condition | Baseline Source | Threshold |
|--------|-----------|----------------|-----------|
| BPS deviation | bytes/s ≥ 2× baseline | p75 or static | configurable |
| PPS deviation | pkts/s ≥ 2× baseline | p75 or static | configurable |
| FPS deviation | flows/s ≥ 2× baseline | p75 or static | configurable |
| Unique source IPs | ≥ 50 unique src IPs | absolute | `DISTRIBUTED_THRESHOLD_UNIQUE_SOURCES = 50` |
| UDP dominance | UDP ≥ 80% of protocol events | absolute | `UDP_FLOOD_PROTOCOL_FRACTION = 0.80` |
| ICMP dominance | ICMP ≥ 80% of protocol events | absolute | `ICMP_FLOOD_PROTOCOL_FRACTION = 0.80` |
| SYN flood alerts | SYN-pattern alerts ≥ 60% of total alerts AND alert_count ≥ 5 | absolute | `SYN_FLOOD_ALERT_FRACTION = 0.60` |

A detection fires when ≥ 1 signal breaches its threshold AND
`event_count ≥ MIN_EVENTS_FOR_DETECTION = 10`.

---

## Severity Semantics

Deterministic severity from highest matched deviation + absolute checks:

| Severity | Condition |
|----------|-----------|
| CRITICAL | deviation ≥ 20× OR BPS ≥ 1 Gbps OR ≥ 3 signals |
| HIGH | deviation ≥ 10× OR PPS ≥ 1 Mpps OR ≥ 2 signals |
| MEDIUM | deviation ≥ 5× |
| LOW | deviation ≥ 2× |

---

## Classification Semantics

Priority order (first match wins):

1. SYN_FLOOD_SUSPECTED — SYN alert signature signal fires
2. UDP_FLOOD_SUSPECTED — UDP dominance signal fires
3. ICMP_FLOOD_SUSPECTED — ICMP dominance signal fires
4. DISTRIBUTED_VOLUMETRIC_FLOOD — distributed source + volumetric signals
5. VOLUMETRIC_FLOOD — BPS/PPS deviation only
6. ANOMALOUS_TRAFFIC_SURGE — FPS or distributed signal without volumetric
7. UNCLASSIFIED_DDOS_SUSPECTED — fallback

`SUSPECTED` suffix indicates inferential classification (not confirmed from
direct packet inspection). Confidence labels are always shown.

---

## Incident Correlation

One incident per protected resource per attack event. Correlation:
- If an open incident exists: update metrics, reset quiet counter, escalate severity if needed
- If no open incident: create new DETECTED incident (SAVEPOINT + refetch for concurrent protection)
- After quiet windows ≥ policy.quiet_period_windows: transition to RESOLVED

Recurrence: RESOLVED incident remains open for recurrence detection via the
`get_open_for_resource` query (which includes RESOLVED in open states if
the attack resumes).

---

## Concurrency Safety

| Operation | Mechanism |
|-----------|-----------|
| Incident creation | SAVEPOINT + refetch on IntegrityError |
| Status transition | Optimistic concurrency (`version` column) |
| Window upsert | `ON CONFLICT DO UPDATE` |
| Metric updates | Best-effort (last-writer-wins) |
| Mitigation approval | Idempotent check before update |

---

## Supported DDoS Categories

| Category | Signal | Confidence |
|----------|--------|-----------|
| Volumetric BPS flood | BPS deviation | CONFIRMED if deviation proven |
| Volumetric PPS flood | PPS deviation | CONFIRMED if deviation proven |
| Distributed flood | ≥50 unique source IPs | CONFIRMED by telemetry |
| UDP flood | UDP protocol dominance | CONFIRMED by protocol distribution |
| ICMP flood | ICMP protocol dominance | CONFIRMED by protocol distribution |
| SYN flood | Suricata SYN alert signatures | INFERENTIAL (SUSPECTED) |

## Unsupported Categories

| Category | Reason |
|----------|--------|
| TCP flag analysis | TCP flags not stored in telemetry_events |
| True SYN/ACK ratio | No TCP state machine data |
| L7 HTTP flood | No HTTP request rate signal |
| Reflection/amplification | No packet-size or direction granularity |
| Connection exhaustion | No connection-state tracking |

---

## RBAC

| Permission | Roles |
|-----------|-------|
| `ddos:read` | OWNER, ADMIN, SECURITY_MANAGER, ANALYST, MEMBER, VIEWER |
| `ddos:manage` | OWNER, ADMIN, SECURITY_MANAGER |
| `ddos:mitigation_approve` | OWNER, ADMIN, SECURITY_MANAGER |

---

## Mitigation Safety

- Default mode: `RECOMMEND_ONLY` — no action without explicit approval
- Approval requires `DDOS_MITIGATION_APPROVE` permission
- Execution adapter: **NOT CONFIGURED** in M19
- Recommendations document the suggested action for manual operator execution
- All approvals and rejections are logged with actor identity

---

## Frontend Pages

| Route | Feature |
|-------|---------|
| `/ddos` | DDoS Overview with posture, active incidents, evidence notice |
| `/ddos/incidents` | Incident list with status/severity filters |
| `/ddos/incidents/[id]` | Full investigation: evidence, timeline, mitigation |
| `/ddos/traffic` | Traffic analytics with SVG charts over real window data |
| `/ddos/protected-resources` | Resource CRUD with policy status |
| `/ddos/mitigation` | Pending recommendations with approve/reject workflow |

All visualizations are backed by real data from `ddos_observation_windows`
and `ddos_incidents`. No hardcoded metrics, no fake values.

---

## Migration

Migration 0031 (`0031_ddos_defense_center.py`) creates 6 tables:
- `ddos_protected_resources`
- `ddos_detection_policies`
- `ddos_observation_windows`
- `ddos_incidents`
- `ddos_incident_events`
- `ddos_mitigation_recommendations`

Downgrade removes all 6 tables in reverse dependency order.

---

## Worker

`DDoSDetectionWorker` follows the `ContinuousValidationSchedulerWorker` pattern:
- asyncio poll loop with configurable `poll_seconds` (default: 60)
- iterates all enabled resources via JOIN query
- exception isolation per resource (one failure doesn't abort batch)
- `start()` / `stop()` / `stats()` lifecycle
- wired into `GracefulShutdownCoordinator` in `app.py`

---

## Stream Integration

DDoS incident events appear in the M15 Security Operations stream as source tag "Z".
`SourceDomain.DDOS` added to the closed StrEnum. The injection is wrapped in
`try/except` to degrade gracefully when the DDoS tables are not yet migrated.
