# ADR-0008: Network Sensor Product Boundary (BYO + Future RedForge-Managed Sensor)

## Status

Accepted (architecture boundary only — sensor itself not yet built)

## Date

2026-09-08

## Context

A repository-first audit found **no real packet-capture, NetFlow/IPFIX/
sFlow collector, or deployable sensor/agent process anywhere in the
repository.** What exists is a push-ingestion API
(`redforge.application.telemetry.ingestion_service.TelemetryIngestionService`,
`sensor_service.py`'s `TelemetrySensorService`) that registers a
"sensor" per organization and accepts already-normalized Suricata EVE
JSON / Zeek JSON that a **customer's own** sensor produces and pushes
in. RedForge does not sniff traffic, capture packets, or ship a
collector binary today.

Network Defense Edition's target scope requires supporting a genuinely
turnkey, dedicated-office deployment — which implies, eventually, a
RedForge-distributed sensor, not only a "bring your own Suricata/Zeek"
integration story. Building packet-capture primitives from scratch would
duplicate mature, already-solved engineering (packet capture, protocol
decoding, flow export) that this team has no comparative advantage
building.

## Decision

Network Defense Edition must support **both** sensor models, and the two
are architecturally distinct concerns:

**A. BYO sensor (already real today)** — existing customers' own
Suricata/Zeek deployments continue to feed the existing
`TelemetryIngestionService`/`TelemetrySensorService` push-ingestion API
unchanged. This remains the supported integration path for any
environment where the customer already operates telemetry tooling.

**B. RedForge-managed Network Sensor (future, not built in this phase)**
— required for a turnkey dedicated-office deployment where no
customer-operated sensor exists. When built, it must follow this
boundary:

- **Do not reinvent mature packet-capture/inspection primitives.** The
  sensor should package and orchestrate proven, mature capture/
  inspection technology (e.g., a Suricata/Zeek/vector.dev/Fluent-Bit-class
  engine bundled and pre-configured by RedForge) rather than writing new
  packet-parsing code in this repository.
- **RedForge-owned surface, on top of that mature engine**, is where the
  actual product investment goes:
  - secure sensor registration (per-tenant identity, enrollment/pairing)
  - configuration management (what to capture, what to ship, policy push)
  - telemetry shipping (into the existing `TelemetryIngestionService`
    contract — the sensor is a producer of the same normalized shape BYO
    sensors already produce, not a new ingestion path)
  - local buffering/backpressure (surviving a network/ingestion outage
    without data loss, up to a bounded local retention window)
  - sensor identity and health (liveness, version, last-seen)
  - metrics (sensor-level operational telemetry, distinct from the
    network telemetry it forwards)
  - upgrade management (safe remote version rollout)
  - evidence linkage (a sensor-sourced finding's provenance must trace
    back to the specific sensor/capture session that produced it, for
    the existing `evidence` bounded context to cite)

**RedForge continues to own, unconditionally, regardless of which
sensor model is in play**: the telemetry contract itself, normalization,
the network entity model, detection (DDoS/behavior/network_security),
Threat Intelligence correlation (per ADR-0007), evidence, alerting,
investigation, and governed response. None of that changes based on
whether telemetry arrived from a BYO sensor or a future RedForge-managed
one — both are just producers against the same contract.

**No sensor implementation work begins in this phase.** This ADR
records the boundary only.

## Consequences

- BYO-sensor customers are unaffected by any future sensor work — same
  API, same contract, indefinitely.
- When sensor work is scoped, the build-vs-buy/package decision is
  already made: package a mature engine, build the RedForge-specific
  lifecycle/management layer around it. This avoids a multi-quarter
  detour into packet-capture engineering that duplicates existing open-
  source maturity.
- The `TelemetryIngestionService` contract becomes a load-bearing,
  stable interface earlier than it might otherwise have been treated —
  any future format expansion (NetFlow/IPFIX/sFlow/proxy/firewall/VPN
  parsers, all currently MISSING per the Phase 0 audit) should extend
  this same contract rather than introducing a parallel one for the
  managed sensor specifically.
- Evidence linkage from sensor-sourced findings is called out explicitly
  now so it isn't retrofitted awkwardly later — the `evidence` bounded
  context's tenant-scoped citation model (ADR-0003, evidence immutability)
  should be able to cite "sensor X, capture session Y" as a source
  without inventing a second evidence concept.

## Alternatives Considered

- **Build native packet capture from scratch** — rejected: duplicates
  mature, widely-deployed engineering (Suricata/Zeek/libpcap-class
  tooling) that offers no differentiation opportunity; RedForge's real
  value-add is everything downstream of capture (detection, behavior,
  correlation, evidence, response).
- **BYO-sensor only, defer managed sensor indefinitely** — rejected as
  the sole answer: the mission's stated requirement is a turnkey
  dedicated-office deployment, which a BYO-only model cannot satisfy for
  a customer with no existing telemetry tooling. BYO remains supported,
  but is not suffient alone.
- **Build the managed sensor as a wrapper with no RedForge-owned
  lifecycle layer** (just ship Suricata pre-configured) — rejected:
  without registration/config/health/upgrade management, it isn't
  actually turnkey or centrally operable at fleet scale; the
  RedForge-owned layer is what makes it a product rather than a
  packaging exercise.
