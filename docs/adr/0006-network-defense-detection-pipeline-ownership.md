# ADR-0006: Network Defense Detection/Alerting Pipeline Ownership (Family A vs. siem_*)

## Status

Accepted

## Date

2026-09-08

## Context

A repository-first audit (Network Defense Edition Phase 0) found two
bounded-context families that each implement a detection → alerting →
investigation pipeline shape, with no code-level connection between them:

**Family A** — `redforge.application`/`redforge.domain` network-adjacent
contexts:
- `telemetry` (ingestion of customer-supplied Suricata EVE JSON / Zeek
  JSON, `application/telemetry/ingestion_service.py`)
- `ddos` (`domain/ddos/detection.py`, `application/ddos/detection_worker.py`)
- `behavior` (`domain/behavior/detection.py` — UEBA-shaped network/IP
  anomaly detection, not user/host behavior)
- `network_security` (`application/network_security` — authorized active
  scanning + drift detection, M16)
- Live alerting via `api/v1/security_operations.py`'s SSE stream
  (`stream_service.py`), which already multiplexes DDoS + behavior +
  investigation events
- `redforge.domain.investigations` (M21/M22) — real correlation adapters
  (`application/investigations/source_adapters.py`:
  `adapt_ddos_incident`, `adapt_behavior_detection`,
  `adapt_threat_intel_enrichment`) and a background correlation worker

**Family B** — the `siem_*` context family: `siem_ingestion` →
`siem_normalization` → `siem_detection` → `siem_correlation` →
`siem_alerting` → `siem_investigation` → `siem_storage`/`siem_search`/
`siem_analytics`.

Verified: zero imports of `siem_alerting` (or any `siem_*` package) exist
anywhere under `application/behavior`, `application/ddos`, or
`application/network_security`. These are two independent pipelines,
not a shared one with an adapter layer.

Two other systems compound this: `incident` (M34, NIST-style IR
lifecycle) is not fed by DDoS/behavior findings either, and there are two
generations of Threat Intelligence (legacy `redforge.domain.threat_intel`
providers/correlation, and the new M51 native suite — see ADR-0007).

Network Defense Edition needs one unambiguous "this is where a network
finding becomes an alert becomes an investigation" answer before any
product screen is built against it.

## Decision

**Family A is the canonical, current operational network-defense
detection/alerting/investigation pipeline for Network Defense Edition
product work.** It is the family actually wired end-to-end today: real
telemetry ingestion → real DDoS/behavior detection → a real live SSE
alert feed → a real investigation-correlation worker consuming both.

Concretely, for any new Network Defense Edition screen or capability:
- Detections/findings are produced by `ddos`, `behavior`, or
  `network_security`.
- Live alerts are read from the `security_operations` SSE stream, not
  `siem_alerting`.
- Investigation cases are read from `redforge.domain.investigations`
  (via its existing correlation worker/adapters), not `incident` (M34)
  or `siem_investigation`.

`siem_*` is **not** deleted, not deprecated, and not built upon for
Network Defense Edition in this phase. It continues to exist and evolve
independently. No third detection/alerting/investigation pipeline is to
be created to reconcile the two — if unification ever happens, it
happens *to* one of these two families, not as a new third one.

**Convergence of `siem_*` and Family A is explicitly deferred** as a
future architecture-hardening initiative (tracked here as an M52-M55-era
concern, exact milestone TBD at that time) — out of scope for Network
Defense Edition Phase 0/1.

## Consequences

- Network Defense Edition can start building product screens immediately
  against a pipeline that is real, tested, and already end-to-end wired
  — no new plumbing required to reach "ingestion → detection → alert →
  investigation."
- `siem_*` continues unmaintained-by-this-initiative in the interim;
  teams working on `siem_*` should be aware Network Defense Edition will
  not consume or extend it for now, to avoid surprise expectations.
- The eventual convergence work (if pursued) is now a named, tracked
  decision rather than an implicit unresolved fork — this ADR is the
  place to record that decision when it happens (supersede this ADR, or
  add a follow-up ADR that references it).
- Any engineer building a Network Defense Edition alert/investigation
  screen should treat "wire it to `siem_alerting` instead" as
  **explicitly rejected** for this phase, not an oversight to silently
  fix.

## Alternatives Considered

- **Build Network Defense Edition on `siem_*` instead** — rejected: it is
  not currently fed by DDoS/behavior/network_security findings at all;
  choosing it would mean building the missing adapter layer from scratch
  before any product work could start, with no corresponding gain over
  Family A's already-working pipeline.
- **Build a third, unifying pipeline now** — rejected: doubles the
  maintenance surface immediately and pre-empts a convergence decision
  that deserves its own dedicated design effort, not one made
  incidentally while building a product edition.
- **Wire both families into every Network Defense Edition screen** —
  rejected: doubles engineering cost for this phase with no clear
  product benefit; a single canonical source is simpler to reason about
  and matches what already works.
