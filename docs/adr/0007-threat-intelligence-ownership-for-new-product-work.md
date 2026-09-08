# ADR-0007: Threat Intelligence Ownership for New Product Work (M51 Native Suite vs. Legacy)

## Status

Accepted

## Date

2026-09-08

## Context

Two generations of Threat Intelligence coexist in the repository:

**Legacy**: `redforge.domain.threat_intel` — providers
(AbuseIPDB, AlienVault OTX, Spamhaus DROP, abuse.ch, etc. under
`infrastructure/threat_intel/providers/`), enrichment, and
`application/threat_intel/correlation_service.py` (`IocCorrelationService`).
This is real, working code, consumed today by the legacy IOC/enrichment
API routes and (on-demand only, not auto-triggered) available for
correlation.

**M51 Native Threat Intelligence suite** — nine bounded contexts built
to a consistent Clean Architecture shape, generalizing a single
tenant/global-scoped reference-data pattern (ADR-M51.1-02) across
observable-indicator and structured-intelligence entities:
`ioc_intelligence`, `threat_actor_intel`, `attack_pattern_intel`,
`malware_intel`, `campaign_intel`, `tool_intel`, `infrastructure_intel`,
`threat_report_intel`, `intelligence_relationships`. `ioc_intelligence`
specifically has been carried through a full production-certification
pass (server-side query/filter/sort/pagination, a formalized
evidence-citation policy, an in-process TTL-expiry scheduler, and
scale/E2E verification — see `docs/RUNBOOK_IOC_INTELLIGENCE.md`) and is
the most architecturally mature of the nine.

Network Defense Edition's target scope includes "Network Threat
Intelligence" as a named capability. Building it against both
generations simultaneously would mean maintaining two independent IOC/
threat-actor/campaign data models and two independent correlation code
paths for the same product surface — a maintenance and consistency
liability with no product benefit.

## Decision

**The M51 Native Threat Intelligence suite is canonical for all NEW
Network Defense Edition product work.** Any new screen, correlation
path, or evidence-citation flow this initiative builds must be
implemented against `ioc_intelligence` / `threat_actor_intel` /
`attack_pattern_intel` / `malware_intel` / `campaign_intel` /
`tool_intel` / `infrastructure_intel` / `threat_report_intel` /
`intelligence_relationships` — not the legacy model.

**Legacy `redforge.domain.threat_intel` may continue to exist and be
used only as an existing provider/enrichment/compatibility source**
where already required (e.g., its `IocCorrelationService`/provider
adapters feeding data into the newer suite, or existing legacy API
routes that are out of this initiative's scope to migrate). **No new
product ownership is to be introduced into the legacy model** — no new
legacy tables, no new legacy application services, no new legacy API
routes, for Network Defense Edition or otherwise, starting now.

This does not retire or migrate the legacy model in this phase — that
would be a separate, larger migration effort outside Phase 0/1 scope.

## Consequences

- Network Defense Edition's "Network Threat Intelligence" screens have
  one unambiguous backend to build against, already the more mature of
  the two per the `ioc_intelligence` certification precedent.
- Legacy `threat_intel` providers remain a valid *data source* — the M51
  suite's own ingestion/correlation paths may continue to consume
  AbuseIPDB/OTX/Spamhaus/abuse.ch data through the legacy provider
  adapters where that plumbing already exists, without that counting as
  "new product ownership in the legacy model."
- A future decision to fully retire the legacy model (or formally
  migrate its remaining consumers to M51) is deferred and should be a
  separate ADR when undertaken.
- Anyone tempted to add a new capability to `redforge.domain.threat_intel`
  for Network Defense Edition should treat that as a signal to build in
  the M51 suite instead, or to raise a new ADR if a genuine reason
  exists to deviate.

## Alternatives Considered

- **Build new product work against the legacy model** — rejected: it
  predates the more disciplined M51 architecture and is not where recent
  investment (including the `ioc_intelligence` production-certification
  pass) has gone.
- **Require full legacy-to-M51 migration before Network Defense Edition
  work begins** — rejected: unnecessarily blocks product work on an
  unrelated, larger migration effort; the two can coexist as long as new
  product ownership only accrues to M51.
- **Build against both, keep them in sync** — rejected: doubles
  correlation/query logic for the same conceptual data with no product
  benefit, and risks the two silently drifting into inconsistent
  answers for the same IOC/indicator.
