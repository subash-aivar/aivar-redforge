# M6–M8 Enterprise Exposure Foundation — Combined Checkpoint

**Date**: 2026-07-11

## Reconnaissance decision

A targeted reconnaissance sweep (network/cloud/vulnerability concepts) confirmed the repository had essentially nothing to reuse for M6/M7/M8 beyond the identity/ontology/connector scaffolding already built in M1-M5: no scanning libraries, no cloud SDKs, no CVE/CWE/vulnerability modeling anywhere except an unrelated `CvssMetadata` in the Attack Library context. This meant all three milestones required building real, working new architecture rather than wiring up dormant code — a materially larger scope per milestone than M4/M5 (which extended already-partially-built foundations).

## M6 — Network, Device & Service Discovery Foundation

**Status: COMPLETE.**

Reused the canonical `AIAsset` aggregate for `NETWORK`/`DEVICE`/`SERVICE` (joining M3's `HOST`/`IP_ADDRESS`) — no disconnected inventory, **no new migration needed**. Built 3 new deterministic identity schemes, a generalized race-safe asset/relationship resolution service, a real bounded read-only TCP-connect discovery adapter (no shell execution, server-enforced scope policy), Security Graph ontology v3, deterministic exposure analysis, and full live acceptance against real loopback sockets and real PostgreSQL. Full detail: [M6_NETWORK_DEVICE_SERVICE_DISCOVERY_REPORT.md](M6_NETWORK_DEVICE_SERVICE_DISCOVERY_REPORT.md).

**M6 checkpoint gate: CLEAN.** No unresolved P0. Remaining P1s (deferred `UNENCRYPTED_SERVICE_OBSERVED` rule, no dedicated network browsing page, browser acceptance unproven, IPv6 scan not live-tested) do not block M7.

## M7 — Multi-Cloud Security Foundation

**Status: NOT STARTED this session.**

## M8 — Vulnerability & Exposure Management Foundation

**Status: NOT STARTED this session.**

## Honest reason M7/M8 were not attempted this session

M7 (provider-neutral cloud architecture + a real AWS/Azure/GCP adapter + cloud-specific credential/TLS review + ontology v4 + cloud exposure rules + APIs + frontend) and M8 (a full vulnerability/exposure-management bounded context with an OBSERVED/INFERRED/VALIDATED state model + stable dedup identity + CVSS validation + an ingestion port + evidence architecture with size/content limits + ontology v5 + APIs + frontend) are each comparable in scope to the M6 work just completed — which itself required building an entire bounded context, a real adapter with its own safety-boundary tests, an ontology bump, and a full live-acceptance cycle from zero pre-existing code. Compressing either into the remainder of this session would force exactly the outcome the milestone's own instructions forbid: "Do not reduce architecture quality merely to reach M8" and "If the session cannot honestly finish all three, complete the furthest dependency-safe milestone and return an exact continuation checkpoint." This is that checkpoint.

## Exact continuation state for the next session

- Migration head: **0015** (unchanged by M6 — no new migration).
- Backend tests: **3,557 passed, 5 skipped** (ruff clean, strict mypy clean).
- Frontend: tsc/build/vitest clean, 23 routes, npm advisory unchanged (2 moderate, pre-existing).
- Security Graph ontology version: **3** (`NETWORK`/`DEVICE`/`SERVICE`/`CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK` added this session).
- Network live acceptance: PROVEN (real loopback TCP discovery, 15/15 live steps).
- Cloud live acceptance: N/A — M7 not started.
- Exposure ingestion proof: N/A — M8 not started.
- Tenant isolation proof: PROVEN for M6 (7 adversarial tests + live cross-tenant denial).
- Secret sentinel proof: N/A for M6 (no credentials involved in bounded TCP-connect discovery); will be required for M7's cloud credential-reference architecture.
- Unresolved P0: **none**.
- Unresolved P1: see M6 report §24 — none block M7.
- **Exact recommended next milestone: M7 — Multi-Cloud Security Foundation**, starting from repository reconnaissance of the M6-established patterns (`resolve_asset`/`add_relationship_for_org` generalization, ontology-extension discipline, connector-type branching in `TenantConnectorService`) which M7's cloud connector should follow directly, plus a fresh check for any installed cloud SDK (none were present as of this session — `boto3`/`azure-*`/`google-cloud-*` would need to be added and the M7 report must honestly mark provider live proof BLOCKED unless real cloud credentials are available in the execution environment).
