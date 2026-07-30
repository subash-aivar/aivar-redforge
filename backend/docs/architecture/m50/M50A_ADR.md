# M50A ADR — Vulnerability Management vs. Existing `vulnerability` / `vulnerability_engine` Contexts

Status: **BLOCKED — escalated to human reviewer, no domain code written for M50A**
Date: 2026-07-30

## Trigger

Per the M50A task brief, before implementing a new `src/vulnerability_management/`
bounded context, the repository was checked for the existing `vulnerability` and
`vulnerability_engine` packages referenced in earlier M48/M49 milestone notes as
"mature contexts to mirror." Both exist and are fully built out (domain +
application + infrastructure + API layers, with `__pycache__` artifacts confirming
they have been imported/exercised, not just scaffolded).

## What already exists

### `src/vulnerability/domain/` (the larger, more mature of the two)

- **Aggregates**: `Vulnerability` (canonical CVE/CVSS/EPSS/KEV vulnerability
  definition, lifecycle DISCOVERED→ENRICHED→ACTIVE→DEPRECATED, tenant-scoped),
  `VulnerabilityInstance` (per-asset/per-scope occurrence of a `Vulnerability` —
  i.e. the "assessed against an affected asset" record), `VulnerabilityEvidence`,
  `VulnerabilityException` (risk-acceptance equivalent), `RemediationPlan`,
  `VulnerabilitySource`.
- **Entities**: `AffectedVersionRange`, `ExploitRecord`, `FixedVersion`,
  `InstanceScanResult`, `RemediationActivity`, `RemediationTask`,
  `RemediationVerification`, `VulnerabilityReference`.
- **Value objects**: `CvssV3Score`/`CvssV4Score`/`EpssScore` (`scores.py`),
  `VulnerabilitySeverity`/`ExploitMaturity`/`VulnerabilityLifecycleState`
  (`enums.py`), `VulnerabilityFingerprint`/`VulnerabilityKey` (`keys.py`),
  identifiers, references, component/SBOM metadata, lifecycle VOs.
- **Domain events**: full lifecycle event set across
  `vulnerability_events.py`, `instance_events.py`, `evidence_events.py`,
  `exception_events.py`, `remediation_events.py`, `source_events.py`.
- **Prioritization**: a dedicated `domain/prioritization/` package —
  `engine.py`, `policies.py`, `signals.py`, `composer.py` — i.e. exactly the
  "risk prioritization policy using CVSS + exploitability + asset criticality"
  M50A calls for.
- Plus repository interfaces, ports, provider adapters, and full
  application/infrastructure/API layers already wired on top of this domain.

### `src/vulnerability_engine/domain/`

- **Aggregates**: `VulnerabilityDefinition` (declarative CVE/CVSS/EPSS/KEV
  metadata record — explicitly documented in its own docstring as "the
  canonical... vulnerability intelligence record"), `AssetVulnerability`
  (per-asset correlation with its own open→resolved→reopened lifecycle,
  suppression, and remediation-tracking metadata — again, exactly the
  "per-asset assessment" concept M50A's `VulnerabilityAssessment` aggregate
  is meant to cover), plus `ScanJob`, `ScanPolicy`, `ScanProviderRegistration`,
  `ScanTarget`, `VulnerabilityAsset`.
- **Value objects**: `cve.py`, `cvss.py`, `epss.py`, `kev.py`, identifiers,
  network, scan window, vendor/product, version reference.

## Assessment

M50A's spec asks for:

- `Vulnerability` aggregate with CVSS/CVE/CWE/severity value objects →
  **already exists** as `vulnerability.domain.aggregates.Vulnerability` (and
  duplicated again as `vulnerability_engine.domain.aggregates.VulnerabilityDefinition`).
- `VulnerabilityAssessment` as a per-asset assessment record with its own
  lifecycle/SLA/verification state → **already exists** as
  `vulnerability.domain.aggregates.VulnerabilityInstance` (with
  `RemediationPlan`/`RemediationTask`/`RemediationVerification` covering
  SLA/patch/verification tracking) and, independently, as
  `vulnerability_engine.domain.aggregates.AssetVulnerability`.
- `Evidence`, `PatchRecommendation`, `VulnerabilityReference` entities →
  **already exist** near-verbatim (`VulnerabilityEvidence`,
  `RemediationTask`/`RemediationPlan`, `VulnerabilityReference`).
- Risk-acceptance concept → **already exists** as `VulnerabilityException`.
- Risk-prioritization policy (CVSS + exploitability + asset criticality) →
  **already exists** as `vulnerability.domain.prioritization`.

This is not a superficial name collision. It is the same aggregate
responsibility, the same lifecycle shape, and largely the same value-object
vocabulary (CVSS/CVE/EPSS/KEV/severity) that M50A specifies — implemented
twice already, in two overlapping packages, with full application/
infrastructure/API layers on top. Building a third, `vulnerability_management`,
domain-only package that models `Vulnerability` + `VulnerabilityAssessment`
with CVSS/CVE/severity/exploitability value objects would duplicate live,
already-integrated aggregate logic, not create a genuinely distinct bounded
context referencing the others only by opaque ID (the pattern
`attack_surface_management`/`risk_engine` follow toward each other).

There is also an unresolved question the ADR cannot answer unilaterally:
`vulnerability` and `vulnerability_engine` themselves already overlap
substantially with each other (two separate `Vulnerability`-shaped
aggregates, two separate CVSS/CVE value-object sets, two separate per-asset
correlation aggregates). Whether that pre-existing duplication is intentional
(e.g. a deliberate migration from `vulnerability_engine` to `vulnerability`,
or two provider-specific verticals) is not discoverable from the domain code
alone and is out of scope for this ADR to resolve — but it strengthens the
case against adding a third overlapping implementation without human
clarification.

## Decision

**STOP. Do not implement `src/vulnerability_management/` as specified.**

Per the task's own escalation rule, this is flagged as an architecture
conflict requiring human clarification rather than either:
(a) silently duplicating `Vulnerability`/`VulnerabilityInstance`/
`AssetVulnerability`'s responsibility under a new package name, or
(b) silently merging M50A's scope into the existing `vulnerability` or
`vulnerability_engine` packages (which would violate "implement only what
was scoped" and the existing packages' own frozen-milestone status, which is
unknown/unverified from here).

## Options for the human reviewer

1. **Cancel/redefine M50A.** Treat vulnerability lifecycle/assessment/
   remediation management as already delivered by `src/vulnerability`
   (the more complete of the two). If gaps remain (e.g. explicit
   `RiskAcceptance`/`DetectionMethod`/`PatchWindow` value objects, or a
   distinct SLA policy), scope a follow-up milestone that *extends*
   `src/vulnerability` rather than forking a new context.
2. **Consolidate first.** If `vulnerability` and `vulnerability_engine` are
   themselves meant to be reconciled (one superseding the other), that
   consolidation should happen before any new vulnerability-domain work is
   added, to avoid a third divergent model.
3. **Confirm a genuinely distinct scope for `vulnerability_management`.** If
   the actual intent is something narrower and non-overlapping — e.g.
   cross-vulnerability remediation *campaign/workflow orchestration* that
   references `vulnerability`/`vulnerability_engine` records only by opaque
   ID (comparable to how `attack_surface_management` and `risk_engine`
   reference each other) — restate M50A's scope to explicitly exclude
   `Vulnerability`/CVSS/CVE/severity/assessment-lifecycle modeling (since
   that already exists) and instead define the new aggregate boundary in
   terms of what is NOT already covered above.

No code, tests, or files under `src/vulnerability_management/` were created.
This ADR is the only artifact produced for M50A pending reviewer decision.
