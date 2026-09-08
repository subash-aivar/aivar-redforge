"""threat_actor_intel — Threat Actor Intelligence bounded context (M51A).

Domain layer only in this milestone (application/infrastructure/api
land in M51B-D per docs/architecture/m51/M51_REDESIGN_ROADMAP.md).
Owns `ThreatActor` — the one confirmed genuine capability gap
identified by the M51A repository study/ADR
(docs/architecture/m51/M51A_ADR.md) and independently re-verified at
this milestone's start. Deliberately does not model Feed, Indicator,
STIX, TAXII, ATT&CK, DetectionRule, Campaign, MalwareFamily,
ThreatReport, Sigma, or YARA — all already owned elsewhere or
explicitly deferred; see M51A_ADR.md and the roadmap for the full
ownership matrix.

Chosen as a new peer bounded context rather than living inside
`redforge.domain.threat_intel` — see
docs/architecture/m51/M51A_BOUNDED_CONTEXT_DECISION.md for the full
repository-evidence-based rationale (identifier-convention mismatch,
structural-convention mismatch, no cross-context reuse precedent,
ThreatActor's uniformly-tenant-scoped shape).
"""

from __future__ import annotations
