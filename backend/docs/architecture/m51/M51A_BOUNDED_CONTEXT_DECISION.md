# M51A Bounded Context Decision — ThreatActor Location

## Status
Decided, based on repository evidence gathered fresh in this session.
Not blocking — implementation of the ThreatActor domain proceeds
under this decision within the same M51A milestone.

## Question
Per `M51_REDESIGN_ROADMAP.md` §6 ("Architectural risks"), this was
left as an explicit open question: does `ThreatActor` belong inside
`redforge.domain.threat_intel`, or a new peer bounded context?

## Evidence

1. **Identifier convention mismatch.** `redforge.domain.threat_intel.Feed`
   (and its siblings) use a raw `organization_id: str | None` — nullable,
   because ATT&CK/STIX reference data in the same module is *global*,
   not tenant-scoped (`attack_technique_entity.py`'s own docstring:
   "carry no `organization_id`"). This is a fundamentally different
   identity scheme from the shared-kernel `TenantId = EntityId`
   (ULID-backed, always-present) convention used uniformly by
   `vulnerability`, `risk_engine`, `attack_surface_management`, and
   now `vulnerability`'s `scanning` sub-domain.

2. **Structural convention mismatch.** `redforge.domain.threat_intel`
   is a module directly under the `redforge` platform package
   (`src/redforge/domain/threat_intel/`), not a standalone peer
   bounded-context package (`src/<context>/domain/`) with its own
   `application/`/`infrastructure/`/`api/` siblings, container,
   startup hook, and dedicated test tree — the pattern every M48–M50
   milestone established and mirrored exactly.

3. **No precedent for cross-reuse.** `grep` across `risk_engine`,
   `attack_surface_management`, and `vulnerability` for
   `from redforge.domain.` found zero domain-model reuse — only
   `redforge.api.security`/`Permission` (an auth utility, not a
   domain concept) in API-layer files. No mature peer context treats
   `redforge.domain.threat_intel` as something to build directly on
   top of.

4. **ThreatActor is inherently, uniformly tenant-scoped.** Every
   tenant needs its own view of which threat actors are relevant to
   *their* attack surface — there is no global/reference-data half
   to this concept the way ATT&CK techniques are global MITRE data.
   It does not fit the mixed global/optional-tenant shape
   `redforge.domain.threat_intel` was built around.

## Decision

**ThreatActor is implemented as a new peer bounded context**,
`src/threat_actor_intel/`, structurally identical to
`attack_surface_management`/`risk_engine`: `domain/` this milestone,
with `application/`/`infrastructure/`/`api/` in subsequent M51
milestones per the roadmap. It uses the shared-kernel `TenantId`
(`EntityId`) exactly as those contexts do — never a raw
`organization_id: str`.

It references `redforge.domain.threat_intel`'s `AttackTechnique`/
`FusedIndicator` and `detection`'s `DetectionRule` only via opaque
ID/reference value objects if and when a future milestone needs
that association — never by importing or re-modeling those types,
per the roadmap's explicit instruction and the zero-cross-context-
import discipline established since M48.

## Naming
`threat_actor_intel` was chosen over the roadmap's placeholder
`threat_actor_intel` (confirmed unclaimed via `find src -maxdepth 1
-iname "*threat_actor*"` returning no results) and deliberately
avoids the word "intelligence" standing alone, since
`redforge.domain.threat_intel`/`redforge.application.threat_intel`
already claim that term at the platform level — reusing it bare for
a peer package would create exactly the ubiquitous-language
collision risk the roadmap flagged.
