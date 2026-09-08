# M51A ADR — Threat Intelligence Domain: Existing Ownership Conflict

## Status
BLOCKED — repository study performed per the M51A task specification's
"First — Repository Study" requirement, before any code was written.
Per that same specification's explicit rule ("If ownership already
exists: STOP. Produce an ADR. Do NOT duplicate."), this ADR is the
required output. No `src/threat_intelligence/` domain code has been
created.

## Method
Read-only audit: `ls src/`, then targeted `grep`/`Read` across the
repository for every concept M51A named (threat intelligence, IOC,
indicators, STIX, TAXII, feeds, malware, campaigns, threat actors,
ATT&CK, Sigma, YARA, intelligence, detection, knowledge graph), then
direct inspection of every hit's actual class/module content — not
name-matching alone, per the same discipline used in the M50 audit.

## Finding: five of M51A's seven candidate aggregates are already owned

| M51A candidate | Existing owner | Evidence |
|---|---|---|
| **Indicator** | `redforge.domain.threat_intel.fusion_entity.FusedIndicator` | A full aggregate/entity: canonical indicator keying (`CanonicalIndicatorKey`), lifecycle (`IndicatorLifecycle` — `fusion_value_objects.py:55`), fusion confidence scoring (`FusionConfidence`), multi-source attribution (`SourceAttribution`), aggregated risk (`AggregatedRisk`), temporal validity windows. This is not reference data — it is the exact "Indicator" concept M51A names. |
| **IntelligenceFeed** | `redforge.domain.threat_intel.feed_entity.Feed` | A `Feed` aggregate with its own repository (`feed_repository.py`), events (`feed_events.py`), exceptions (`feed_exceptions.py`), sync-run tracking (`feed_sync_run_entity.py`), and an application-layer sync worker (`redforge.application.threat_intel.feed_sync_worker`) already wired into `redforge.app`'s startup. |
| **STIX/TAXII** | `redforge.domain.threat_intel.stix_objects.py` / `stix_parser.py` / `stix_value_objects.py`, plus `redforge.application.threat_intel.stix_taxii_connector.py` / `stix_reference_data_mapper.py` | `StixAttackPattern`, `StixTactic`, `StixRelationship`, `StixVulnerability`, `StixKillChainPhase`, `StixExternalReference` are already modeled, with a working TAXII connector and STIX-bundle parser. |
| **ATT&CK (technique/tactic)** | `redforge.domain.threat_intel.attack_technique_entity.py` (`AttackTactic`, `AttackTechnique`, `AttackTechniqueRelationship`) | Explicitly documented as "M22 Phase 1" reference entities globally seeded from the public MITRE ATT&CK STIX bundle. Also independently referenced by `detection.domain.entities.rule_entities.MitreAttackMapping`, meaning `detection` already maps its own rules to this same ATT&CK taxonomy — a second consumer of the same canonical technique/tactic data, reinforcing that this is settled, shared reference data, not something to re-model. |
| **DetectionRule** | **Duplicated already**: `detection.domain.aggregates.detection_rule.DetectionRule` *and* `siem_detection.domain.aggregates.detection_rule.DetectionRule` | Two independent `DetectionRule` aggregates already exist in two different bounded contexts (`detection` — versioned detection logic artifact with `RuleVersion`/`RuleTestCase`/`MitreAttackMapping`; `siem_detection` — "a versioned rule definition," M37 §2.2, explicitly scoped to definition-only with execution deferred to `siem_correlation`). A third `DetectionRule` under a new `threat_intelligence` context would be a **third** parallel model of the same concept — precisely the class of accidental duplication the M50 series (`vulnerability` vs `vulnerability_engine`) was created specifically to eliminate, not repeat. |

## Findings that are NOT conflicts (checked and ruled out)

- **Campaign**: `campaign.domain.aggregates.campaign.Campaign` (red-team offensive campaign orchestration, M30) and `redforge.domain.campaigns.entity.Campaign` (platform validation-run campaign coordination) both exist, but neither models a *threat-intelligence* campaign (a real-world adversary operation, e.g. "APT29's SolarWinds campaign," tracked for intelligence purposes). These are a same-name, different-meaning collision across unrelated bounded contexts — normal and acceptable under DDD's ubiquitous-language-is-context-scoped principle, not evidence of ownership over a threat-intel "Campaign" concept. No conflict.
- **ThreatActor**: no aggregate exists anywhere in the repository. `exposure.domain.ports.i_threat_intelligence_query_port.py` only defines an ACL port (`IThreatIntelligenceQueryPort`) and a read-only `ThreatActorMatch` value object (an opaque `threat_actor_ref: str`, never a rich `ThreatActor` object) — its own docstring calls this "M21 threat intelligence (Phase 3 hybrid model)," implying a threat-actor data source was expected to exist, but no concrete owning aggregate for `ThreatActor` was found anywhere in the current tree. This is the one candidate with a genuine ownership gap.
- **MalwareFamily**, **ThreatReport**: no aggregate, entity, or reference-data model found anywhere in the repository under any name. Genuine gaps.
- **Sigma / YARA**: no modeling found anywhere (only free-text mentions in unrelated docstrings). Genuine gap, though likely out of scope for a domain-layer-only milestone regardless.
- **Knowledge graph**: an existing `KnowledgeGraph`/`KGProjection` infrastructure exists at the platform level (`redforge.application.platform.projections.kg_projection`), consumed by multiple bounded contexts as a projection target, not a domain concept to be owned by a new context.

## Why this blocks M51A as scoped

M51A's own instructions are explicit and leave no discretion: *"Verify whether any existing bounded context already owns any of these concepts. If ownership already exists: STOP. Produce an ADR. Do NOT duplicate."* Five of the seven named candidate aggregates (`Indicator`, `IntelligenceFeed`, and the STIX/TAXII and ATT&CK vocabulary that would underpin `ThreatReport`/`Campaign` if built, plus `DetectionRule` which is already duplicated once) are already owned, several by rich, actively-wired aggregates with real invariants, events, and application-layer consumers — not stubs or scaffolding. Proceeding to design and implement a parallel `threat_intelligence` bounded context as specified would repeat the exact duplication pattern the M50 consolidation effort was created to eliminate, this time across up to three parallel models for some concepts (e.g. a third `DetectionRule`).

## Recommendation

Do not implement M51A as originally scoped. Two narrower, legitimate paths remain open and do not require duplicating existing ownership:

1. **`ThreatActor` and `MalwareFamily`/`ThreatReport` as a genuinely new, narrow bounded context.** These three concepts have no existing owner anywhere in the repository. A redefined M51A could scope itself to *only* these — referencing `redforge.domain.threat_intel`'s `Feed`/`FusedIndicator`/ATT&CK entities and `detection`'s `DetectionRule` only via opaque ID/reference value objects (the same discipline `attack_surface_management`/`risk_engine` use toward other contexts), never re-modeling them.
2. **Consolidation, not new construction, for the conflicting concepts.** If a genuine business need exists to unify `detection`'s and `siem_detection`'s two `DetectionRule` aggregates, or to extend `redforge.domain.threat_intel`'s existing `FusedIndicator`/`Feed`/STIX modeling, that is architecturally a consolidation milestone in the shape of the M50 series (audit → roadmap → phased migration), not a greenfield "M51A domain architecture" milestone.

## Quality gates
Not run — no code was written this milestone (domain-layer-only scope, and the STOP condition triggered before implementation began).

## Conclusion

**M51A REQUIRES CHANGES** — architecture conflict found; ADR generated per specification; implementation did not proceed. Awaiting a decision on which recommendation path (or a different resolution) to take before any `threat_intelligence` domain code is written.
