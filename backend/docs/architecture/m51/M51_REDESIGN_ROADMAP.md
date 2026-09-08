# M51 Redesign Roadmap — Threat Intelligence Platform

## Status
PLANNING ONLY. No source code was created, modified, or deleted to
produce this document. Every claim below was re-derived from the
repository directly in this session — `git`/`grep`/`Read`, not carried
over from `M51A_ADR.md`'s prior findings (though every prior finding
independently re-confirmed).

---

## 1. Ownership matrix

| Concept | Owning bounded context | Aggregate/entity/VO | Maturity | Runtime integration | DB ownership | API ownership |
|---|---|---|---|---|---|---|
| **Feed** | `redforge.domain.threat_intel` | `Feed` (`feed_entity.py`) + `FeedSyncRun` | **Mature** | `feed_sync_worker` registered at app startup; consumed by `attack_path`, `investigations` | `feed_sync` table, migration `0036_feed_sync_foundation.py`, repo `feed_sync_repository.py` | `api/v1/feed_sync.py` (mounted) |
| **FusedIndicator** | `redforge.domain.threat_intel` | `FusedIndicator`, `FusedRelationship` (`fusion_entity.py`) | **Mature** | `threat_fusion_service`/`threat_fusion_query_service`; consumed by `attack_path`, `investigations` | `threat_fusion` tables, migration `0037_threat_fusion.py`, repo `threat_fusion_repository.py` | `api/v1/threat_fusion.py` (mounted) |
| **STIX (objects/parser)** | `redforge.domain.threat_intel` | `StixAttackPattern`, `StixTactic`, `StixRelationship`, `StixVulnerability`, etc. (`stix_objects.py`) | **Mature** | `stix_parser.py` feeds ingestion; `stix_reference_data_mapper.py` | Backs the same reference-data tables as ATT&CK below | `api/v1/threat_intel_reference_data.py` (mounted) |
| **TAXII** | `redforge.domain.threat_intel` (app: `redforge.application.threat_intel`) | `stix_taxii_connector.py` | **Mature** | Real client at `redforge.infrastructure.threat_intel.taxii_client.py` | N/A (transport layer) | Indirect, via feed sync endpoints |
| **ATT&CK (technique/tactic)** | `redforge.domain.threat_intel` | `AttackTactic`, `AttackTechnique`, `AttackTechniqueRelationship` (`attack_technique_entity.py`, M22) | **Mature** | Independently consumed by `detection.domain.entities.rule_entities.MitreAttackMapping` — a second bounded context already maps into this canonical taxonomy | Reference-data tables (globally seeded, no `organization_id`) | `api/v1/threat_intel_reference_data.py` (mounted) |
| **DetectionRule** | **Canonical: `detection`.** Duplicate: `siem_detection` | `detection.domain.aggregates.detection_rule.DetectionRule` (canonical) vs. `siem_detection.domain.aggregates.detection_rule.DetectionRule` (duplicate) | Canonical: **mature**. Duplicate: **domain+application only, unwired** | Canonical: `DetectionContainer` registered at startup (`app.py:180,712`), exception handlers mounted (`app.py:1338`). Duplicate: **zero** hits for `siem_detection` in `app.py` | Canonical: migration `0058_detection_rule_foundation.py`, repo `pg_detection_rule_repository.py`. Duplicate: **`src/siem_detection/infrastructure/` and `src/siem_detection/api/` contain only empty `__init__.py` files — no repository, no migration, no route** | Canonical: mounted. Duplicate: none |
| **ThreatActor** | **None** | Only `ThreatActorMatch`/`ThreatActorMatchResult` (opaque value objects) behind `exposure.domain.ports.i_threat_intelligence_query_port.IThreatIntelligenceQueryPort` | **Gap** — the one concrete adapter, `exposure.infrastructure.acl.threat_intelligence_m21_adapter.ThreatIntelligenceM21Adapter`, is explicitly documented `"M21 threat intelligence ACL adapter — seedable until live M21 wiring"` and `"in-process seedable adapter (ops injects live M21 client in production)"` — i.e. no live `ThreatActor` source exists anywhere; the port is a prepared extension seam, unfulfilled | N/A | N/A | N/A |
| **Campaign** (threat-intel meaning: a tracked real-world adversary operation) | **None** — `campaign` (red-team orchestration, M30) and `redforge.domain.campaigns` (validation-run coordination) both exist but model an unrelated concept sharing only the English word "campaign" | — | **Gap** (same-name/different-meaning collision, not ownership; confirmed by reading both aggregates' docstrings) | N/A | N/A | N/A |
| **MalwareFamily** | **None** | — | **Gap** — zero hits repository-wide | N/A | N/A | N/A |
| **ThreatReport** | **None** | — | **Gap** — zero hits repository-wide | N/A | N/A | N/A |
| **Sigma** | **None** | — | **Gap** — zero hits repository-wide | N/A | N/A | N/A |
| **YARA** | **None** | — | **Gap** — zero hits repository-wide | N/A | N/A | N/A |

---

## 2. Dependency graph

```
redforge.domain.threat_intel / redforge.application.threat_intel
                │
                │  (imported by, confirmed via grep)
                ├── redforge.api.v1  (threat_intel.py, threat_intel_reference_data.py,
                │                     threat_fusion.py, feed_sync.py — all mounted)
                ├── redforge.application.attack_path
                ├── redforge.domain.attack_path
                ├── redforge.application.investigations
                ├── redforge.application.platform  (KG projection consumer)
                └── redforge.infrastructure.database.repositories

detection.domain.aggregates.DetectionRule
                │
                └── (independently) consumes redforge.domain.threat_intel's
                    ATT&CK technique/tactic taxonomy via MitreAttackMapping

siem_detection.domain.aggregates.DetectionRule   ── zero external consumers
                                                      (unwired, matches the
                                                      vulnerability_engine
                                                      pattern from M50)

exposure.domain.ports.IThreatIntelligenceQueryPort
                │
                └── exposure.infrastructure.acl.ThreatIntelligenceM21Adapter
                    (seedable stub — the one open extension seam for a
                    real ThreatActor source)
```

`redforge.domain.threat_intel` is a **platform-core** capability — depended on by attack-path analysis and investigations, not a siloed module. This is materially different from the M50 situation, where `vulnerability_engine` had *zero* external consumers. Any M51 work must integrate with this platform-core context, never fork it.

---

## 3. Gap analysis

Confirmed, independently, via `grep -rln "class ThreatActor\b|class MalwareFamily\b|class ThreatReport\b|class SigmaRule\b|class YaraRule\b"` across all of `src/`: zero matches. Combined with the ACL-port evidence above, four genuine capability gaps exist:

1. **ThreatActor** — has a *prepared* extension seam (`IThreatIntelligenceQueryPort`) already waiting in `exposure`, but no aggregate anywhere provides real data.
2. **MalwareFamily** — no seam, no aggregate. Full gap.
3. **ThreatReport** — no seam, no aggregate. Full gap.
4. **Sigma / YARA** — no seam, no aggregate, and (per the original M51A ADR) likely a `detection`/`siem_detection` concern (rule *content format*) rather than a `threat_intelligence` concern — needs its owning-context question answered explicitly before any milestone touches it (see Open Question below).

Separately, one **duplication requiring consolidation**, not new construction:
5. **DetectionRule**: `siem_detection`'s copy is domain+application only, completely unwired (identical shape to `vulnerability_engine` before the M50 consolidation) — while `detection`'s copy is the canonical, fully-wired implementation.

---

## 4. Revised M51 milestone roadmap

The original single "M51A — Threat Intelligence Domain Architecture" is replaced by two independent tracks. They do not depend on each other and may run in either order.

### Track A — New capability: Threat Actor Intelligence (fills a real gap)

- **M51A (redefined) — Threat Actor Intelligence Domain**
  Scope: domain layer only, for `ThreatActor` and its directly-supporting value objects (attribution confidence, aliases, associated TTPs-by-reference, associated indicators-by-reference). New bounded context: `src/threat_actor_intel/` (name deliberately distinct from `redforge.domain.threat_intel` to avoid ubiquitous-language collision — final naming to be confirmed against repository convention before implementation). Must reference `redforge.domain.threat_intel`'s `AttackTechnique`/`FusedIndicator` and `detection`'s `DetectionRule` only via opaque ID/reference value objects — mirroring the `attack_surface_management`→other-contexts discipline. Must define the concrete adapter contract that will eventually let `exposure.infrastructure.acl.ThreatIntelligenceM21Adapter` be replaced by a real implementation, without modifying `exposure` itself in this milestone.
  Gate: architecture/DDD/tenant-isolation/cross-context review, same discipline as every prior M48–M50 domain milestone.

- **M51B — Threat Actor Intelligence Application Layer**
  Mirrors the `risk_engine`/`attack_surface_management` M*B pattern: commands, queries, DTOs, async ABC ports, application services. No infrastructure, no API, no wiring.

- **M51C — Threat Actor Intelligence Infrastructure**
  SQLAlchemy models, async repositories, UnitOfWork, event publisher, next alembic migration. No API, no DI-container wiring into `redforge.app` yet.

- **M51D — Threat Actor Intelligence API + Wiring**
  Routers, schemas, DI container, `app.py` startup hook, router mount. At this point — and only at this point — `exposure`'s `ThreatIntelligenceM21Adapter` becomes a candidate for replacement with a real adapter calling into this new context; that replacement is itself a separate, explicit milestone (M51E) requiring `exposure`'s own review, not bundled here.

- **M51E — Wire `exposure`'s ACL adapter to the real ThreatActor source**
  Touches `exposure.infrastructure.acl.threat_intelligence_m21_adapter.py` only — replaces the seedable stub with a real client against the new M51D API/service. Scoped separately because it modifies an existing, frozen bounded context (`exposure`) and deserves its own review gate, same discipline as M50E→M50F's separation of "verify" from "delete."

**MalwareFamily** and **ThreatReport** are deferred, not scoped into A–E above: no consuming context currently references either concept (unlike `ThreatActor`, which has `exposure`'s waiting port), so there is no repository evidence yet establishing what shape these aggregates need. Recommend they become their own future milestone(s) only once a concrete consumer requirement is identified — building speculative domain models with no evidenced consumer repeats the exact mistake `vulnerability_engine` made (M46 built rich domain modeling with zero real consumers, sat unwired for 4+ sub-milestones).

**Sigma / YARA**: recommend explicitly punting this to a follow-up scoping question, not a milestone yet — first determine whether it belongs to `detection`/`siem_detection` (rule *content format*, i.e. extending `DetectionRule`) or to the new `threat_actor_intel` context (intelligence *about* what content exists), since the answer changes which track it belongs to. Building it now would risk exactly the kind of premature ownership assumption M51A's original ADR was written to prevent.

### Track B — Consolidation: `siem_detection` → `detection` (mirrors M50 exactly)

- **M51F — DetectionRule Consolidation Audit**
  Read-only. Confirms (independently, at execution time) that `siem_detection`'s `DetectionRule` remains unwired and that no consumer has appeared since this roadmap was written. Produces an ownership/migration-strategy document, same shape as `M50_ARCHITECTURE_AUDIT_ADR.md`.

- **M51G — Port any genuinely unique `siem_detection` capability into `detection`**
  Per M37 §5's own documented boundary ("`siem_detection` owns the rule definition, `siem_correlation` owns execution"), determine whether `siem_detection.DetectionRule` has any field/behavior `detection.DetectionRule` lacks. If so, port only that delta — never duplicate wholesale. If `siem_detection`'s aggregate is a strict subset of `detection`'s (plausible, given `detection`'s already has `RuleVersion`/`RuleTestCase`/`MitreAttackMapping`), this milestone may conclude "nothing to port."

- **M51H — Deprecate `siem_detection`'s domain/application layers**
  Mark deprecated, no deletion, matching M50A's caution.

- **M51I — Final verification gate**
  Read-only, matching M50E exactly — re-prove zero consumers before deletion is authorized.

- **M51J — Delete `siem_detection`'s duplicate `DetectionRule`**
  Matching M50F's scope discipline exactly — the only milestone authorized to delete.

Track B is lower urgency than Track A: it eliminates a duplication risk but doesn't deliver new capability. It may be sequenced after Track A completes, or interleaved — the two tracks touch disjoint files (`threat_actor_intel`/`exposure` vs. `siem_detection`/`detection`) and have no ordering dependency.

---

## 5. Implementation sequencing

```
Track A: M51A → M51B → M51C → M51D → M51E   (sequential — each phase gates the next)
Track B: M51F → M51G → M51H → M51I → M51J   (sequential — mirrors M50 exactly)
```

No cross-track ordering dependency. Recommend Track A first (delivers new capability against a confirmed live gap with a waiting consumer), Track B second (pure risk elimination, no waiting consumer blocked on it).

---

## 6. Architectural risks

- **Ubiquitous-language collision risk**: "Campaign" already means two different things in two contexts (`campaign`, `redforge.domain.campaigns`). A new `threat_actor_intel` context must not introduce a third meaning for any term already claimed elsewhere (`Feed`, `Indicator`, `Campaign` are all taken) — naming must be verified against the full `src/` tree at each new milestone's start, not assumed safe from this document alone (repository state can change between now and execution).
- **Scope creep into `redforge.domain.threat_intel`**: because that context is mature and platform-core, there will be strong temptation to "just add ThreatActor there instead of a new context." That decision needs deliberate architecture review at M51A (redefined) time — this roadmap does not prejudge it, since `redforge.domain.threat_intel` is a platform-level (`redforge.*`) module rather than a peer bounded-context package (`src/<context>/`), and mixing tenant-scoped `ThreatActor` intelligence into it may or may not fit that module's existing conventions. Recommend the redefined M51A's own repository study explicitly resolve this before choosing a package location.
- **Speculative modeling risk**: `MalwareFamily`/`ThreatReport` deferred specifically to avoid repeating `vulnerability_engine`'s core mistake (rich domain model, zero consumers, built anyway).

## 7. Migration risks (Track B only)

- Same profile as M50: `siem_detection`'s `DetectionRule` has zero live consumers and zero persisted data (no migration exists for it), so — pending M51F's fresh confirmation at execution time — deletion risk is expected to be as low as `vulnerability_engine`'s was. Not assumed here; M51F/M51I must independently re-verify before M51J proceeds, exactly as M50E re-verified before M50F.
- If M51G finds `siem_detection`'s aggregate has behavior `detection`'s lacks, the port must preserve `detection`'s existing consumers' contracts (its `DetectionContainer`, its mounted API, its exception handlers) without breaking them — standard consolidation-milestone risk, same as M50's `ScanJob`/`ScanPolicy` port into `vulnerability`.

---

## Conclusion

**M51 REDESIGN APPROVED — READY FOR REDEFINED M51A**
