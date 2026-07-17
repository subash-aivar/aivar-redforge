"""Threat Fusion application service — M22 Phase 4.

Consumes only Phase 1 reference-data catalog rows (populated by Phase 3
STIX/TAXII and/or Phase 1 admin loads). Does not call external providers
and does not re-parse STIX.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redforge.domain.threat_intel.fusion_entity import FusedIndicator, FusedRelationship
from redforge.domain.threat_intel.fusion_exceptions import FusionBatchTooLargeError
from redforge.domain.threat_intel.fusion_policies import (
    DEFAULT_FUSION_WEIGHTS,
    FusionConflictPolicy,
    IndicatorTTLPolicy,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    CanonicalIndicatorKey,
    FusedIndicatorType,
    FusionConfidence,
    FusionWeight,
    SourceAttribution,
    fused_type_for_stix_ref,
)
from redforge.domain.threat_intel.reference_data_value_objects import ReferenceDataSource
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.threat_fusion_repository import (
    SqlAlchemyFusedIndicatorRepository,
    SqlAlchemyFusedRelationshipRepository,
    SqlAlchemyFusionConfigRepository,
)
from redforge.infrastructure.database.repositories.threat_intel_reference_data_repository import (
    SqlAlchemyAttackTacticRepository,
    SqlAlchemyAttackTechniqueRepository,
    SqlAlchemyVulnerabilityRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

_MAX_FUSION_INDICATORS = 20_000
_PAGE = 500


@dataclass(frozen=True, slots=True)
class FusionRunResult:
    indicators_created: int
    indicators_updated: int
    relationships_upserted: int
    stub_indicators_created: int
    no_evidence_count: int


class ThreatFusionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        audit_factory: Callable[[AsyncSession], PostgresPlatformAuditLog] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_factory = audit_factory or (
            lambda session: PostgresPlatformAuditLog(session)
        )

    async def fuse_reference_catalog(self, *, actor_id: str) -> FusionRunResult:
        """Normalize, dedupe, correlate, and enrich the reference catalog
        into fused indicators + relationships."""
        async with self._session_factory() as session, session.begin():
            weight_repo = SqlAlchemyFusionConfigRepository(session)
            overrides = await weight_repo.list_weights()
            weights = [
                FusionWeight(source_system=src, weight=w) for src, w in overrides
            ]
            conflict_policy = FusionConflictPolicy(weights)
            ttl_policy = IndicatorTTLPolicy()

            tactic_repo = SqlAlchemyAttackTacticRepository(session)
            technique_repo = SqlAlchemyAttackTechniqueRepository(session)
            vuln_repo = SqlAlchemyVulnerabilityRepository(session)
            fused_repo = SqlAlchemyFusedIndicatorRepository(session)
            rel_repo = SqlAlchemyFusedRelationshipRepository(session)

            now = datetime.now(UTC)
            created = updated = stubs = no_evidence = 0
            key_to_id: dict[str, str] = {}
            tactic_shortnames: dict[str, str] = {}

            # ── tactics ──────────────────────────────────────────────
            offset = 0
            while True:
                tactics_page = await tactic_repo.list_all(limit=_PAGE, offset=offset)
                if not tactics_page:
                    break
                for tactic in tactics_page:
                    tactic_shortnames[tactic.tactic_id.value] = tactic.shortname
                    key = CanonicalIndicatorKey.for_type(
                        FusedIndicatorType.TACTIC, tactic.tactic_id.value
                    )
                    c, u, n = await self._upsert_catalog_indicator(
                        fused_repo,
                        conflict_policy=conflict_policy,
                        ttl_policy=ttl_policy,
                        key=key,
                        display_name=tactic.name,
                        source_system=ReferenceDataSource.MITRE_ATTACK.value,
                        external_id=tactic.stix_id,
                        confidence=FusionConfidence.MEDIUM,
                        metadata={
                            "shortname": tactic.shortname,
                            "stix_id": tactic.stix_id,
                        },
                        now=now,
                    )
                    created += c
                    updated += u
                    no_evidence += n
                    stored = await fused_repo.get_by_canonical_key(key)
                    if stored:
                        key_to_id[key.value] = stored.id
                offset += _PAGE
                if len(key_to_id) > _MAX_FUSION_INDICATORS:
                    raise FusionBatchTooLargeError(
                        len(key_to_id), _MAX_FUSION_INDICATORS
                    )

            # ── techniques ───────────────────────────────────────────
            offset = 0
            while True:
                techniques_page = await technique_repo.list_all(
                    limit=_PAGE, offset=offset
                )
                if not techniques_page:
                    break
                for technique in techniques_page:
                    key = CanonicalIndicatorKey.for_type(
                        FusedIndicatorType.TECHNIQUE, technique.technique_id.value
                    )
                    kill_chain = None
                    if technique.tactic_ids:
                        kill_chain = tactic_shortnames.get(
                            technique.tactic_ids[0].value
                        )
                    meta: dict[str, Any] = {
                        "stix_id": technique.stix_id,
                        "is_sub_technique": str(technique.is_sub_technique),
                    }
                    if kill_chain:
                        meta["kill_chain_phase"] = kill_chain
                    if technique.tactic_ids:
                        meta["tactic_ids"] = ",".join(
                            t.value for t in technique.tactic_ids
                        )
                    if technique.parent_technique_id:
                        meta["parent_technique_id"] = (
                            technique.parent_technique_id.value
                        )
                    c, u, n = await self._upsert_catalog_indicator(
                        fused_repo,
                        conflict_policy=conflict_policy,
                        ttl_policy=ttl_policy,
                        key=key,
                        display_name=technique.name,
                        source_system=ReferenceDataSource.MITRE_ATTACK.value,
                        external_id=technique.stix_id,
                        confidence=FusionConfidence.MEDIUM,
                        metadata=meta,
                        now=now,
                    )
                    created += c
                    updated += u
                    no_evidence += n
                    stored = await fused_repo.get_by_canonical_key(key)
                    if stored:
                        key_to_id[key.value] = stored.id
                offset += _PAGE

            # ── vulnerabilities ──────────────────────────────────────
            offset = 0
            while True:
                vulns_page = await vuln_repo.list_all(limit=_PAGE, offset=offset)
                if not vulns_page:
                    break
                for vuln in vulns_page:
                    key = CanonicalIndicatorKey.for_type(
                        FusedIndicatorType.VULNERABILITY, vuln.cve_id.value
                    )
                    confidence = (
                        FusionConfidence.HIGH
                        if vuln.is_kev
                        else FusionConfidence.MEDIUM
                    )
                    meta = {
                        "is_kev": str(vuln.is_kev),
                        "cve_id": vuln.cve_id.value,
                    }
                    if vuln.epss is not None:
                        meta["epss_probability"] = str(vuln.epss.probability)
                    c, u, n = await self._upsert_catalog_indicator(
                        fused_repo,
                        conflict_policy=conflict_policy,
                        ttl_policy=ttl_policy,
                        key=key,
                        display_name=vuln.cve_id.value,
                        source_system=ReferenceDataSource.STIX_TAXII_FEED.value,
                        external_id=vuln.cve_id.value,
                        confidence=confidence,
                        metadata=meta,
                        now=now,
                    )
                    created += c
                    updated += u
                    no_evidence += n
                    stored = await fused_repo.get_by_canonical_key(key)
                    if stored:
                        key_to_id[key.value] = stored.id
                offset += _PAGE

            # ── relationships + endpoint stubs ───────────────────────
            relationships_upserted = 0
            offset = 0
            while True:
                rels_page = await technique_repo.list_all_relationships(
                    limit=_PAGE, offset=offset
                )
                if not rels_page:
                    break
                for rel in rels_page:
                    source_id, source_key, stub_c = await self._ensure_endpoint(
                        fused_repo,
                        conflict_policy=conflict_policy,
                        ttl_policy=ttl_policy,
                        stix_ref=rel.source_ref,
                        technique_id=(
                            rel.source_technique_id.value
                            if rel.source_technique_id
                            else None
                        ),
                        key_to_id=key_to_id,
                        now=now,
                    )
                    stubs += stub_c
                    target_id, target_key, stub_c = await self._ensure_endpoint(
                        fused_repo,
                        conflict_policy=conflict_policy,
                        ttl_policy=ttl_policy,
                        stix_ref=rel.target_ref,
                        technique_id=(
                            rel.target_technique_id.value
                            if rel.target_technique_id
                            else None
                        ),
                        key_to_id=key_to_id,
                        now=now,
                    )
                    stubs += stub_c
                    if source_id is None or target_id is None:
                        continue
                    await rel_repo.upsert(
                        FusedRelationship(
                            id=str(EntityId.generate()),
                            relationship_type=rel.relationship_type,
                            source_indicator_id=source_id,
                            target_indicator_id=target_id,
                            source_canonical_key=source_key or "",
                            target_canonical_key=target_key or "",
                            stix_relationship_id=rel.stix_id,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                    relationships_upserted += 1
                offset += _PAGE

            audit = self._audit_factory(session)
            batch_id = str(EntityId.generate())
            await audit.record(
                AuditEntry(
                    action=AuditAction.INDICATOR_FUSED,
                    actor_id=actor_id[:26],
                    resource_type="fused_indicator_catalog",
                    resource_id=batch_id,
                    metadata={
                        "indicators_created": str(created),
                        "indicators_updated": str(updated),
                        "relationships_upserted": str(relationships_upserted),
                        "stub_indicators_created": str(stubs),
                    },
                )
            )

            return FusionRunResult(
                indicators_created=created,
                indicators_updated=updated,
                relationships_upserted=relationships_upserted,
                stub_indicators_created=stubs,
                no_evidence_count=no_evidence,
            )

    async def update_fusion_weight(
        self, *, source_system: str, weight: float, actor_id: str
    ) -> None:
        # Validate via VO
        FusionWeight(source_system=source_system, weight=weight)
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyFusionConfigRepository(session)
            await repo.upsert_weight(
                source_system, weight, actor_id=actor_id[:26]
            )
            audit = self._audit_factory(session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.FUSION_WEIGHT_UPDATED,
                    actor_id=actor_id[:26],
                    resource_type="fusion_config",
                    resource_id=str(EntityId.generate()),
                    metadata={
                        "source_system": source_system,
                        "weight": str(weight),
                    },
                )
            )

    async def list_effective_weights(self) -> dict[str, float]:
        effective = dict(DEFAULT_FUSION_WEIGHTS)
        async with self._session_factory() as session:
            repo = SqlAlchemyFusionConfigRepository(session)
            for src, weight in await repo.list_weights():
                effective[src] = weight
        return effective

    async def _upsert_catalog_indicator(
        self,
        fused_repo: SqlAlchemyFusedIndicatorRepository,
        *,
        conflict_policy: FusionConflictPolicy,
        ttl_policy: IndicatorTTLPolicy,
        key: CanonicalIndicatorKey,
        display_name: str,
        source_system: str,
        external_id: str,
        confidence: FusionConfidence,
        metadata: dict[str, Any],
        now: datetime,
    ) -> tuple[int, int, int]:
        attribution = SourceAttribution(
            source_system=source_system,
            external_id=external_id,
            content_hash=key.content_fingerprint(display_name, source_system),
            observed_at=now,
            weight_applied=conflict_policy.weight_for(source_system),
            confidence=confidence,
            metadata={k: str(v) for k, v in metadata.items()},
        )
        valid_until = ttl_policy.valid_until(key.indicator_type.value, valid_from=now)
        existing = await fused_repo.get_by_canonical_key(key)
        created = updated = no_evidence = 0
        if existing is None:
            indicator = FusedIndicator.fuse(
                id=str(EntityId.generate()),
                canonical_key=key,
                display_name=display_name,
                attributions=[attribution],
                conflict_policy=conflict_policy,
                valid_until=valid_until,
                metadata=metadata,
                now=now,
            )
            if indicator.aggregated_risk.confidence is None:
                no_evidence = 1
            await fused_repo.upsert(indicator)
            created = 1
        else:
            existing.merge_attribution(
                attribution,
                conflict_policy=conflict_policy,
                display_name=display_name,
                metadata=metadata,
                valid_until=valid_until,
                now=now,
            )
            await fused_repo.upsert(existing)
            updated = 1
        return created, updated, no_evidence

    async def _ensure_endpoint(
        self,
        fused_repo: SqlAlchemyFusedIndicatorRepository,
        *,
        conflict_policy: FusionConflictPolicy,
        ttl_policy: IndicatorTTLPolicy,
        stix_ref: str,
        technique_id: str | None,
        key_to_id: dict[str, str],
        now: datetime,
    ) -> tuple[str | None, str | None, int]:
        if technique_id:
            key = CanonicalIndicatorKey.for_type(
                FusedIndicatorType.TECHNIQUE, technique_id
            )
            indicator_id = key_to_id.get(key.value)
            if indicator_id:
                return indicator_id, key.value, 0
            existing = await fused_repo.get_by_canonical_key(key)
            if existing:
                key_to_id[key.value] = existing.id
                return existing.id, key.value, 0

        fused_type = fused_type_for_stix_ref(stix_ref)
        if fused_type is None:
            return None, None, 0
        if fused_type is FusedIndicatorType.TECHNIQUE and technique_id is None:
            # Technique side missing from catalog — cannot honestly fuse.
            return None, None, 0

        raw_value = stix_ref
        key = CanonicalIndicatorKey.for_type(fused_type, raw_value)
        if key.value in key_to_id:
            return key_to_id[key.value], key.value, 0
        existing = await fused_repo.get_by_canonical_key(key)
        if existing:
            key_to_id[key.value] = existing.id
            return existing.id, key.value, 0

        attribution = SourceAttribution(
            source_system=ReferenceDataSource.MITRE_ATTACK.value,
            external_id=stix_ref,
            content_hash=key.content_fingerprint(stix_ref),
            observed_at=now,
            weight_applied=conflict_policy.weight_for(
                ReferenceDataSource.MITRE_ATTACK.value
            ),
            confidence=FusionConfidence.LOW,
            metadata={"stix_ref": stix_ref, "stub": "true"},
        )
        indicator = FusedIndicator.fuse(
            id=str(EntityId.generate()),
            canonical_key=key,
            display_name=stix_ref,
            attributions=[attribution],
            conflict_policy=conflict_policy,
            valid_until=ttl_policy.valid_until(fused_type.value, valid_from=now),
            metadata={"stix_ref": stix_ref, "stub": True},
            now=now,
        )
        stored = await fused_repo.upsert(indicator)
        key_to_id[key.value] = stored.id
        return stored.id, key.value, 1
