"""Attack Path Engine application services — M22 Phase 5.

Builds an ATT&CK/fusion attack graph from Phase 4 fused outputs and
runs bounded BFS path discovery. Does not duplicate fusion logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.domain.attack_path.entity import AttackPath
from redforge.domain.attack_path.exceptions import AttackPathSeedInvalidError
from redforge.domain.attack_path.graph import (
    GraphEdge,
    GraphNode,
    build_graph_from_fusion,
    discover_paths,
)
from redforge.domain.attack_path.policies import InferenceGatePolicy, PathExplosionPolicy
from redforge.domain.attack_path.value_objects import (
    AttackStep,
    PathConfidence,
    PathExplosionBudget,
    PathStatus,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    FusedIndicatorType,
    FusionConfidence,
    IndicatorLifecycle,
)
from redforge.domain.threat_intel.reference_data_value_objects import AttackRelationshipType
from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.attack_path_repository import (
    SqlAlchemyAttackPathRepository,
    SqlAlchemyAttackPathStepRepository,
)
from redforge.infrastructure.database.repositories.threat_fusion_repository import (
    SqlAlchemyFusedIndicatorRepository,
    SqlAlchemyFusedRelationshipRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class AttackPathComputeResult:
    path: AttackPath
    steps: tuple[AttackStep, ...]
    alternate_path_count: int


class AttackPathService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        audit_factory: Callable[[AsyncSession], PostgresPlatformAuditLog] | None = None,
        explosion_budget: PathExplosionBudget | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._audit_factory = audit_factory or (
            lambda session: PostgresPlatformAuditLog(session)
        )
        self._budget = explosion_budget or PathExplosionBudget()

    async def compute(
        self,
        *,
        organization_id: str,
        seed_indicator_id: str,
        actor_id: str,
    ) -> AttackPathComputeResult:
        """On-demand path compute (Hardening Review: seed + trigger contract).

        Trigger: explicit admin API call with required seed_indicator_id.
        Previous ACTIVE paths for the same org+seed are archived to HISTORICAL.
        """
        async with self._session_factory() as session, session.begin():
            fused_repo = SqlAlchemyFusedIndicatorRepository(session)
            rel_repo = SqlAlchemyFusedRelationshipRepository(session)
            path_repo = SqlAlchemyAttackPathRepository(session)
            step_repo = SqlAlchemyAttackPathStepRepository(session)

            seed = await fused_repo.get_by_id(seed_indicator_id)
            if seed is None or seed.lifecycle is not IndicatorLifecycle.ACTIVE:
                raise AttackPathSeedInvalidError(
                    f"Seed indicator {seed_indicator_id!r} is missing or not ACTIVE"
                )
            if seed.confidence is None:
                raise AttackPathSeedInvalidError(
                    f"Seed indicator {seed_indicator_id!r} has NO_EVIDENCE risk state"
                )

            indicators = await fused_repo.list_active(limit=5000)
            relationships = await rel_repo.list_all(limit=10000)

            nodes: list[GraphNode] = []
            for ind in indicators:
                conf = ind.confidence or FusionConfidence.LOW
                technique_id = (
                    ind.canonical_key.raw_value
                    if ind.indicator_type is FusedIndicatorType.TECHNIQUE
                    else None
                )
                meta = ind.metadata
                epss = None
                if "epss_probability" in meta:
                    try:
                        epss = float(meta["epss_probability"])
                    except ValueError:
                        epss = None
                nodes.append(
                    GraphNode(
                        entity_id=ind.id,
                        canonical_key=ind.canonical_key.value,
                        indicator_type=ind.indicator_type,
                        display_name=ind.display_name,
                        confidence=conf,
                        technique_id=technique_id,
                        kill_chain_phase=meta.get("kill_chain_phase"),
                        is_kev=meta.get("is_kev") == "True",
                        epss_probability=epss,
                        evidence_refs=(ind.id,),
                        metadata=meta,
                    )
                )

            edges: list[GraphEdge] = []
            for rel in relationships:
                edges.append(
                    GraphEdge(
                        source_entity_id=rel.source_indicator_id,
                        target_entity_id=rel.target_indicator_id,
                        relationship_type=rel.relationship_type.value,
                        confidence=FusionConfidence.MEDIUM,
                        evidence_ref=rel.stix_relationship_id or rel.id,
                        observed=True,
                    )
                )

            # INFERRED candidate precedes edges between technique nodes
            # when a fused precedes relationship is absent but both
            # techniques share a kill-chain ordering hint — only when
            # an OBSERVED path already exists elsewhere; here we only
            # add precedes edges that already exist as OBSERVED fused
            # relationships. Additional inferred precedes without a
            # fused row would fabricate structure — skipped.

            # Bidirectional USES edges: also traverse reverse for path
            # discovery when relationship is uses (software→technique).
            for rel in relationships:
                if rel.relationship_type is AttackRelationshipType.USES:
                    edges.append(
                        GraphEdge(
                            source_entity_id=rel.target_indicator_id,
                            target_entity_id=rel.source_indicator_id,
                            relationship_type="used-by",
                            confidence=FusionConfidence.LOW,
                            evidence_ref=rel.stix_relationship_id or rel.id,
                            observed=False,
                        )
                    )

            graph = build_graph_from_fusion(nodes=nodes, edges=edges)
            discovered = discover_paths(
                graph,
                seed_entity_id=seed.id,
                explosion=PathExplosionPolicy(self._budget),
                inference_gate=InferenceGatePolicy(),
            )
            if not discovered:
                raise AttackPathSeedInvalidError(
                    "No evidence-backed path could be discovered from seed"
                )

            # Prefer longest path, then highest exposure.
            primary = max(
                discovered,
                key=lambda p: (len(p.steps), p.max_exposure_score),
            )

            # Archive prior ACTIVE paths for this seed.
            for prior in await path_repo.list_active_for_root(
                organization_id, seed.id
            ):
                prior.archive()
                await path_repo.update(prior)

            now = datetime.now(UTC)
            path = AttackPath.create_computed(
                id=str(EntityId.generate()),
                organization_id=organization_id,
                root_entity_id=seed.id,
                root_canonical_key=seed.canonical_key.value,
                terminal_entity_id=primary.steps[-1].entity_id,
                path_confidence=primary.path_confidence,
                technique_coverage=list(primary.technique_coverage),
                attributed_actors=list(primary.attributed_actors),
                step_count=len(primary.steps),
                evidence_count=sum(len(s.evidence_refs) for s in primary.steps),
                max_exposure_score=primary.max_exposure_score,
                first_step_at=now,
                last_step_at=now,
                now=now,
            )
            await path_repo.add(path)
            await step_repo.replace_steps(
                path.id, organization_id, list(primary.steps)
            )

            audit = self._audit_factory(session)
            await audit.record(
                AuditEntry(
                    action=AuditAction.ATTACK_PATH_COMPUTED,
                    actor_id=actor_id[:26],
                    resource_type="attack_path",
                    resource_id=path.id,
                    metadata={
                        "organization_id": organization_id,
                        "seed_indicator_id": seed_indicator_id,
                        "step_count": str(path.step_count),
                        "path_confidence": path.path_confidence.value,
                    },
                )
            )

            return AttackPathComputeResult(
                path=path,
                steps=primary.steps,
                alternate_path_count=max(0, len(discovered) - 1),
            )

    async def contain(
        self, *, organization_id: str, path_id: str, actor_id: str
    ) -> AttackPath:
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyAttackPathRepository(session)
            path = await repo.get_by_id(path_id, organization_id=organization_id)
            if path is None:
                from redforge.core.exceptions import NotFoundError

                raise NotFoundError("AttackPath", path_id)
            path.contain()
            updated = await repo.update(path)
            await self._audit_factory(session).record(
                AuditEntry(
                    action=AuditAction.ATTACK_PATH_UPDATED,
                    actor_id=actor_id[:26],
                    resource_type="attack_path",
                    resource_id=path_id,
                    metadata={
                        "organization_id": organization_id,
                        "status": PathStatus.CONTAINED.value,
                    },
                )
            )
            return updated

    async def archive(
        self, *, organization_id: str, path_id: str, actor_id: str
    ) -> AttackPath:
        async with self._session_factory() as session, session.begin():
            repo = SqlAlchemyAttackPathRepository(session)
            path = await repo.get_by_id(path_id, organization_id=organization_id)
            if path is None:
                from redforge.core.exceptions import NotFoundError

                raise NotFoundError("AttackPath", path_id)
            path.archive()
            updated = await repo.update(path)
            await self._audit_factory(session).record(
                AuditEntry(
                    action=AuditAction.ATTACK_PATH_UPDATED,
                    actor_id=actor_id[:26],
                    resource_type="attack_path",
                    resource_id=path_id,
                    metadata={
                        "organization_id": organization_id,
                        "status": PathStatus.HISTORICAL.value,
                    },
                )
            )
            return updated


class AttackPathQueryService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_path(
        self, *, organization_id: str, path_id: str
    ) -> tuple[AttackPath, list[AttackStep]] | None:
        async with self._session_factory() as session:
            path_repo = SqlAlchemyAttackPathRepository(session)
            step_repo = SqlAlchemyAttackPathStepRepository(session)
            path = await path_repo.get_by_id(path_id, organization_id=organization_id)
            if path is None:
                return None
            steps = await step_repo.list_steps(path_id, organization_id=organization_id)
            return path, steps

    async def list_paths(
        self,
        *,
        organization_id: str,
        status: PathStatus | None = None,
        root_technique_id: str | None = None,
        confidence_floor: PathConfidence | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPath]:
        async with self._session_factory() as session:
            repo = SqlAlchemyAttackPathRepository(session)
            return await repo.list_for_organization(
                organization_id,
                status=status,
                root_technique_id=root_technique_id,
                confidence_floor=confidence_floor,
                limit=limit,
                offset=offset,
            )
