"""SQLAlchemy repositories for the Attack Path Engine — M22 Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from redforge.domain.attack_path.entity import AttackPath
from redforge.domain.attack_path.value_objects import (
    AttackStep,
    PathConfidence,
    PathStatus,
    StepType,
    path_confidence_rank,
)
from redforge.infrastructure.database.models.attack_path import (
    AttackPathModel,
    AttackPathStepEvidenceModel,
    AttackPathStepModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _path_to_domain(model: AttackPathModel) -> AttackPath:
    return AttackPath(
        id=model.id,
        organization_id=model.organization_id,
        root_entity_id=model.root_entity_id,
        root_canonical_key=model.root_canonical_key,
        terminal_entity_id=model.terminal_entity_id,
        path_confidence=PathConfidence(model.path_confidence),
        technique_coverage=[str(x) for x in (model.technique_coverage or [])],
        attributed_actors=[str(x) for x in (model.attributed_actors or [])],
        step_count=model.step_count,
        evidence_count=model.evidence_count,
        max_exposure_score=float(model.max_exposure_score),
        first_step_at=model.first_step_at,
        last_step_at=model.last_step_at,
        status=PathStatus(model.status),
        created_at=model.created_at,
        updated_at=model.updated_at,
        investigation_id=getattr(model, "investigation_id", None),
    )


def _apply_path(model: AttackPathModel, path: AttackPath) -> None:
    model.id = path.id
    model.organization_id = path.organization_id
    model.root_entity_id = path.root_entity_id
    model.root_canonical_key = path.root_canonical_key
    model.terminal_entity_id = path.terminal_entity_id
    model.path_confidence = path.path_confidence.value
    model.technique_coverage = list(path.technique_coverage)
    model.attributed_actors = list(path.attributed_actors)
    model.step_count = path.step_count
    model.evidence_count = path.evidence_count
    model.max_exposure_score = path.max_exposure_score
    model.first_step_at = path.first_step_at
    model.last_step_at = path.last_step_at
    model.status = path.status.value
    model.investigation_id = path.investigation_id
    model.created_at = path.created_at
    model.updated_at = path.updated_at


class SqlAlchemyAttackPathRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self, path_id: str, *, organization_id: str
    ) -> AttackPath | None:
        stmt = select(AttackPathModel).where(
            AttackPathModel.id == path_id,
            AttackPathModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return _path_to_domain(model) if model else None

    async def add(self, path: AttackPath) -> AttackPath:
        model = AttackPathModel(id=path.id)
        _apply_path(model, path)
        self._session.add(model)
        await self._session.flush()
        return _path_to_domain(model)

    async def update(self, path: AttackPath) -> AttackPath:
        model = await self._session.get(AttackPathModel, path.id)
        if model is None:
            return await self.add(path)
        if model.organization_id != path.organization_id:
            return await self.add(path)
        _apply_path(model, path)
        await self._session.flush()
        return _path_to_domain(model)

    async def list_for_organization(
        self,
        organization_id: str,
        *,
        status: PathStatus | None = None,
        root_technique_id: str | None = None,
        confidence_floor: PathConfidence | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPath]:
        stmt = select(AttackPathModel).where(
            AttackPathModel.organization_id == organization_id
        )
        if status is not None:
            stmt = stmt.where(AttackPathModel.status == status.value)
        stmt = (
            stmt.order_by(AttackPathModel.created_at.desc()).limit(limit * 3).offset(offset)
        )
        result = await self._session.execute(stmt)
        paths = [_path_to_domain(m) for m in result.scalars().all()]
        if confidence_floor is not None:
            floor = path_confidence_rank(confidence_floor)
            paths = [
                p for p in paths if path_confidence_rank(p.path_confidence) >= floor
            ]
        if root_technique_id is not None:
            paths = [
                p for p in paths if root_technique_id in p.technique_coverage
            ]
        return paths[:limit]

    async def list_by_root_entity(
        self,
        organization_id: str,
        root_entity_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPath]:
        stmt = (
            select(AttackPathModel)
            .where(
                AttackPathModel.organization_id == organization_id,
                AttackPathModel.root_entity_id == root_entity_id,
            )
            .order_by(AttackPathModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_path_to_domain(m) for m in result.scalars().all()]

    async def list_active_for_root(
        self, organization_id: str, root_entity_id: str
    ) -> list[AttackPath]:
        stmt = select(AttackPathModel).where(
            AttackPathModel.organization_id == organization_id,
            AttackPathModel.root_entity_id == root_entity_id,
            AttackPathModel.status == PathStatus.ACTIVE.value,
        )
        result = await self._session.execute(stmt)
        return [_path_to_domain(m) for m in result.scalars().all()]

    async def list_for_investigation(
        self,
        organization_id: str,
        investigation_id: str,
        *,
        limit: int = 20,
    ) -> list[AttackPath]:
        stmt = (
            select(AttackPathModel)
            .where(
                AttackPathModel.organization_id == organization_id,
                AttackPathModel.investigation_id == investigation_id,
            )
            .order_by(AttackPathModel.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_path_to_domain(m) for m in result.scalars().all()]


class SqlAlchemyAttackPathStepRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def replace_steps(
        self, path_id: str, organization_id: str, steps: list[AttackStep]
    ) -> None:
        existing = await self._session.execute(
            select(AttackPathStepModel.id).where(
                AttackPathStepModel.attack_path_id == path_id
            )
        )
        existing_step_ids = list(existing.scalars().all())
        if existing_step_ids:
            await self._session.execute(
                delete(AttackPathStepEvidenceModel).where(
                    AttackPathStepEvidenceModel.step_id.in_(existing_step_ids)
                )
            )
        await self._session.execute(
            delete(AttackPathStepModel).where(
                AttackPathStepModel.attack_path_id == path_id
            )
        )
        new_step_ids: list[str] = []
        for step in steps:
            step_id = str(EntityId.generate())
            new_step_ids.append(step_id)
            self._session.add(
                AttackPathStepModel(
                    id=step_id,
                    attack_path_id=path_id,
                    organization_id=organization_id,
                    sequence=step.sequence,
                    entity_id=step.entity_id,
                    canonical_key=step.canonical_key,
                    step_type=step.step_type.value,
                    confidence=step.confidence.value,
                    technique_id=step.technique_id,
                    relationship_type=step.relationship_type,
                    kill_chain_phase=step.kill_chain_phase,
                    observed_at=step.observed_at,
                    inferred_from_step=step.inferred_from_step,
                    exposure_score=step.exposure_score,
                )
            )
        # Parent steps must be visible before evidence FK inserts (asyncpg).
        await self._session.flush()
        for step, step_id in zip(steps, new_step_ids, strict=True):
            for ref in step.evidence_refs:
                self._session.add(
                    AttackPathStepEvidenceModel(
                        id=str(EntityId.generate()),
                        step_id=step_id,
                        organization_id=organization_id,
                        evidence_ref=ref[:128],
                    )
                )
        await self._session.flush()

    async def list_steps(
        self, path_id: str, *, organization_id: str
    ) -> list[AttackStep]:
        stmt = (
            select(AttackPathStepModel)
            .where(
                AttackPathStepModel.attack_path_id == path_id,
                AttackPathStepModel.organization_id == organization_id,
            )
            .order_by(AttackPathStepModel.sequence)
        )
        result = await self._session.execute(stmt)
        models = list(result.scalars().all())
        steps: list[AttackStep] = []
        for model in models:
            evidence_stmt = select(AttackPathStepEvidenceModel.evidence_ref).where(
                AttackPathStepEvidenceModel.step_id == model.id
            )
            evidence_result = await self._session.execute(evidence_stmt)
            refs = tuple(evidence_result.scalars().all())
            steps.append(
                AttackStep(
                    sequence=model.sequence,
                    entity_id=model.entity_id,
                    canonical_key=model.canonical_key,
                    step_type=StepType(model.step_type),
                    confidence=PathConfidence(model.confidence),
                    technique_id=model.technique_id,
                    evidence_refs=refs,
                    relationship_type=model.relationship_type,
                    kill_chain_phase=model.kill_chain_phase,
                    observed_at=model.observed_at,
                    inferred_from_step=model.inferred_from_step,
                    exposure_score=float(model.exposure_score),
                )
            )
        return steps
