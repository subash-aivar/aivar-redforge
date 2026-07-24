"""PgDetectionPackRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from detection.domain.aggregates.detection_pack import DetectionPack
from detection.domain.entities.pack_entities import PackRule, PackVersion
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_pack_repository import (
    IDetectionPackRepository,
)
from detection.domain.value_objects.enums import PackCategory, PackLifecycleState
from detection.domain.value_objects.identifiers import (
    DetectionPackId,
    PackRuleId,
    PackVersionId,
    TenantId,
)
from detection.domain.value_objects.keys import RuleSemVer
from detection.domain.value_objects.pack import PackKey
from detection.infrastructure.persistence.models.pack_exception_evidence_model import (
    DetectionPackModel,
    DetectionPackRuleModel,
    DetectionPackVersionModel,
)
from detection.infrastructure.persistence.serialization import (
    compliance_fw_from_json,
    compliance_fw_to_json,
    coverage_from_json,
    coverage_to_json,
    pack_maintainer_from_json,
    pack_maintainer_to_json,
    pack_metadata_from_json,
    pack_metadata_to_json,
    subscription_from_json,
    subscription_to_json,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgDetectionPackRepository(IDetectionPackRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, pack: DetectionPack) -> None:
        existing = await self._session.execute(
            select(DetectionPackModel).where(DetectionPackModel.id == pack.pack_id.value)
        )
        row = existing.scalar_one_or_none()
        if row is None:
            self._session.add(self._to_model(pack))
        else:
            if row.row_version > pack.version:
                raise OptimisticLockConflict(str(pack.pack_id))
            row.pack_key = str(pack.pack_key)
            row.title = pack.title
            row.category = pack.category.value
            row.lifecycle_state = pack.lifecycle_state.value
            row.semver = str(pack.semver)
            row.maintainer_json = pack_maintainer_to_json(pack.maintainer)
            row.subscription_json = subscription_to_json(pack.subscription_scope)
            row.compliance_framework_json = compliance_fw_to_json(pack.compliance_framework)
            row.coverage_json = coverage_to_json(pack.coverage_matrix)
            row.metadata_json = pack_metadata_to_json(pack.metadata)
            row.updated_at = pack.updated_at
            row.row_version = pack.version

        await self._session.execute(
            delete(DetectionPackRuleModel).where(
                DetectionPackRuleModel.pack_id == pack.pack_id.value
            )
        )
        for rule in pack.rules:
            self._session.add(
                DetectionPackRuleModel(
                    id=rule.pack_rule_id.value,
                    pack_id=pack.pack_id.value,
                    tenant_id=pack.tenant_id.value,
                    rule_id=rule.rule_id,
                    rule_version=str(rule.rule_version) if rule.rule_version else None,
                    optional=rule.optional,
                    added_at=rule.added_at,
                )
            )

        await self._session.execute(
            delete(DetectionPackVersionModel).where(
                DetectionPackVersionModel.pack_id == pack.pack_id.value
            )
        )
        for ver in pack.pack_versions:
            self._session.add(
                DetectionPackVersionModel(
                    id=ver.pack_version_id.value,
                    pack_id=pack.pack_id.value,
                    tenant_id=pack.tenant_id.value,
                    version=str(ver.version),
                    rule_snapshots_json=[
                        {"rule_id": rid, "rule_version": rv}
                        for rid, rv in ver.rule_snapshots
                    ],
                    release_notes=ver.release_notes,
                    released_at=ver.released_at,
                )
            )
        await self._session.flush()

    def _to_model(self, pack: DetectionPack) -> DetectionPackModel:
        return DetectionPackModel(
            id=pack.pack_id.value,
            tenant_id=pack.tenant_id.value,
            pack_key=str(pack.pack_key),
            title=pack.title,
            category=pack.category.value,
            lifecycle_state=pack.lifecycle_state.value,
            semver=str(pack.semver),
            maintainer_json=pack_maintainer_to_json(pack.maintainer),
            subscription_json=subscription_to_json(pack.subscription_scope),
            compliance_framework_json=compliance_fw_to_json(pack.compliance_framework),
            coverage_json=coverage_to_json(pack.coverage_matrix),
            metadata_json=pack_metadata_to_json(pack.metadata),
            created_at=pack.created_at,
            updated_at=pack.updated_at,
            row_version=pack.version,
        )

    async def _hydrate(self, model: DetectionPackModel) -> DetectionPack:
        rules_q = await self._session.execute(
            select(DetectionPackRuleModel).where(
                DetectionPackRuleModel.pack_id == model.id
            )
        )
        rules = [
            PackRule(
                pack_rule_id=PackRuleId(r.id),
                rule_id=r.rule_id,
                rule_version=RuleSemVer.parse(r.rule_version) if r.rule_version else None,
                added_at=r.added_at,
                optional=r.optional,
            )
            for r in rules_q.scalars().all()
        ]
        vers_q = await self._session.execute(
            select(DetectionPackVersionModel).where(
                DetectionPackVersionModel.pack_id == model.id
            )
        )
        versions = [
            PackVersion(
                pack_version_id=PackVersionId(v.id),
                version=RuleSemVer.parse(v.version),
                rule_snapshots=tuple(
                    (str(s["rule_id"]), s.get("rule_version"))
                    for s in (v.rule_snapshots_json or [])
                ),
                released_at=v.released_at,
                release_notes=v.release_notes or "",
            )
            for v in vers_q.scalars().all()
        ]
        return DetectionPack(
            pack_id=DetectionPackId(model.id),
            tenant_id=TenantId.from_uuid(model.tenant_id),
            pack_key=PackKey(model.pack_key),
            title=model.title,
            category=PackCategory(model.category),
            maintainer=pack_maintainer_from_json(model.maintainer_json),
            lifecycle_state=PackLifecycleState(model.lifecycle_state),
            semver=RuleSemVer.parse(model.semver),
            created_at=model.created_at,
            updated_at=model.updated_at,
            rules=rules,
            pack_versions=versions,
            subscription_scope=subscription_from_json(model.subscription_json),
            compliance_framework=compliance_fw_from_json(model.compliance_framework_json),
            coverage_matrix=coverage_from_json(model.coverage_json),
            metadata=pack_metadata_from_json(model.metadata_json),
            version=model.row_version,
        )

    async def find_by_id(
        self, pack_id: DetectionPackId, tenant_id: TenantId
    ) -> DetectionPack | None:
        result = await self._session.execute(
            select(DetectionPackModel).where(
                DetectionPackModel.id == pack_id.value,
                DetectionPackModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return await self._hydrate(model) if model else None

    async def find_by_pack_key(
        self, pack_key: PackKey, tenant_id: TenantId
    ) -> DetectionPack | None:
        result = await self._session.execute(
            select(DetectionPackModel).where(
                DetectionPackModel.pack_key == str(pack_key),
                DetectionPackModel.tenant_id == tenant_id.value,
            )
        )
        model = result.scalar_one_or_none()
        return await self._hydrate(model) if model else None

    async def find_active_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionPack]:
        result = await self._session.execute(
            select(DetectionPackModel)
            .where(
                DetectionPackModel.tenant_id == tenant_id.value,
                DetectionPackModel.lifecycle_state == PackLifecycleState.PUBLISHED.value,
            )
            .limit(limit)
            .offset(offset)
        )
        return [await self._hydrate(m) for m in result.scalars().all()]

    async def find_by_compliance_framework(
        self,
        framework_ref: str,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DetectionPack]:
        result = await self._session.execute(
            select(DetectionPackModel)
            .where(DetectionPackModel.tenant_id == tenant_id.value)
            .limit(limit)
            .offset(offset)
        )
        packs = [await self._hydrate(m) for m in result.scalars().all()]
        return [
            p
            for p in packs
            if p.compliance_framework
            and p.compliance_framework.framework_id == framework_ref
        ]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionPack]:
        result = await self._session.execute(
            select(DetectionPackModel)
            .where(DetectionPackModel.tenant_id == tenant_id.value)
            .limit(limit)
            .offset(offset)
        )
        return [await self._hydrate(m) for m in result.scalars().all()]
