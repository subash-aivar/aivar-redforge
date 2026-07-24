"""PgDetectionRuleRepository — SQLAlchemy implementation of IDetectionRuleRepository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select, update

from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.entities.rule_entities import (
    MitreAttackMapping,
    RuleTestCase,
    RuleTestResult,
    RuleVersion,
)
from detection.domain.exceptions.domain_exceptions import OptimisticLockConflict
from detection.domain.repositories.i_detection_rule_repository import IDetectionRuleRepository
from detection.domain.value_objects.enums import (
    RuleCategory,
    RuleConfidence,
    RuleLifecycleState,
    RuleSeverity,
    TestResultStatus,
)
from detection.domain.value_objects.identifiers import (
    DetectionRuleId,
    MitreAttackMappingId,
    RuleTestCaseId,
    RuleTestResultId,
    RuleVersionId,
    TenantId,
)
from detection.domain.value_objects.keys import (
    AuthorRef,
    MitreTechniqueId,
    ReviewerRef,
    RuleKey,
    RuleSemVer,
)
from detection.infrastructure.persistence.models.detection_rule_model import (
    DetectionRuleModel,
    MitreAttackMappingModel,
    RuleTestCaseModel,
    RuleTestResultModel,
    RuleVersionModel,
)
from detection.infrastructure.persistence.serialization import (
    asset_scope_from_json,
    asset_scope_to_json,
    external_refs_from_json,
    external_refs_to_json,
    fp_profile_from_json,
    fp_profile_to_json,
    rule_logic_from_dict,
    rule_logic_to_dict,
    tags_from_json,
    tags_to_json,
    telemetry_sources_from_json,
    telemetry_sources_to_json,
    throttle_from_json,
    throttle_to_json,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _version_models(rule: DetectionRule) -> list[RuleVersionModel]:
    return [
        RuleVersionModel(
            id=item.version_id.value,
            rule_id=rule.rule_id.value,
            tenant_id=rule.tenant_id.value,
            semver=str(item.semver),
            logic_json=rule_logic_to_dict(item.logic),
            change_summary=item.change_summary,
            published_at=item.published_at,
            published_by=item.published_by,
        )
        for item in rule.versions
    ]


def _test_case_models(rule: DetectionRule) -> list[RuleTestCaseModel]:
    return [
        RuleTestCaseModel(
            id=item.test_case_id.value,
            rule_id=rule.rule_id.value,
            tenant_id=rule.tenant_id.value,
            name=item.name,
            input_payload_json=dict(item.input_payload),
            expected_match=item.expected_match,
            description=item.description,
        )
        for item in rule.test_cases
    ]


def _test_result_models(rule: DetectionRule) -> list[RuleTestResultModel]:
    return [
        RuleTestResultModel(
            id=item.result_id.value,
            rule_id=rule.rule_id.value,
            test_case_id=item.test_case_id.value,
            tenant_id=rule.tenant_id.value,
            status=item.status.value,
            duration_ms=item.duration_ms,
            recorded_at=item.recorded_at,
            message=item.message,
            rule_version=item.rule_version,
        )
        for item in rule.test_results
    ]


def _mitre_models(rule: DetectionRule) -> list[MitreAttackMappingModel]:
    return [
        MitreAttackMappingModel(
            id=item.mapping_id.value,
            rule_id=rule.rule_id.value,
            tenant_id=rule.tenant_id.value,
            tactic=item.tactic,
            technique=item.technique.value,
            sub_technique=item.sub_technique.value if item.sub_technique is not None else None,
            notes=item.notes,
            weight=1.0,
        )
        for item in rule.mitre_mappings
    ]


def _to_domain(row: DetectionRuleModel) -> DetectionRule:
    versions = [
        RuleVersion(
            version_id=RuleVersionId(item.id),
            semver=RuleSemVer.parse(item.semver),
            logic=rule_logic_from_dict(item.logic_json),
            change_summary=item.change_summary,
            published_at=item.published_at,
            published_by=item.published_by,
        )
        for item in row.versions
    ]
    test_cases = [
        RuleTestCase(
            test_case_id=RuleTestCaseId(item.id),
            name=item.name,
            input_payload=dict(item.input_payload_json),
            expected_match=item.expected_match,
            description=item.description,
        )
        for item in row.test_cases
    ]
    test_results = [
        RuleTestResult(
            result_id=RuleTestResultId(item.id),
            test_case_id=RuleTestCaseId(item.test_case_id),
            status=TestResultStatus(item.status),
            duration_ms=item.duration_ms,
            recorded_at=item.recorded_at,
            message=item.message,
            rule_version=item.rule_version,
        )
        for item in row.test_results
    ]
    mitre_mappings = [
        MitreAttackMapping(
            mapping_id=MitreAttackMappingId(item.id),
            tactic=item.tactic,
            technique=MitreTechniqueId(item.technique),
            sub_technique=(
                MitreTechniqueId(item.sub_technique) if item.sub_technique is not None else None
            ),
            notes=item.notes,
        )
        for item in row.mitre_mappings
    ]
    reviewer = (
        ReviewerRef(row.reviewer_identity) if row.reviewer_identity is not None else None
    )
    return DetectionRule(
        rule_id=DetectionRuleId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        rule_key=RuleKey(row.rule_key),
        title=row.title,
        description=row.description,
        category=RuleCategory(row.category),
        severity=RuleSeverity(row.severity),
        confidence=RuleConfidence(row.confidence),
        author=AuthorRef(row.author_identity),
        lifecycle_state=RuleLifecycleState(row.lifecycle_state),
        current_logic=rule_logic_from_dict(row.current_logic_json),
        created_at=row.created_at,
        updated_at=row.updated_at,
        versions=versions,
        test_cases=test_cases,
        test_results=test_results,
        mitre_mappings=mitre_mappings,
        telemetry_sources=telemetry_sources_from_json(row.telemetry_sources_json),
        asset_scope=asset_scope_from_json(row.asset_scope_json),
        throttle_policy=throttle_from_json(row.throttle_json),
        false_positive_profile=fp_profile_from_json(row.fp_profile_json),
        reviewer=reviewer,
        tags=tags_from_json(row.tags_json),
        external_refs=external_refs_from_json(row.external_refs_json),
        row_version=row.row_version,
    )


def _from_domain(rule: DetectionRule) -> DetectionRuleModel:
    return DetectionRuleModel(
        id=rule.rule_id.value,
        tenant_id=rule.tenant_id.value,
        rule_key=rule.rule_key.value,
        title=rule.title,
        description=rule.description,
        category=rule.category.value,
        severity=rule.severity.value,
        confidence=rule.confidence.value,
        lifecycle_state=rule.lifecycle_state.value,
        author_identity=rule.author.identity,
        reviewer_identity=rule.reviewer.identity if rule.reviewer is not None else None,
        current_logic_json=rule_logic_to_dict(rule.current_logic),
        telemetry_sources_json=telemetry_sources_to_json(rule.telemetry_sources),
        asset_scope_json=asset_scope_to_json(rule.asset_scope),
        throttle_json=throttle_to_json(rule.throttle_policy),
        fp_profile_json=fp_profile_to_json(rule.false_positive_profile),
        tags_json=tags_to_json(rule.tags),
        external_refs_json=external_refs_to_json(rule.external_refs),
        created_at=rule.created_at,
        updated_at=rule.updated_at,
        row_version=rule.version,
        versions=_version_models(rule),
        test_cases=_test_case_models(rule),
        test_results=_test_result_models(rule),
        mitre_mappings=_mitre_models(rule),
    )


def _replace_children(model: DetectionRuleModel, rule: DetectionRule) -> None:
    model.versions.clear()
    model.versions.extend(_version_models(rule))
    model.test_cases.clear()
    model.test_cases.extend(_test_case_models(rule))
    model.test_results.clear()
    model.test_results.extend(_test_result_models(rule))
    model.mitre_mappings.clear()
    model.mitre_mappings.extend(_mitre_models(rule))


class PgDetectionRuleRepository(IDetectionRuleRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, rule: DetectionRule) -> None:
        existing = await self._session.execute(
            select(DetectionRuleModel).where(DetectionRuleModel.id == rule.rule_id.value)
        )
        row = existing.scalar_one_or_none()

        if row is None:
            model = _from_domain(rule)
            model.row_version = 1
            self._session.add(model)
            await self._session.flush()
            rule._version = 1
            return

        if row.tenant_id != rule.tenant_id.value:
            raise OptimisticLockConflict(str(rule.rule_id))

        actual = row.row_version
        if rule.version == actual + 1 or rule.version == actual:
            expected_version = actual
        else:
            raise OptimisticLockConflict(str(rule.rule_id))

        result = await self._session.execute(
            update(DetectionRuleModel)
            .where(
                DetectionRuleModel.id == rule.rule_id.value,
                DetectionRuleModel.tenant_id == rule.tenant_id.value,
                DetectionRuleModel.row_version == expected_version,
            )
            .values(
                rule_key=rule.rule_key.value,
                title=rule.title,
                description=rule.description,
                category=rule.category.value,
                severity=rule.severity.value,
                confidence=rule.confidence.value,
                lifecycle_state=rule.lifecycle_state.value,
                author_identity=rule.author.identity,
                reviewer_identity=(
                    rule.reviewer.identity if rule.reviewer is not None else None
                ),
                current_logic_json=rule_logic_to_dict(rule.current_logic),
                telemetry_sources_json=telemetry_sources_to_json(rule.telemetry_sources),
                asset_scope_json=asset_scope_to_json(rule.asset_scope),
                throttle_json=throttle_to_json(rule.throttle_policy),
                fp_profile_json=fp_profile_to_json(rule.false_positive_profile),
                tags_json=tags_to_json(rule.tags),
                external_refs_json=external_refs_to_json(rule.external_refs),
                updated_at=rule.updated_at,
                row_version=expected_version + 1,
            )
            .returning(DetectionRuleModel.row_version)
        )
        new_version = result.scalar_one_or_none()
        if new_version is None:
            raise OptimisticLockConflict(str(rule.rule_id))

        await self._session.refresh(row)
        _replace_children(row, rule)
        await self._session.flush()
        rule._version = new_version

    async def find_by_id(
        self, rule_id: DetectionRuleId, tenant_id: TenantId
    ) -> DetectionRule | None:
        stmt = select(DetectionRuleModel).where(
            DetectionRuleModel.id == rule_id.value,
            DetectionRuleModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_by_key(
        self, key: RuleKey, tenant_id: TenantId
    ) -> DetectionRule | None:
        stmt = select(DetectionRuleModel).where(
            DetectionRuleModel.rule_key == key.value,
            DetectionRuleModel.tenant_id == tenant_id.value,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _to_domain(row) if row is not None else None

    async def find_active_by_tenant(self, tenant_id: TenantId) -> list[DetectionRule]:
        stmt = (
            select(DetectionRuleModel)
            .where(
                DetectionRuleModel.tenant_id == tenant_id.value,
                DetectionRuleModel.lifecycle_state == RuleLifecycleState.ACTIVE.value,
            )
            .order_by(DetectionRuleModel.updated_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_by_lifecycle_state(
        self, tenant_id: TenantId, state: RuleLifecycleState
    ) -> list[DetectionRule]:
        stmt = (
            select(DetectionRuleModel)
            .where(
                DetectionRuleModel.tenant_id == tenant_id.value,
                DetectionRuleModel.lifecycle_state == state.value,
            )
            .order_by(DetectionRuleModel.updated_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_by_telemetry_source(
        self, tenant_id: TenantId, source_id: str
    ) -> list[DetectionRule]:
        stmt = (
            select(DetectionRuleModel)
            .where(
                DetectionRuleModel.tenant_id == tenant_id.value,
                DetectionRuleModel.telemetry_sources_json.contains(
                    [{"source_id": source_id}]
                ),
            )
            .order_by(DetectionRuleModel.updated_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]

    async def find_by_attack_technique(
        self, tenant_id: TenantId, technique_id: str
    ) -> list[DetectionRule]:
        stmt = (
            select(DetectionRuleModel)
            .join(
                MitreAttackMappingModel,
                MitreAttackMappingModel.rule_id == DetectionRuleModel.id,
            )
            .where(
                DetectionRuleModel.tenant_id == tenant_id.value,
                MitreAttackMappingModel.tenant_id == tenant_id.value,
                MitreAttackMappingModel.technique == technique_id,
            )
            .order_by(DetectionRuleModel.updated_at.desc())
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().unique().all()]

    async def list_by_tenant(
        self, tenant_id: TenantId, *, limit: int = 100, offset: int = 0
    ) -> list[DetectionRule]:
        stmt = (
            select(DetectionRuleModel)
            .where(DetectionRuleModel.tenant_id == tenant_id.value)
            .order_by(DetectionRuleModel.updated_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_to_domain(row) for row in result.scalars().all()]
