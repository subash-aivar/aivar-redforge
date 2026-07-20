"""Detection rule DTOs for API responses."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Self

from detection.domain.value_objects.keys import (
    AssetScopeFilter,
    ExternalRuleRef,
    FalsePositiveProfile,
    RuleTag,
    TelemetrySourceRef,
    ThrottlePolicy,
)
from detection.domain.value_objects.rule_logic import RuleCondition, RuleLogic

if TYPE_CHECKING:
    from detection.domain.aggregates.detection_rule import DetectionRule
    from detection.domain.entities.rule_entities import RuleTestResult


def _condition_to_dict(condition: RuleCondition) -> dict[str, Any]:
    return {
        "field": condition.field.path,
        "operator": condition.operator.value,
        "value": condition.value,
        "connector": condition.connector.value if condition.connector is not None else None,
        "children": [_condition_to_dict(child) for child in condition.children],
    }


def _logic_to_dict(logic: RuleLogic) -> dict[str, Any]:
    return {
        "logic_type": logic.logic_type.value,
        "conditions": [_condition_to_dict(c) for c in logic.conditions],
        "sequence_window_seconds": _timedelta_seconds(logic.sequence_window),
        "aggregation_field": logic.aggregation_field,
        "threshold_count": logic.threshold_count,
        "threshold_window_seconds": _timedelta_seconds(logic.threshold_window),
        "correlation_refs": [str(ref) for ref in logic.correlation_refs],
        "normalized_field_refs": [ref.path for ref in logic.normalized_field_refs],
    }


def _timedelta_seconds(value: timedelta | None) -> int | None:
    if value is None:
        return None
    return int(value.total_seconds())


def _telemetry_to_dict(refs: list[TelemetrySourceRef]) -> list[dict[str, Any]]:
    return [{"source_id": r.source_id, "source_type": r.source_type} for r in refs]


def _asset_scope_to_dict(scope: AssetScopeFilter | None) -> dict[str, Any] | None:
    if scope is None:
        return None
    return {"asset_types": list(scope.asset_types), "tags": list(scope.tags)}


def _throttle_to_dict(policy: ThrottlePolicy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {"window_seconds": policy.window_seconds, "max_count": policy.max_count}


def _fp_to_dict(profile: FalsePositiveProfile | None) -> dict[str, Any] | None:
    if profile is None:
        return None
    return {
        "fp_rate": profile.fp_rate,
        "total_findings": profile.total_findings,
        "fp_count": profile.fp_count,
        "last_calculated_at": profile.last_calculated_at,
    }


def _tags_to_list(tags: list[RuleTag]) -> list[str]:
    return [tag.value for tag in tags]


def _external_to_dict(refs: list[ExternalRuleRef]) -> list[dict[str, str]]:
    return [{"system": ref.system, "external_id": ref.external_id} for ref in refs]


@dataclass(frozen=True, slots=True)
class DetectionRuleDTO:
    rule_id: str
    tenant_id: str
    rule_key: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    lifecycle_state: str
    author_identity: str
    reviewer_identity: str | None
    current_logic: dict[str, Any]
    versions: list[dict[str, Any]]
    test_cases: list[dict[str, Any]]
    test_results: list[dict[str, Any]]
    mitre_mappings: list[dict[str, Any]]
    telemetry_sources: list[dict[str, Any]]
    asset_scope: dict[str, Any] | None
    throttle: dict[str, Any] | None
    false_positive_profile: dict[str, Any] | None
    tags: list[str]
    external_refs: list[dict[str, str]]
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_aggregate(cls, rule: DetectionRule) -> Self:
        return cls(
            rule_id=str(rule.rule_id),
            tenant_id=str(rule.tenant_id),
            rule_key=rule.rule_key.value,
            title=rule.title,
            description=rule.description,
            category=rule.category.value,
            severity=rule.severity.value,
            confidence=rule.confidence.value,
            lifecycle_state=rule.lifecycle_state.value,
            author_identity=rule.author.identity,
            reviewer_identity=rule.reviewer.identity if rule.reviewer is not None else None,
            current_logic=_logic_to_dict(rule.current_logic),
            versions=[
                {
                    "version_id": str(item.version_id),
                    "semver": str(item.semver),
                    "logic": _logic_to_dict(item.logic),
                    "change_summary": item.change_summary,
                    "published_at": item.published_at.isoformat(),
                    "published_by": item.published_by,
                }
                for item in rule.versions
            ],
            test_cases=[
                {
                    "test_case_id": str(item.test_case_id),
                    "name": item.name,
                    "input_payload": dict(item.input_payload),
                    "expected_match": item.expected_match,
                    "description": item.description,
                }
                for item in rule.test_cases
            ],
            test_results=[
                {
                    "result_id": str(item.result_id),
                    "test_case_id": str(item.test_case_id),
                    "status": item.status.value,
                    "duration_ms": item.duration_ms,
                    "recorded_at": item.recorded_at.isoformat(),
                    "message": item.message,
                    "rule_version": item.rule_version,
                }
                for item in rule.test_results
            ],
            mitre_mappings=[
                {
                    "mapping_id": str(item.mapping_id),
                    "tactic": item.tactic,
                    "technique": item.technique.value,
                    "sub_technique": (
                        item.sub_technique.value if item.sub_technique is not None else None
                    ),
                    "notes": item.notes,
                }
                for item in rule.mitre_mappings
            ],
            telemetry_sources=_telemetry_to_dict(rule.telemetry_sources),
            asset_scope=_asset_scope_to_dict(rule.asset_scope),
            throttle=_throttle_to_dict(rule.throttle_policy),
            false_positive_profile=_fp_to_dict(rule.false_positive_profile),
            tags=_tags_to_list(rule.tags),
            external_refs=_external_to_dict(rule.external_refs),
            created_at=rule.created_at.isoformat(),
            updated_at=rule.updated_at.isoformat(),
            version=rule.version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "tenant_id": self.tenant_id,
            "rule_key": self.rule_key,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "lifecycle_state": self.lifecycle_state,
            "author_identity": self.author_identity,
            "reviewer_identity": self.reviewer_identity,
            "current_logic": self.current_logic,
            "versions": list(self.versions),
            "test_cases": list(self.test_cases),
            "test_results": list(self.test_results),
            "mitre_mappings": list(self.mitre_mappings),
            "telemetry_sources": list(self.telemetry_sources),
            "asset_scope": self.asset_scope,
            "throttle": self.throttle,
            "false_positive_profile": self.false_positive_profile,
            "tags": list(self.tags),
            "external_refs": list(self.external_refs),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class RulePageDTO:
    items: list[DetectionRuleDTO]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class ValidateRuleResultDTO:
    rule_id: str
    valid: bool


@dataclass(frozen=True, slots=True)
class RuleTestSuiteResultDTO:
    rule_id: str
    results: list[dict[str, Any]]

    @classmethod
    def from_results(
        cls, rule_id: str, results: list[RuleTestResult]
    ) -> Self:
        return cls(
            rule_id=rule_id,
            results=[
                {
                    "result_id": str(item.result_id),
                    "test_case_id": str(item.test_case_id),
                    "status": item.status.value,
                    "duration_ms": item.duration_ms,
                    "recorded_at": item.recorded_at.isoformat(),
                    "message": item.message,
                    "rule_version": item.rule_version,
                }
                for item in results
            ],
        )
