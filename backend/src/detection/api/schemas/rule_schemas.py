"""Detection rule API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RuleConditionSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    field: str
    operator: str
    value: str | int | float | bool | list[str] | None = None
    connector: str | None = None
    children: list[RuleConditionSchema] = Field(default_factory=list)


class RuleLogicSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    logic_type: str
    conditions: list[RuleConditionSchema]
    sequence_window_seconds: int | None = None
    aggregation_field: str | None = None
    threshold_count: int | None = None
    threshold_window_seconds: int | None = None
    correlation_refs: list[str] = Field(default_factory=list)
    normalized_field_refs: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "logic_type": self.logic_type,
            "conditions": [c.model_dump() for c in self.conditions],
            "sequence_window_seconds": self.sequence_window_seconds,
            "aggregation_field": self.aggregation_field,
            "threshold_count": self.threshold_count,
            "threshold_window_seconds": self.threshold_window_seconds,
            "correlation_refs": list(self.correlation_refs),
            "normalized_field_refs": list(self.normalized_field_refs),
        }


class TelemetrySourceRefSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    source_id: str
    source_type: str | None = None


class AssetScopeSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    asset_types: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class ThrottleSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    window_seconds: int
    max_count: int


class ExternalRuleRefSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    system: str
    external_id: str


class TestCaseRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    name: str
    input_payload: dict[str, Any]
    expected_match: bool = True
    description: str | None = None


class AuthorDetectionRuleRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    rule_key: str
    title: str
    description: str = ""
    category: str
    severity: str
    confidence: str
    logic: RuleLogicSchema
    telemetry_sources: list[TelemetrySourceRefSchema] = Field(default_factory=list)
    asset_scope: AssetScopeSchema | None = None
    throttle: ThrottleSchema | None = None
    tags: list[str] = Field(default_factory=list)
    external_refs: list[ExternalRuleRefSchema] = Field(default_factory=list)
    test_cases: list[TestCaseRequest] = Field(default_factory=list)


class UpdateRuleRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    title: str | None = None
    description: str | None = None
    severity: str | None = None
    confidence: str | None = None
    throttle: ThrottleSchema | None = None
    tags: list[str] | None = None
    test_cases: list[TestCaseRequest] | None = None


class PublishRuleVersionRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    change_summary: str
    semver: str | None = None
    logic: RuleLogicSchema | None = None


class PromoteRuleRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    target_state: str
    reviewer_identity: str | None = None


class DemoteRuleRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    target_state: str
    reason: str


class DetectionRuleResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    rule_id: UUID
    tenant_id: UUID
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
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: object) -> DetectionRuleResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        data["rule_id"] = UUID(str(data["rule_id"]))
        data["tenant_id"] = UUID(str(data["tenant_id"]))
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        data["updated_at"] = datetime.fromisoformat(str(data["updated_at"]))
        return cls(**data)


class ListRulesResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    items: list[DetectionRuleResponse]
    total: int
    limit: int
    offset: int


class ValidateRuleResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    rule_id: UUID
    valid: bool


class RuleTestSuiteResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    rule_id: UUID
    results: list[dict[str, Any]]
