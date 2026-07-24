"""Detection rule command dataclasses (CQRS write side)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from detection.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class AuthorDetectionRule:
    tenant_id: TenantId
    rule_key: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    author_identity: str
    logic: dict[str, Any]
    telemetry_sources: list[dict[str, str | None]] = field(default_factory=list)
    asset_scope: dict[str, list[str]] | None = None
    throttle: dict[str, int] | None = None
    tags: list[str] = field(default_factory=list)
    external_refs: list[dict[str, str]] = field(default_factory=list)
    test_cases: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PublishRuleVersion:
    tenant_id: TenantId
    rule_id: UUID
    change_summary: str
    published_by: str
    semver: str | None = None
    logic: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class PromoteRule:
    tenant_id: TenantId
    rule_id: UUID
    target_state: str
    actor: str
    reviewer_identity: str | None = None


@dataclass(frozen=True, slots=True)
class DemoteRule:
    tenant_id: TenantId
    rule_id: UUID
    target_state: str
    actor: str
    reason: str


@dataclass(frozen=True, slots=True)
class RunRuleTestSuite:
    tenant_id: TenantId
    rule_id: UUID


@dataclass(frozen=True, slots=True)
class ValidateRule:
    tenant_id: TenantId
    rule_id: UUID


@dataclass(frozen=True, slots=True)
class UpdateRule:
    tenant_id: TenantId
    rule_id: UUID
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    confidence: str | None = None
    throttle: dict[str, int] | None = None
    tags: list[str] | None = None
    test_cases: list[dict[str, Any]] | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class UpsertTestCase:
    tenant_id: TenantId
    rule_id: UUID
    name: str
    input_payload: dict[str, Any]
    expected_match: bool
    actor: str
    description: str | None = None
