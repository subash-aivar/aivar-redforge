"""DetectionRule aggregate root — versioned detection logic artifact."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid7

from detection.domain.entities.rule_entities import (
    MitreAttackMapping,
    RuleTestCase,
    RuleTestResult,
    RuleVersion,
)
from detection.domain.events.rule_events import (
    DetectionRuleActivated,
    DetectionRuleArchived,
    DetectionRuleCreated,
    DetectionRuleDemoted,
    DetectionRuleDeprecated,
    DetectionRulePromoted,
    DetectionRuleVersionPublished,
    FalsePositiveProfileUpdated,
    MitreAttackMappingUpdated,
    RuleTestResultRecorded,
    RuleTestSuiteUpdated,
)
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    RulePromotionBlocked,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    RuleLifecycleState,
    TestResultStatus,
)
from detection.domain.value_objects.identifiers import (
    MitreAttackMappingId,
    RuleTestCaseId,
    RuleTestResultId,
    RuleVersionId,
)
from detection.domain.value_objects.keys import RuleSemVer

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import (
        RuleCategory,
        RuleConfidence,
        RuleSeverity,
    )
    from detection.domain.value_objects.identifiers import DetectionRuleId, TenantId
    from detection.domain.value_objects.keys import (
        AssetScopeFilter,
        AuthorRef,
        ExternalRuleRef,
        FalsePositiveProfile,
        MitreTechniqueId,
        ReviewerRef,
        RuleKey,
        RuleTag,
        TelemetrySourceRef,
        ThrottlePolicy,
    )
    from detection.domain.value_objects.rule_logic import RuleLogic

_FORWARD: dict[RuleLifecycleState, frozenset[RuleLifecycleState]] = {
    RuleLifecycleState.DRAFT: frozenset({RuleLifecycleState.UNDER_REVIEW}),
    RuleLifecycleState.UNDER_REVIEW: frozenset({RuleLifecycleState.TESTED}),
    RuleLifecycleState.TESTED: frozenset({RuleLifecycleState.STAGED}),
    RuleLifecycleState.STAGED: frozenset({RuleLifecycleState.ACTIVE}),
    RuleLifecycleState.ACTIVE: frozenset({RuleLifecycleState.DEPRECATED}),
    RuleLifecycleState.DEPRECATED: frozenset({RuleLifecycleState.ARCHIVED}),
    RuleLifecycleState.ARCHIVED: frozenset(),
}

# Demotion / hotfix paths
_DEMOTION: dict[RuleLifecycleState, frozenset[RuleLifecycleState]] = {
    RuleLifecycleState.ACTIVE: frozenset({RuleLifecycleState.STAGED}),
    RuleLifecycleState.STAGED: frozenset(
        {RuleLifecycleState.TESTED, RuleLifecycleState.UNDER_REVIEW}
    ),
    RuleLifecycleState.TESTED: frozenset(
        {RuleLifecycleState.UNDER_REVIEW, RuleLifecycleState.DRAFT}
    ),
    RuleLifecycleState.UNDER_REVIEW: frozenset({RuleLifecycleState.DRAFT}),
}


class DetectionRule:
    """Canonical detection logic artifact with versioning and test suite."""

    __slots__ = (
        "_pending_events",
        "_version",
        "asset_scope",
        "author",
        "category",
        "confidence",
        "created_at",
        "current_logic",
        "description",
        "external_refs",
        "false_positive_profile",
        "lifecycle_state",
        "mitre_mappings",
        "reviewer",
        "rule_id",
        "rule_key",
        "severity",
        "tags",
        "telemetry_sources",
        "tenant_id",
        "test_cases",
        "test_results",
        "throttle_policy",
        "title",
        "updated_at",
        "versions",
    )

    def __init__(
        self,
        rule_id: DetectionRuleId,
        tenant_id: TenantId,
        rule_key: RuleKey,
        title: str,
        description: str,
        category: RuleCategory,
        severity: RuleSeverity,
        confidence: RuleConfidence,
        author: AuthorRef,
        lifecycle_state: RuleLifecycleState,
        current_logic: RuleLogic,
        created_at: datetime,
        updated_at: datetime,
        *,
        versions: list[RuleVersion] | None = None,
        test_cases: list[RuleTestCase] | None = None,
        test_results: list[RuleTestResult] | None = None,
        mitre_mappings: list[MitreAttackMapping] | None = None,
        telemetry_sources: list[TelemetrySourceRef] | None = None,
        asset_scope: AssetScopeFilter | None = None,
        throttle_policy: ThrottlePolicy | None = None,
        false_positive_profile: FalsePositiveProfile | None = None,
        reviewer: ReviewerRef | None = None,
        tags: list[RuleTag] | None = None,
        external_refs: list[ExternalRuleRef] | None = None,
        row_version: int = 1,
    ) -> None:
        if not title.strip():
            raise InvalidArgument("DetectionRule", "title required")
        self.rule_id = rule_id
        self.tenant_id = tenant_id
        self.rule_key = rule_key
        self.title = title.strip()
        self.description = description
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.author = author
        self.lifecycle_state = lifecycle_state
        self.current_logic = current_logic
        self.created_at = created_at
        self.updated_at = updated_at
        self.versions = list(versions or [])
        self.test_cases = list(test_cases or [])
        self.test_results = list(test_results or [])
        self.mitre_mappings = list(mitre_mappings or [])
        self.telemetry_sources = list(telemetry_sources or [])
        self.asset_scope = asset_scope
        self.throttle_policy = throttle_policy
        self.false_positive_profile = false_positive_profile
        self.reviewer = reviewer
        self.tags = list(tags or [])
        self.external_refs = list(external_refs or [])
        self._version = row_version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @classmethod
    def create(
        cls,
        *,
        tenant_id: TenantId,
        rule_key: RuleKey,
        title: str,
        description: str,
        category: RuleCategory,
        severity: RuleSeverity,
        confidence: RuleConfidence,
        author: AuthorRef,
        logic: RuleLogic,
        now: datetime,
        rule_id: DetectionRuleId | None = None,
        telemetry_sources: list[TelemetrySourceRef] | None = None,
        asset_scope: AssetScopeFilter | None = None,
        throttle_policy: ThrottlePolicy | None = None,
        tags: list[RuleTag] | None = None,
        external_refs: list[ExternalRuleRef] | None = None,
    ) -> DetectionRule:
        from detection.domain.value_objects.identifiers import DetectionRuleId

        rid = rule_id or DetectionRuleId.generate()
        logic.validate()
        rule = cls(
            rule_id=rid,
            tenant_id=tenant_id,
            rule_key=rule_key,
            title=title,
            description=description,
            category=category,
            severity=severity,
            confidence=confidence,
            author=author,
            lifecycle_state=RuleLifecycleState.DRAFT,
            current_logic=logic,
            created_at=now,
            updated_at=now,
            telemetry_sources=telemetry_sources,
            asset_scope=asset_scope,
            throttle_policy=throttle_policy,
            tags=tags,
            external_refs=external_refs,
        )
        rule._emit(
            DetectionRuleCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(rid),
                aggregate_type="DetectionRule",
                rule_key=str(rule_key),
                category=category.value,
                severity=severity.value,
            )
        )
        return rule

    def publish_version(
        self,
        *,
        tenant_id: TenantId,
        semver: RuleSemVer | None,
        change_summary: str,
        published_by: str,
        logic: RuleLogic | None,
        now: datetime,
    ) -> RuleVersion:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state == RuleLifecycleState.ARCHIVED:
            raise InvalidStateTransition(
                self.lifecycle_state.value, "publish_version"
            )
        next_logic = logic or self.current_logic
        next_logic.validate()
        if semver is None:
            if self.versions:
                last = max(
                    self.versions,
                    key=lambda v: (v.semver.major, v.semver.minor, v.semver.patch),
                )
                semver = last.semver.bump_patch()
            else:
                semver = RuleSemVer(0, 1, 0)
        if any(v.semver == semver for v in self.versions):
            raise InvalidArgument("RuleVersion", f"version {semver} already published")

        snap = RuleVersion(
            version_id=RuleVersionId.generate(),
            semver=semver,
            logic=next_logic,
            change_summary=change_summary,
            published_at=now,
            published_by=published_by,
        )
        self.versions.append(snap)
        self.current_logic = next_logic
        self._mutate(now)
        self._emit(
            DetectionRuleVersionPublished(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                semver=str(semver),
                published_by=published_by,
                change_summary=change_summary,
            )
        )
        return snap

    def promote(
        self,
        *,
        tenant_id: TenantId,
        target: RuleLifecycleState,
        actor: str,
        now: datetime,
        reviewer: ReviewerRef | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        allowed = _FORWARD.get(self.lifecycle_state, frozenset())
        # Allow Staged → Active re-promotion after demotion
        if (
            self.lifecycle_state == RuleLifecycleState.STAGED
            and target == RuleLifecycleState.ACTIVE
        ):
            pass
        elif target not in allowed:
            raise InvalidStateTransition(self.lifecycle_state.value, target.value)

        if target == RuleLifecycleState.TESTED:
            self._assert_tests_passing()
        if target == RuleLifecycleState.ACTIVE:
            if self.throttle_policy is None:
                raise RulePromotionBlocked("ThrottlePolicy required before Active (ADR-M28-005)")
            if not self.versions:
                raise RulePromotionBlocked("at least one published RuleVersion required")

        previous = self.lifecycle_state
        self.lifecycle_state = target
        if reviewer is not None:
            self.reviewer = reviewer
        self._mutate(now)
        self._emit(
            DetectionRulePromoted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                previous_state=previous.value,
                new_state=target.value,
                actor=actor,
            )
        )
        if target == RuleLifecycleState.ACTIVE:
            current = self.versions[-1] if self.versions else None
            self._emit(
                DetectionRuleActivated(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.rule_id),
                    aggregate_type="DetectionRule",
                    semver=str(current.semver) if current else "0.0.0",
                    actor=actor,
                )
            )

    def demote(
        self,
        *,
        tenant_id: TenantId,
        target: RuleLifecycleState,
        actor: str,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("demote", "reason required")
        allowed = _DEMOTION.get(self.lifecycle_state, frozenset())
        if target not in allowed:
            raise InvalidStateTransition(self.lifecycle_state.value, target.value)
        previous = self.lifecycle_state
        self.lifecycle_state = target
        self._mutate(now)
        self._emit(
            DetectionRuleDemoted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                previous_state=previous.value,
                new_state=target.value,
                actor=actor,
                reason=reason.strip(),
            )
        )

    def deprecate(
        self, *, tenant_id: TenantId, actor: str, reason: str, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state != RuleLifecycleState.ACTIVE:
            raise InvalidStateTransition(self.lifecycle_state.value, "Deprecated")
        if not reason.strip():
            raise InvalidArgument("deprecate", "reason required")
        self.lifecycle_state = RuleLifecycleState.DEPRECATED
        self._mutate(now)
        self._emit(
            DetectionRuleDeprecated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                actor=actor,
                reason=reason.strip(),
            )
        )

    def archive(
        self, *, tenant_id: TenantId, actor: str, reason: str, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("archive", "reason required")
        if self.lifecycle_state == RuleLifecycleState.ARCHIVED:
            raise InvalidStateTransition("Archived", "Archived")
        self.lifecycle_state = RuleLifecycleState.ARCHIVED
        self._mutate(now)
        self._emit(
            DetectionRuleArchived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                actor=actor,
                reason=reason.strip(),
            )
        )

    def upsert_test_case(
        self,
        *,
        tenant_id: TenantId,
        name: str,
        input_payload: dict[str, Any],
        expected_match: bool,
        actor: str,
        now: datetime,
        description: str | None = None,
        test_case_id: RuleTestCaseId | None = None,
    ) -> RuleTestCase:
        self._assert_tenant(tenant_id)
        existing = next((t for t in self.test_cases if t.name == name), None)
        if existing is not None:
            existing.input_payload = input_payload
            existing.expected_match = expected_match
            existing.description = description
            case = existing
        else:
            case = RuleTestCase(
                test_case_id=test_case_id or RuleTestCaseId.generate(),
                name=name,
                input_payload=input_payload,
                expected_match=expected_match,
                description=description,
            )
            self.test_cases.append(case)
        self._mutate(now)
        self._emit(
            RuleTestSuiteUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                test_case_count=len(self.test_cases),
                actor=actor,
            )
        )
        return case

    def record_test_result(
        self,
        *,
        tenant_id: TenantId,
        test_case_id: RuleTestCaseId,
        status: TestResultStatus,
        duration_ms: int,
        now: datetime,
        message: str | None = None,
    ) -> RuleTestResult:
        self._assert_tenant(tenant_id)
        if not any(t.test_case_id == test_case_id for t in self.test_cases):
            raise InvalidArgument("RuleTestResult", "unknown test_case_id")
        current = str(self.versions[-1].semver) if self.versions else None
        result = RuleTestResult(
            result_id=RuleTestResultId.generate(),
            test_case_id=test_case_id,
            status=status,
            duration_ms=duration_ms,
            recorded_at=now,
            message=message,
            rule_version=current,
        )
        self.test_results.append(result)
        self._mutate(now)
        self._emit(
            RuleTestResultRecorded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                test_case_id=str(test_case_id),
                status=status.value,
                duration_ms=duration_ms,
            )
        )
        return result

    def run_test_suite(
        self, *, tenant_id: TenantId, now: datetime
    ) -> list[RuleTestResult]:
        """Evaluate test cases against current logic structure (no telemetry).

        Phase 1 validation only: structural presence of expected fields in
        input payload vs normalized field refs. Does not execute queries.
        """
        self._assert_tenant(tenant_id)
        results: list[RuleTestResult] = []
        required = {ref.path for ref in self.current_logic.normalized_field_refs}
        for case in self.test_cases:
            missing = [p for p in required if p not in case.input_payload]
            if missing:
                status = TestResultStatus.ERROR
                message = f"missing fields: {', '.join(missing)}"
                matched = False
            else:
                # Structural match proxy: presence of all fields => "match candidate"
                matched = True
                status = (
                    TestResultStatus.PASS
                    if matched == case.expected_match
                    else TestResultStatus.FAIL
                )
                message = None
            results.append(
                self.record_test_result(
                    tenant_id=tenant_id,
                    test_case_id=case.test_case_id,
                    status=status,
                    duration_ms=0,
                    now=now,
                    message=message,
                )
            )
        return results

    def set_mitre_mappings(
        self,
        *,
        tenant_id: TenantId,
        mappings: list[tuple[str, MitreTechniqueId, MitreTechniqueId | None]],
        actor: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.mitre_mappings = [
            MitreAttackMapping(
                mapping_id=MitreAttackMappingId.generate(),
                tactic=tactic,
                technique=technique,
                sub_technique=sub,
            )
            for tactic, technique, sub in mappings
        ]
        self._mutate(now)
        self._emit(
            MitreAttackMappingUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                mapping_count=len(self.mitre_mappings),
                actor=actor,
            )
        )

    def update_false_positive_profile(
        self,
        *,
        tenant_id: TenantId,
        profile: FalsePositiveProfile,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.false_positive_profile = profile
        self._mutate(now)
        self._emit(
            FalsePositiveProfileUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.rule_id),
                aggregate_type="DetectionRule",
                fp_rate=profile.fp_rate,
                total_findings=profile.total_findings,
                fp_count=profile.fp_count,
            )
        )

    def update_metadata(
        self,
        *,
        tenant_id: TenantId,
        now: datetime,
        title: str | None = None,
        description: str | None = None,
        severity: RuleSeverity | None = None,
        confidence: RuleConfidence | None = None,
        throttle_policy: ThrottlePolicy | None = None,
        tags: list[RuleTag] | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state == RuleLifecycleState.ARCHIVED:
            raise InvalidStateTransition("Archived", "update")
        if title is not None:
            if not title.strip():
                raise InvalidArgument("title", "required")
            self.title = title.strip()
        if description is not None:
            self.description = description
        if severity is not None:
            self.severity = severity
        if confidence is not None:
            self.confidence = confidence
        if throttle_policy is not None:
            self.throttle_policy = throttle_policy
        if tags is not None:
            self.tags = list(tags)
        self._mutate(now)

    def validate_logic(self) -> None:
        self.current_logic.validate()

    def _assert_tests_passing(self) -> None:
        if not self.test_cases:
            raise RulePromotionBlocked("at least one RuleTestCase required for Tested")
        latest_by_case: dict[str, RuleTestResult] = {}
        for result in self.test_results:
            latest_by_case[str(result.test_case_id)] = result
        for case in self.test_cases:
            latest = latest_by_case.get(str(case.test_case_id))
            if latest is None or latest.status != TestResultStatus.PASS:
                raise RulePromotionBlocked(
                    f"test case '{case.name}' has no passing result"
                )

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1
