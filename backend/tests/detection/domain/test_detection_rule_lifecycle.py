"""DetectionRule aggregate lifecycle, gates, and domain event tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.domain.entities.rule_entities import RuleVersion
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
    RuleVersionImmutable,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    RuleLifecycleState,
    RuleLogicType,
    RuleSeverity,
)
from detection.domain.value_objects.enums import TestResultStatus as RuleTestResultStatus
from detection.domain.value_objects.keys import (
    FalsePositiveProfile,
    MitreTechniqueId,
    ReviewerRef,
    RuleSemVer,
    RuleTag,
    ThrottlePolicy,
)
from tests.detection.conftest import advance, make_logic, make_rule


class TestCreate:
    def test_create_starts_in_draft(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now)
        assert rule.lifecycle_state == RuleLifecycleState.DRAFT
        assert rule.version == 1

    def test_create_emits_created_event(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now)
        events = rule.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], DetectionRuleCreated)
        assert events[0].rule_key == "aivar.suspicious_cmd"
        assert events[0].severity == "High"

    def test_create_rejects_blank_title(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="title"):
            make_rule(tenant_id=tenant_id, now=now, title="   ")

    def test_create_validates_logic(self, tenant_id, now) -> None:
        with pytest.raises(InvalidArgument, match="Sequence"):
            make_rule(
                tenant_id=tenant_id,
                now=now,
                logic=make_logic(
                    logic_type=RuleLogicType.SEQUENCE,
                    sequence_window=timedelta(seconds=0),
                ),
            )


class TestPublishVersion:
    def test_publish_defaults_to_0_1_0(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        snap = rule.publish_version(
            tenant_id=tenant_id,
            semver=None,
            change_summary="initial",
            published_by="alice",
            logic=None,
            now=advance(now, minutes=1),
        )
        assert str(snap.semver) == "0.1.0"
        assert len(rule.versions) == 1

    def test_publish_emits_event(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="v1",
            published_by="alice",
            logic=None,
            now=now,
        )
        events = rule.pop_events()
        assert any(isinstance(e, DetectionRuleVersionPublished) for e in events)
        published = next(e for e in events if isinstance(e, DetectionRuleVersionPublished))
        assert published.semver == "1.0.0"

    def test_publish_auto_bumps_patch(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(0, 1, 0),
            change_summary="first",
            published_by="alice",
            logic=None,
            now=now,
        )
        snap = rule.publish_version(
            tenant_id=tenant_id,
            semver=None,
            change_summary="second",
            published_by="alice",
            logic=None,
            now=advance(now, minutes=1),
        )
        assert str(snap.semver) == "0.1.1"

    def test_publish_rejects_duplicate_semver(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="first",
            published_by="alice",
            logic=None,
            now=now,
        )
        with pytest.raises(InvalidArgument, match="already published"):
            rule.publish_version(
                tenant_id=tenant_id,
                semver=RuleSemVer(1, 0, 0),
                change_summary="dup",
                published_by="alice",
                logic=None,
                now=advance(now, minutes=1),
            )

    def test_published_version_is_immutable(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        snap = rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="locked",
            published_by="alice",
            logic=None,
            now=now,
        )
        with pytest.raises(RuleVersionImmutable):
            snap.assert_immutable()

    def test_publish_updates_current_logic(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        new_logic = make_logic()
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(0, 2, 0),
            change_summary="logic update",
            published_by="alice",
            logic=new_logic,
            now=now,
        )
        assert rule.current_logic is new_logic

    def test_publish_rejected_when_archived(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.archive(tenant_id=tenant_id, actor="alice", reason="done", now=now)
        with pytest.raises(InvalidStateTransition):
            rule.publish_version(
                tenant_id=tenant_id,
                semver=None,
                change_summary="nope",
                published_by="alice",
                logic=None,
                now=advance(now, minutes=1),
            )

    def test_publish_tenant_mismatch(self, tenant_id, other_tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(TenantMismatch):
            rule.publish_version(
                tenant_id=other_tenant_id,
                semver=None,
                change_summary="x",
                published_by="alice",
                logic=None,
                now=now,
            )


class TestPromotePath:
    def _prepare_for_tested(self, rule, tenant_id, now) -> None:
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="positive",
            input_payload={"process.name": "cmd.exe"},
            expected_match=True,
            actor="alice",
            now=now,
        )
        rule.run_test_suite(tenant_id=tenant_id, now=now)
        rule.pop_events()

    def test_promote_draft_to_under_review(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
            reviewer=ReviewerRef("bob"),
        )
        assert rule.lifecycle_state == RuleLifecycleState.UNDER_REVIEW
        assert rule.reviewer is not None
        assert rule.reviewer.identity == "bob"

    def test_promote_under_review_to_tested_requires_passing_tests(
        self, tenant_id, now
    ) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
        )
        with pytest.raises(RulePromotionBlocked, match="RuleTestCase"):
            rule.promote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.TESTED,
                actor="alice",
                now=advance(now, minutes=1),
            )

    def test_promote_to_tested_with_passing_suite(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
        )
        self._prepare_for_tested(rule, tenant_id, now)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.TESTED,
            actor="alice",
            now=advance(now, minutes=1),
        )
        assert rule.lifecycle_state == RuleLifecycleState.TESTED

    def test_promote_to_tested_blocked_on_fail(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
        )
        case = rule.upsert_test_case(
            tenant_id=tenant_id,
            name="expect_no_match",
            input_payload={"process.name": "cmd.exe"},
            expected_match=False,
            actor="alice",
            now=now,
        )
        rule.record_test_result(
            tenant_id=tenant_id,
            test_case_id=case.test_case_id,
            status=RuleTestResultStatus.FAIL,
            duration_ms=1,
            now=now,
        )
        with pytest.raises(RulePromotionBlocked, match="passing"):
            rule.promote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.TESTED,
                actor="alice",
                now=advance(now, minutes=1),
            )

    def test_promote_tested_to_staged(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.TESTED
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.STAGED,
            actor="alice",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.STAGED

    def test_promote_to_active_requires_throttle(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.STAGED
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="v1",
            published_by="alice",
            logic=None,
            now=now,
        )
        with pytest.raises(RulePromotionBlocked, match="ThrottlePolicy"):
            rule.promote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.ACTIVE,
                actor="alice",
                now=advance(now, minutes=1),
            )

    def test_promote_to_active_requires_published_version(self, tenant_id, now) -> None:
        rule = make_rule(
            tenant_id=tenant_id,
            now=now,
            pop_events=True,
            throttle_policy=ThrottlePolicy(60, 5),
        )
        rule.lifecycle_state = RuleLifecycleState.STAGED
        with pytest.raises(RulePromotionBlocked, match="published"):
            rule.promote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.ACTIVE,
                actor="alice",
                now=now,
            )

    def test_full_path_draft_to_active(self, tenant_id, now) -> None:
        rule = make_rule(
            tenant_id=tenant_id,
            now=now,
            pop_events=True,
            throttle_policy=ThrottlePolicy(300, 10),
        )
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
        )
        self._prepare_for_tested(rule, tenant_id, now)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.TESTED,
            actor="alice",
            now=advance(now, minutes=1),
        )
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.STAGED,
            actor="alice",
            now=advance(now, minutes=2),
        )
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="release",
            published_by="alice",
            logic=None,
            now=advance(now, minutes=3),
        )
        rule.pop_events()
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.ACTIVE,
            actor="alice",
            now=advance(now, minutes=4),
        )
        assert rule.lifecycle_state == RuleLifecycleState.ACTIVE
        events = rule.pop_events()
        assert any(isinstance(e, DetectionRulePromoted) for e in events)
        assert any(isinstance(e, DetectionRuleActivated) for e in events)

    def test_invalid_forward_skip_blocked(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            rule.promote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.ACTIVE,
                actor="alice",
                now=now,
            )

    def test_promote_emits_promoted_event(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            now=now,
        )
        events = rule.pop_events()
        assert len(events) == 1
        assert isinstance(events[0], DetectionRulePromoted)
        assert events[0].previous_state == "Draft"
        assert events[0].new_state == "UnderReview"


class TestDemote:
    def test_demote_active_to_staged(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.ACTIVE
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.STAGED,
            actor="alice",
            reason="hotfix needed",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.STAGED
        events = rule.pop_events()
        assert isinstance(events[0], DetectionRuleDemoted)
        assert events[0].reason == "hotfix needed"

    def test_demote_staged_to_tested(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.STAGED
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.TESTED,
            actor="alice",
            reason="retest",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.TESTED

    def test_demote_staged_to_under_review(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.STAGED
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.UNDER_REVIEW,
            actor="alice",
            reason="needs review",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.UNDER_REVIEW

    def test_demote_tested_to_draft(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.TESTED
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.DRAFT,
            actor="alice",
            reason="rewrite",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.DRAFT

    def test_demote_under_review_to_draft(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.UNDER_REVIEW
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.DRAFT,
            actor="alice",
            reason="back",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.DRAFT

    def test_demote_requires_reason(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.ACTIVE
        with pytest.raises(InvalidArgument, match="reason"):
            rule.demote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.STAGED,
                actor="alice",
                reason="  ",
                now=now,
            )

    def test_demote_invalid_path(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            rule.demote(
                tenant_id=tenant_id,
                target=RuleLifecycleState.STAGED,
                actor="alice",
                reason="nope",
                now=now,
            )

    def test_re_promote_after_demotion(self, tenant_id, now) -> None:
        rule = make_rule(
            tenant_id=tenant_id,
            now=now,
            pop_events=True,
            throttle_policy=ThrottlePolicy(60, 3),
        )
        rule.lifecycle_state = RuleLifecycleState.ACTIVE
        rule.publish_version(
            tenant_id=tenant_id,
            semver=RuleSemVer(1, 0, 0),
            change_summary="v1",
            published_by="alice",
            logic=None,
            now=now,
        )
        rule.demote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.STAGED,
            actor="alice",
            reason="pause",
            now=advance(now, minutes=1),
        )
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.ACTIVE,
            actor="alice",
            now=advance(now, minutes=2),
        )
        assert rule.lifecycle_state == RuleLifecycleState.ACTIVE


class TestDeprecateAndArchive:
    def test_deprecate_from_active(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.ACTIVE
        rule.deprecate(
            tenant_id=tenant_id, actor="alice", reason="superseded", now=now
        )
        assert rule.lifecycle_state == RuleLifecycleState.DEPRECATED
        events = rule.pop_events()
        assert isinstance(events[0], DetectionRuleDeprecated)

    def test_deprecate_not_from_draft(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidStateTransition):
            rule.deprecate(tenant_id=tenant_id, actor="alice", reason="x", now=now)

    def test_deprecate_requires_reason(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.ACTIVE
        with pytest.raises(InvalidArgument, match="reason"):
            rule.deprecate(tenant_id=tenant_id, actor="alice", reason="", now=now)

    def test_archive_from_deprecated_via_promote(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.lifecycle_state = RuleLifecycleState.DEPRECATED
        rule.promote(
            tenant_id=tenant_id,
            target=RuleLifecycleState.ARCHIVED,
            actor="alice",
            now=now,
        )
        assert rule.lifecycle_state == RuleLifecycleState.ARCHIVED

    def test_archive_direct(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.archive(tenant_id=tenant_id, actor="alice", reason="cleanup", now=now)
        assert rule.lifecycle_state == RuleLifecycleState.ARCHIVED
        events = rule.pop_events()
        assert isinstance(events[0], DetectionRuleArchived)

    def test_archive_idempotent_blocked(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.archive(tenant_id=tenant_id, actor="alice", reason="once", now=now)
        with pytest.raises(InvalidStateTransition):
            rule.archive(
                tenant_id=tenant_id,
                actor="alice",
                reason="twice",
                now=advance(now, minutes=1),
            )

    def test_archive_requires_reason(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        with pytest.raises(InvalidArgument, match="reason"):
            rule.archive(tenant_id=tenant_id, actor="alice", reason=" ", now=now)


class TestTestSuiteAndMetadata:
    def test_upsert_test_case_emits_event(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="case1",
            input_payload={"process.name": "cmd.exe"},
            expected_match=True,
            actor="alice",
            now=now,
        )
        events = rule.pop_events()
        assert isinstance(events[0], RuleTestSuiteUpdated)
        assert events[0].test_case_count == 1

    def test_upsert_updates_existing_by_name(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="case1",
            input_payload={"process.name": "a"},
            expected_match=True,
            actor="alice",
            now=now,
        )
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="case1",
            input_payload={"process.name": "b"},
            expected_match=False,
            actor="alice",
            now=advance(now, minutes=1),
        )
        assert len(rule.test_cases) == 1
        assert rule.test_cases[0].input_payload["process.name"] == "b"

    def test_run_test_suite_pass(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="pos",
            input_payload={"process.name": "cmd.exe"},
            expected_match=True,
            actor="alice",
            now=now,
        )
        results = rule.run_test_suite(tenant_id=tenant_id, now=now)
        assert len(results) == 1
        assert results[0].status == RuleTestResultStatus.PASS
        events = rule.pop_events()
        assert any(isinstance(e, RuleTestResultRecorded) for e in events)

    def test_run_test_suite_error_on_missing_field(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.upsert_test_case(
            tenant_id=tenant_id,
            name="missing",
            input_payload={},
            expected_match=True,
            actor="alice",
            now=now,
        )
        results = rule.run_test_suite(tenant_id=tenant_id, now=now)
        assert results[0].status == RuleTestResultStatus.ERROR

    def test_set_mitre_mappings(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.set_mitre_mappings(
            tenant_id=tenant_id,
            mappings=[("Execution", MitreTechniqueId("T1059"), MitreTechniqueId("T1059.001"))],
            actor="alice",
            now=now,
        )
        assert len(rule.mitre_mappings) == 1
        events = rule.pop_events()
        assert isinstance(events[0], MitreAttackMappingUpdated)

    def test_update_false_positive_profile(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        profile = FalsePositiveProfile(fp_rate=0.1, total_findings=100, fp_count=10)
        rule.update_false_positive_profile(
            tenant_id=tenant_id, profile=profile, now=now
        )
        assert rule.false_positive_profile is profile
        events = rule.pop_events()
        assert isinstance(events[0], FalsePositiveProfileUpdated)

    def test_update_metadata(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.update_metadata(
            tenant_id=tenant_id,
            now=now,
            title="Updated title",
            severity=RuleSeverity.CRITICAL,
            tags=[RuleTag("endpoint")],
            throttle_policy=ThrottlePolicy(120, 2),
        )
        assert rule.title == "Updated title"
        assert rule.severity == RuleSeverity.CRITICAL
        assert rule.throttle_policy is not None

    def test_update_metadata_blocked_when_archived(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.archive(tenant_id=tenant_id, actor="alice", reason="done", now=now)
        with pytest.raises(InvalidStateTransition):
            rule.update_metadata(tenant_id=tenant_id, now=now, title="nope")

    def test_validate_logic(self, tenant_id, now) -> None:
        rule = make_rule(tenant_id=tenant_id, now=now, pop_events=True)
        rule.validate_logic()

    def test_rule_version_entity_requires_summary(self, tenant_id, now) -> None:
        from detection.domain.value_objects.identifiers import RuleVersionId

        with pytest.raises(InvalidArgument, match="change_summary"):
            RuleVersion(
                version_id=RuleVersionId.generate(),
                semver=RuleSemVer(1, 0, 0),
                logic=make_logic(),
                change_summary="  ",
                published_at=now,
                published_by="alice",
            )
