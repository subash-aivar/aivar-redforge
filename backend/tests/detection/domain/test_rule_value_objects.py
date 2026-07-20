"""Value object validation tests for Detection Engineering Phase 1."""

from __future__ import annotations

import pytest

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.keys import (
    AssetScopeFilter,
    AuthorRef,
    ExternalRuleRef,
    FalsePositiveProfile,
    MitreTechniqueId,
    ReviewerRef,
    RuleKey,
    RuleSemVer,
    RuleTag,
    TelemetrySourceRef,
    ThrottlePolicy,
)


class TestRuleKey:
    def test_valid_namespace_rule_name(self) -> None:
        key = RuleKey("aivar.suspicious_cmd")
        assert str(key) == "aivar.suspicious_cmd"

    def test_allows_hyphen_in_rule_name(self) -> None:
        key = RuleKey("soc.lateral-movement")
        assert key.value == "soc.lateral-movement"

    def test_allows_digits_after_first_char(self) -> None:
        key = RuleKey("ns1.rule_2")
        assert key.value == "ns1.rule_2"

    def test_rejects_uppercase(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleKey"):
            RuleKey("Aivar.cmd")

    def test_rejects_missing_dot(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleKey"):
            RuleKey("aivar_cmd")

    def test_rejects_leading_underscore_namespace(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleKey"):
            RuleKey("_ns.rule")

    def test_rejects_empty(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleKey"):
            RuleKey("")

    def test_rejects_space(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleKey"):
            RuleKey("aivar.bad rule")


class TestRuleSemVer:
    def test_parse_valid(self) -> None:
        v = RuleSemVer.parse("1.2.3")
        assert (v.major, v.minor, v.patch) == (1, 2, 3)

    def test_str_round_trip(self) -> None:
        assert str(RuleSemVer(0, 1, 0)) == "0.1.0"

    def test_bump_patch(self) -> None:
        assert str(RuleSemVer(1, 0, 0).bump_patch()) == "1.0.1"

    def test_bump_minor_resets_patch(self) -> None:
        assert str(RuleSemVer(1, 2, 3).bump_minor()) == "1.3.0"

    def test_bump_major_resets_minor_patch(self) -> None:
        assert str(RuleSemVer(1, 2, 3).bump_major()) == "2.0.0"

    def test_rejects_negative_component(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleVersion"):
            RuleSemVer(-1, 0, 0)

    def test_parse_rejects_two_parts(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleVersion"):
            RuleSemVer.parse("1.0")

    def test_parse_rejects_non_numeric(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleVersion"):
            RuleSemVer.parse("1.0.x")


class TestThrottlePolicy:
    def test_valid(self) -> None:
        policy = ThrottlePolicy(window_seconds=300, max_count=5)
        assert policy.window_seconds == 300
        assert policy.max_count == 5

    def test_rejects_zero_window(self) -> None:
        with pytest.raises(InvalidArgument, match="ThrottlePolicy"):
            ThrottlePolicy(window_seconds=0, max_count=1)

    def test_rejects_negative_max_count(self) -> None:
        with pytest.raises(InvalidArgument, match="ThrottlePolicy"):
            ThrottlePolicy(window_seconds=60, max_count=0)


class TestFalsePositiveProfile:
    def test_valid_bounds(self) -> None:
        profile = FalsePositiveProfile(fp_rate=0.25, total_findings=100, fp_count=25)
        assert profile.fp_rate == 0.25

    def test_allows_zero_rate(self) -> None:
        profile = FalsePositiveProfile(fp_rate=0.0, total_findings=0, fp_count=0)
        assert profile.fp_count == 0

    def test_rejects_rate_above_one(self) -> None:
        with pytest.raises(InvalidArgument, match="FalsePositiveProfile"):
            FalsePositiveProfile(fp_rate=1.1, total_findings=10, fp_count=1)

    def test_rejects_negative_counts(self) -> None:
        with pytest.raises(InvalidArgument, match="FalsePositiveProfile"):
            FalsePositiveProfile(fp_rate=0.1, total_findings=-1, fp_count=0)

    def test_rejects_fp_exceeding_total(self) -> None:
        with pytest.raises(InvalidArgument, match="FalsePositiveProfile"):
            FalsePositiveProfile(fp_rate=0.5, total_findings=2, fp_count=3)


class TestRuleTag:
    def test_normalizes_lowercase(self) -> None:
        tag = RuleTag("  Lateral-Movement  ")
        assert tag.value == "lateral-movement"

    def test_rejects_empty(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleTag"):
            RuleTag("   ")

    def test_rejects_too_long(self) -> None:
        with pytest.raises(InvalidArgument, match="RuleTag"):
            RuleTag("x" * 65)


class TestExternalRuleRef:
    def test_valid(self) -> None:
        ref = ExternalRuleRef(system="sigma", external_id="proc_creation_cmd")
        assert ref.system == "sigma"

    def test_rejects_empty_system(self) -> None:
        with pytest.raises(InvalidArgument, match="ExternalRuleRef"):
            ExternalRuleRef(system="  ", external_id="id1")

    def test_rejects_empty_external_id(self) -> None:
        with pytest.raises(InvalidArgument, match="ExternalRuleRef"):
            ExternalRuleRef(system="sigma", external_id="")


class TestAuthorAndReviewerRefs:
    def test_author_required(self) -> None:
        with pytest.raises(InvalidArgument, match="AuthorRef"):
            AuthorRef("  ")

    def test_reviewer_required(self) -> None:
        with pytest.raises(InvalidArgument, match="ReviewerRef"):
            ReviewerRef("")

    def test_author_valid(self) -> None:
        assert AuthorRef("alice").identity == "alice"


class TestTelemetryAndScope:
    def test_telemetry_source_required(self) -> None:
        with pytest.raises(InvalidArgument, match="TelemetrySourceRef"):
            TelemetrySourceRef(source_id=" ")

    def test_telemetry_source_valid(self) -> None:
        ref = TelemetrySourceRef(source_id="edr-1", source_type="endpoint")
        assert ref.source_type == "endpoint"

    def test_asset_scope_rejects_blank_type(self) -> None:
        with pytest.raises(InvalidArgument, match="AssetScopeFilter"):
            AssetScopeFilter(asset_types=("host", " "))

    def test_asset_scope_valid(self) -> None:
        scope = AssetScopeFilter(asset_types=("host",), tags=("prod",))
        assert scope.tags == ("prod",)


class TestMitreTechniqueId:
    def test_valid_technique(self) -> None:
        assert MitreTechniqueId("T1059").value == "T1059"

    def test_valid_sub_technique(self) -> None:
        assert MitreTechniqueId("T1059.001").value == "T1059.001"

    def test_rejects_invalid(self) -> None:
        with pytest.raises(InvalidArgument, match="MitreTechniqueId"):
            MitreTechniqueId("TA0002")
