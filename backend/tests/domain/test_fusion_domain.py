"""Domain unit tests for Threat Fusion — M22 Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.domain.threat_intel.fusion_entity import FusedIndicator
from redforge.domain.threat_intel.fusion_exceptions import (
    InvalidFusionWeightError,
    InvalidIndicatorLifecycleTransitionError,
)
from redforge.domain.threat_intel.fusion_policies import (
    DEFAULT_FUSION_WEIGHTS,
    FusionConflictPolicy,
    IndicatorTTLPolicy,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    AggregatedRiskState,
    CanonicalIndicatorKey,
    FusedIndicatorType,
    FusionConfidence,
    FusionWeight,
    IndicatorLifecycle,
    SourceAttribution,
    fused_type_for_stix_ref,
)


def _attr(
    source: str,
    external_id: str,
    *,
    confidence: FusionConfidence = FusionConfidence.MEDIUM,
    observed_at: datetime | None = None,
    weight: float = 0.7,
) -> SourceAttribution:
    return SourceAttribution(
        source_system=source,
        external_id=external_id,
        content_hash="abc",
        observed_at=observed_at or datetime.now(UTC),
        weight_applied=weight,
        confidence=confidence,
    )


class TestCanonicalKey:
    def test_technique_normalizes_case(self) -> None:
        key = CanonicalIndicatorKey.for_type(FusedIndicatorType.TECHNIQUE, "t1190")
        assert key.value == "technique:T1190"

    def test_stix_ref_mapping(self) -> None:
        assert fused_type_for_stix_ref("malware--abcd") is FusedIndicatorType.SOFTWARE
        assert fused_type_for_stix_ref("intrusion-set--x") is FusedIndicatorType.GROUP
        assert fused_type_for_stix_ref("not-a-stix") is None


class TestFusionConflictPolicy:
    def test_no_attributions_yields_no_evidence_sentinel(self) -> None:
        risk = FusionConflictPolicy().aggregate([], indicator_type="technique")
        assert risk.state is AggregatedRiskState.NO_EVIDENCE
        assert risk.confidence is None
        assert risk.sources == ()

    def test_higher_weight_wins(self) -> None:
        policy = FusionConflictPolicy(
            [
                FusionWeight(source_system="mitre_attack", weight=1.0),
                FusionWeight(source_system="stix_taxii_feed", weight=0.5),
            ]
        )
        older = datetime.now(UTC) - timedelta(days=1)
        newer = datetime.now(UTC)
        risk = policy.aggregate(
            [
                _attr("stix_taxii_feed", "a", confidence=FusionConfidence.HIGH, observed_at=newer),
                _attr("mitre_attack", "b", confidence=FusionConfidence.LOW, observed_at=older),
            ],
            indicator_type="technique",
        )
        assert risk.winner_source_system == "mitre_attack"
        assert risk.state is AggregatedRiskState.CONFLICT

    def test_default_weights_are_documented(self) -> None:
        assert DEFAULT_FUSION_WEIGHTS["mitre_attack"] == 1.0
        assert DEFAULT_FUSION_WEIGHTS["stix_taxii_feed"] == 0.7

    def test_group_corroboration_floor(self) -> None:
        policy = FusionConflictPolicy()
        risk = policy.aggregate(
            [_attr("mitre_attack", "g1", confidence=FusionConfidence.VERY_HIGH)],
            indicator_type="group",
        )
        assert risk.confidence is FusionConfidence.MEDIUM

    def test_invalid_weight_rejected(self) -> None:
        with pytest.raises(InvalidFusionWeightError):
            FusionWeight(source_system="x", weight=0.0)


class TestIndicatorLifecycle:
    def test_fuse_and_merge(self) -> None:
        policy = FusionConflictPolicy()
        ttl = IndicatorTTLPolicy()
        now = datetime.now(UTC)
        key = CanonicalIndicatorKey.for_type(FusedIndicatorType.TECHNIQUE, "T1190")
        indicator = FusedIndicator.fuse(
            id="01TESTINDICATOR00000000001",
            canonical_key=key,
            display_name="Exploit Public-Facing Application",
            attributions=[_attr("mitre_attack", "attack-pattern--1")],
            conflict_policy=policy,
            valid_until=ttl.valid_until("technique", valid_from=now),
            now=now,
        )
        assert indicator.lifecycle is IndicatorLifecycle.ACTIVE
        events = indicator.collect_events()
        assert len(events) == 1

        indicator.merge_attribution(
            _attr("stix_taxii_feed", "attack-pattern--1"),
            conflict_policy=policy,
            now=now,
        )
        assert len(indicator.attributions) == 2

    def test_revoke_is_terminal(self) -> None:
        policy = FusionConflictPolicy()
        key = CanonicalIndicatorKey.for_type(FusedIndicatorType.VULNERABILITY, "CVE-2024-1")
        indicator = FusedIndicator.fuse(
            id="01TESTINDICATOR00000000002",
            canonical_key=key,
            display_name="CVE-2024-1",
            attributions=[_attr("stix_taxii_feed", "CVE-2024-1")],
            conflict_policy=policy,
            valid_until=None,
        )
        indicator.revoke()
        with pytest.raises(InvalidIndicatorLifecycleTransitionError):
            indicator.mark_expired()
