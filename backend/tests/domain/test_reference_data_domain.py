"""M22 Phase 1 — Threat Intelligence Reference Data domain unit tests.

Pure-function, no I/O, no database. Covers:
  - Value objects: TechniqueId, TacticId, CveId (grammar validation),
    EpssScore, CvssScore (range validation + severity banding)
  - Enums: ReferenceDataSource, AttackRelationshipType, IngestionScope
  - Reference entities: AttackTactic, AttackTechnique,
    AttackTechniqueRelationship, Vulnerability (construction, immutability)
  - Aggregate: ReferenceDataIngestionRecord (scope/organization_id
    invariant, `record()` factory, domain event emission/collection)
  - Domain exceptions
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, date, datetime

import pytest

from redforge.domain.threat_intel.attack_technique_entity import (
    AttackTactic,
    AttackTechnique,
    AttackTechniqueRelationship,
)
from redforge.domain.threat_intel.reference_data_events import ReferenceDataObjectIngested
from redforge.domain.threat_intel.reference_data_exceptions import (
    InvalidCveIdError,
    InvalidCvssScoreError,
    InvalidEpssScoreError,
    InvalidIngestionScopeError,
    InvalidTacticIdError,
    InvalidTechniqueIdError,
)
from redforge.domain.threat_intel.reference_data_ingestion import ReferenceDataIngestionRecord
from redforge.domain.threat_intel.reference_data_value_objects import (
    AttackRelationshipType,
    CveId,
    CvssScore,
    EpssScore,
    IngestionScope,
    ReferenceDataSource,
    TacticId,
    TechniqueId,
)
from redforge.domain.threat_intel.vulnerability_entity import Vulnerability

_NOW = datetime(2026, 7, 1, tzinfo=UTC)


# ─── TechniqueId ────────────────────────────────────────────────────────────


class TestTechniqueId:
    @pytest.mark.parametrize("raw", ["T1190", "T1059.001", "T0001", "T9999.999"])
    def test_accepts_valid_ids(self, raw: str) -> None:
        assert TechniqueId(raw).value == raw

    @pytest.mark.parametrize(
        "raw",
        ["", "1190", "T119", "T11900", "T1190.1", "t1190", "T1190.", "TA1190", "T1190001"],
    )
    def test_rejects_invalid_ids(self, raw: str) -> None:
        with pytest.raises(InvalidTechniqueIdError):
            TechniqueId(raw)

    def test_is_sub_technique_true_for_dotted_id(self) -> None:
        assert TechniqueId("T1059.001").is_sub_technique is True
        assert TechniqueId("T1059").is_sub_technique is False

    def test_parent_id_derives_base_technique(self) -> None:
        assert TechniqueId("T1059.001").parent_id == TechniqueId("T1059")
        assert TechniqueId("T1059").parent_id is None

    def test_str_returns_raw_value(self) -> None:
        assert str(TechniqueId("T1190")) == "T1190"

    def test_is_frozen(self) -> None:
        technique_id = TechniqueId("T1190")
        with pytest.raises(dataclasses.FrozenInstanceError):
            technique_id.value = "T1191"  # type: ignore[misc]


# ─── TacticId ───────────────────────────────────────────────────────────────


class TestTacticId:
    @pytest.mark.parametrize("raw", ["TA0001", "TA0043"])
    def test_accepts_valid_ids(self, raw: str) -> None:
        assert TacticId(raw).value == raw

    @pytest.mark.parametrize("raw", ["", "TA1", "TA00001", "ta0001", "T0001"])
    def test_rejects_invalid_ids(self, raw: str) -> None:
        with pytest.raises(InvalidTacticIdError):
            TacticId(raw)

    def test_str_returns_raw_value(self) -> None:
        assert str(TacticId("TA0001")) == "TA0001"


# ─── CveId ──────────────────────────────────────────────────────────────────


class TestCveId:
    @pytest.mark.parametrize("raw", ["CVE-2024-1234", "CVE-2021-44228", "CVE-1999-00001"])
    def test_accepts_valid_ids(self, raw: str) -> None:
        assert CveId(raw).value == raw

    @pytest.mark.parametrize(
        "raw", ["", "CVE-24-1234", "CVE-2024-123", "cve-2024-1234", "2024-1234"]
    )
    def test_rejects_invalid_ids(self, raw: str) -> None:
        with pytest.raises(InvalidCveIdError):
            CveId(raw)

    def test_str_returns_raw_value(self) -> None:
        assert str(CveId("CVE-2024-1234")) == "CVE-2024-1234"


# ─── EpssScore ──────────────────────────────────────────────────────────────


class TestEpssScore:
    def test_accepts_boundary_values(self) -> None:
        score = EpssScore(probability=0.0, percentile=1.0, model_date=date(2026, 7, 1))
        assert score.probability == 0.0
        assert score.percentile == 1.0

    @pytest.mark.parametrize("probability", [-0.01, 1.01, -1.0, 2.0])
    def test_rejects_out_of_range_probability(self, probability: float) -> None:
        with pytest.raises(InvalidEpssScoreError):
            EpssScore(probability=probability, percentile=0.5, model_date=date(2026, 7, 1))

    @pytest.mark.parametrize("percentile", [-0.01, 1.01])
    def test_rejects_out_of_range_percentile(self, percentile: float) -> None:
        with pytest.raises(InvalidEpssScoreError):
            EpssScore(probability=0.5, percentile=percentile, model_date=date(2026, 7, 1))


# ─── CvssScore ──────────────────────────────────────────────────────────────


class TestCvssScore:
    def test_accepts_boundary_values(self) -> None:
        score = CvssScore(version="3.1", base_score=0.0, vector="CVSS:3.1/AV:N")
        assert score.base_score == 0.0

    @pytest.mark.parametrize("base_score", [-0.1, 10.1, -5.0, 15.0])
    def test_rejects_out_of_range_base_score(self, base_score: float) -> None:
        with pytest.raises(InvalidCvssScoreError):
            CvssScore(version="3.1", base_score=base_score, vector="CVSS:3.1/AV:N")

    @pytest.mark.parametrize("vector", ["", "   "])
    def test_rejects_empty_vector(self, vector: str) -> None:
        with pytest.raises(InvalidCvssScoreError):
            CvssScore(version="3.1", base_score=5.0, vector=vector)

    @pytest.mark.parametrize(
        "base_score,expected",
        [
            (0.0, "NONE"),
            (0.1, "LOW"),
            (3.9, "LOW"),
            (4.0, "MEDIUM"),
            (6.9, "MEDIUM"),
            (7.0, "HIGH"),
            (8.9, "HIGH"),
            (9.0, "CRITICAL"),
            (10.0, "CRITICAL"),
        ],
    )
    def test_severity_banding(self, base_score: float, expected: str) -> None:
        score = CvssScore(version="3.1", base_score=base_score, vector="CVSS:3.1/AV:N")
        assert score.severity == expected


# ─── Enums ──────────────────────────────────────────────────────────────────


class TestEnums:
    def test_reference_data_source_is_str_subclass(self) -> None:
        assert isinstance(ReferenceDataSource.MITRE_ATTACK, str)
        assert ReferenceDataSource.MITRE_ATTACK == "mitre_attack"

    def test_attack_relationship_type_values(self) -> None:
        assert AttackRelationshipType.SUBTECHNIQUE_OF == "subtechnique-of"
        assert AttackRelationshipType.USES == "uses"

    def test_ingestion_scope_values(self) -> None:
        assert IngestionScope.GLOBAL == "GLOBAL"
        assert IngestionScope.TENANT == "TENANT"


# ─── AttackTactic entity ────────────────────────────────────────────────────


class TestAttackTactic:
    def test_construction(self) -> None:
        tactic = AttackTactic(
            tactic_id=TacticId("TA0001"),
            name="Initial Access",
            shortname="initial-access",
            description="The adversary is trying to get into your network.",
            stix_id="x-mitre-tactic--ffd5bcee-6e16-4dd2-8eca-7b3beedf33ca",
            url="https://attack.mitre.org/tactics/TA0001",
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert tactic.tactic_id.value == "TA0001"
        assert tactic.name == "Initial Access"

    def test_is_frozen(self) -> None:
        tactic = AttackTactic(
            tactic_id=TacticId("TA0001"),
            name="Initial Access",
            shortname="initial-access",
            description="",
            stix_id="x-mitre-tactic--abc",
            url=None,
            created_at=_NOW,
            updated_at=_NOW,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            tactic.name = "Renamed"  # type: ignore[misc]


# ─── AttackTechnique entity ─────────────────────────────────────────────────


class TestAttackTechnique:
    def test_construction_defaults(self) -> None:
        technique = AttackTechnique(
            technique_id=TechniqueId("T1190"),
            name="Exploit Public-Facing Application",
            description="",
            stix_id="attack-pattern--3f886f2a-874f-4333-b7c6-330e6e546b2d",
            is_sub_technique=False,
            parent_technique_id=None,
        )
        assert technique.tactic_ids == ()
        assert technique.platforms == ()
        assert technique.data_sources == ()
        assert technique.is_deprecated is False
        assert technique.is_revoked is False

    def test_sub_technique_carries_parent(self) -> None:
        sub = AttackTechnique(
            technique_id=TechniqueId("T1059.001"),
            name="PowerShell",
            description="",
            stix_id="attack-pattern--abc",
            is_sub_technique=True,
            parent_technique_id=TechniqueId("T1059"),
            tactic_ids=(TacticId("TA0002"),),
            platforms=("Windows",),
        )
        assert sub.parent_technique_id == TechniqueId("T1059")
        assert TacticId("TA0002") in sub.tactic_ids


# ─── AttackTechniqueRelationship entity ─────────────────────────────────────


class TestAttackTechniqueRelationship:
    def test_construction(self) -> None:
        relationship = AttackTechniqueRelationship(
            stix_id="relationship--abc",
            relationship_type=AttackRelationshipType.SUBTECHNIQUE_OF,
            source_ref="attack-pattern--sub",
            target_ref="attack-pattern--parent",
            source_technique_id=TechniqueId("T1059.001"),
            target_technique_id=TechniqueId("T1059"),
            description="",
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert relationship.relationship_type == AttackRelationshipType.SUBTECHNIQUE_OF

    def test_non_technique_sides_are_none(self) -> None:
        # A `uses` relationship from a Group (not modeled in Phase 1) to a
        # technique — source_technique_id stays None, only the target side
        # resolves.
        relationship = AttackTechniqueRelationship(
            stix_id="relationship--xyz",
            relationship_type=AttackRelationshipType.USES,
            source_ref="intrusion-set--group",
            target_ref="attack-pattern--technique",
            source_technique_id=None,
            target_technique_id=TechniqueId("T1190"),
            description="",
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert relationship.source_technique_id is None
        assert relationship.target_technique_id == TechniqueId("T1190")


# ─── Vulnerability entity ───────────────────────────────────────────────────


class TestVulnerability:
    def test_construction_without_enrichment(self) -> None:
        vulnerability = Vulnerability(
            cve_id=CveId("CVE-2024-1234"),
            description="A vulnerability.",
            cvss_v3=None,
            cvss_v2_score=None,
            epss=None,
            is_kev=False,
            kev_date_added=None,
            kev_due_date=None,
            kev_vulnerability_name=None,
            kev_short_description=None,
            kev_required_action=None,
            kev_known_ransomware_use=False,
            published_at=None,
            last_modified_at=None,
            source_last_synced_at=None,
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert vulnerability.cvss_v3 is None
        assert vulnerability.is_kev is False

    def test_construction_with_full_enrichment(self) -> None:
        vulnerability = Vulnerability(
            cve_id=CveId("CVE-2021-44228"),
            description="Log4Shell",
            cvss_v3=CvssScore(version="3.1", base_score=10.0, vector="CVSS:3.1/AV:N"),
            cvss_v2_score=9.3,
            epss=EpssScore(probability=0.97, percentile=0.99, model_date=date(2026, 7, 1)),
            is_kev=True,
            kev_date_added=_NOW,
            kev_due_date=_NOW,
            kev_vulnerability_name="Apache Log4j2 RCE",
            kev_short_description="RCE via JNDI",
            kev_required_action="Apply vendor patch",
            kev_known_ransomware_use=True,
            published_at=_NOW,
            last_modified_at=_NOW,
            source_last_synced_at=_NOW,
            created_at=_NOW,
            updated_at=_NOW,
        )
        assert vulnerability.cvss_v3 is not None
        assert vulnerability.cvss_v3.severity == "CRITICAL"
        assert vulnerability.is_kev is True
        assert vulnerability.kev_known_ransomware_use is True


# ─── ReferenceDataIngestionRecord aggregate ─────────────────────────────────


class TestReferenceDataIngestionRecord:
    def test_record_creates_global_scope_by_default(self) -> None:
        record = ReferenceDataIngestionRecord.record(
            id="rec-1",
            source_system=ReferenceDataSource.MITRE_ATTACK,
            object_type="attack_technique",
            external_id="attack-pattern--abc",
            content_hash="a" * 64,
            batch_id="batch-1",
            now=_NOW,
        )
        assert record.scope is IngestionScope.GLOBAL
        assert record.organization_id is None
        assert record.source_system is ReferenceDataSource.MITRE_ATTACK
        assert record.content_hash == "a" * 64
        assert record.ingested_at == _NOW
        assert record.batch_id == "batch-1"

    def test_record_emits_domain_event(self) -> None:
        record = ReferenceDataIngestionRecord.record(
            id="rec-2",
            source_system=ReferenceDataSource.NVD_CVE,
            object_type="vulnerability",
            external_id="CVE-2024-1234",
            content_hash="b" * 64,
            now=_NOW,
        )
        events = record.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, ReferenceDataObjectIngested)
        assert event.ingestion_record_id == "rec-2"
        assert event.source_system is ReferenceDataSource.NVD_CVE
        assert event.external_id == "CVE-2024-1234"
        assert event.occurred_at == _NOW

    def test_collect_events_drains_and_clears(self) -> None:
        record = ReferenceDataIngestionRecord.record(
            id="rec-3",
            source_system=ReferenceDataSource.CISA_KEV,
            object_type="vulnerability",
            external_id="CVE-2024-9999",
            content_hash="c" * 64,
        )
        first = record.collect_events()
        second = record.collect_events()
        assert len(first) == 1
        assert second == []

    def test_global_scope_with_organization_id_raises(self) -> None:
        with pytest.raises(InvalidIngestionScopeError):
            ReferenceDataIngestionRecord(
                id="rec-4",
                source_system=ReferenceDataSource.MITRE_ATTACK,
                scope=IngestionScope.GLOBAL,
                organization_id="org-1",
                object_type="attack_technique",
                external_id="attack-pattern--abc",
                content_hash="d" * 64,
                ingested_at=_NOW,
                batch_id=None,
            )

    def test_tenant_scope_without_organization_id_raises(self) -> None:
        with pytest.raises(InvalidIngestionScopeError):
            ReferenceDataIngestionRecord(
                id="rec-5",
                source_system=ReferenceDataSource.MITRE_ATTACK,
                scope=IngestionScope.TENANT,
                organization_id=None,
                object_type="attack_technique",
                external_id="attack-pattern--abc",
                content_hash="e" * 64,
                ingested_at=_NOW,
                batch_id=None,
            )

    def test_tenant_scope_with_organization_id_is_valid(self) -> None:
        record = ReferenceDataIngestionRecord(
            id="rec-6",
            source_system=ReferenceDataSource.MITRE_ATTACK,
            scope=IngestionScope.TENANT,
            organization_id="org-1",
            object_type="attack_technique",
            external_id="attack-pattern--abc",
            content_hash="f" * 64,
            ingested_at=_NOW,
            batch_id=None,
        )
        assert record.scope is IngestionScope.TENANT
        assert record.organization_id == "org-1"

    def test_read_accessors(self) -> None:
        record = ReferenceDataIngestionRecord.record(
            id="rec-7",
            source_system=ReferenceDataSource.EPSS_FIRST,
            object_type="vulnerability",
            external_id="CVE-2024-1111",
            content_hash="0" * 64,
            batch_id="batch-7",
            now=_NOW,
        )
        assert record.id == "rec-7"
        assert record.object_type == "vulnerability"
        assert record.external_id == "CVE-2024-1111"
        assert record.batch_id == "batch-7"
