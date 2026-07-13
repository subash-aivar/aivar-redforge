"""Unit tests for AttackDefinition aggregate root."""

import pytest

from redforge.domain.attack_library.entity import AttackDefinition
from redforge.domain.attack_library.events import (
    AttackArchived,
    AttackCreated,
    AttackDeprecated,
    AttackPublished,
    AttackSuperseded,
)
from redforge.domain.attack_library.exceptions import (
    AttackImmutableError,
    InvalidAttackTransitionError,
)
from redforge.domain.attack_library.value_objects import (
    AttackCategory,
    AttackMaturity,
    AttackPrerequisite,
    AttackReference,
    AttackRelationshipType,
    AttackSeverity,
    AttackStatus,
    AttackTechnique,
    AttackVersion,
    Capability,
    CvssMetadata,
    EvaluationRequirement,
    ExecutionStrategy,
    ExpectedOutcome,
    FrameworkMapping,
    ProviderCompatibility,
    SafetyClassification,
)
from redforge.shared.identifiers import EntityId


def _create_attack(
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
    severity: AttackSeverity = AttackSeverity.HIGH,
) -> AttackDefinition:
    return AttackDefinition.create(
        name="direct-injection-basic",
        display_name="Direct Prompt Injection",
        description="Tests for direct prompt injection vulnerabilities",
        category=category,
        technique=AttackTechnique(
            technique="Prompt Injection", sub_technique="Direct"
        ),
        severity=severity,
    )


def _published_attack() -> AttackDefinition:
    a = _create_attack()
    a.publish()
    a.collect_events()
    return a


class TestCreate:
    def test_creates_draft(self) -> None:
        a = _create_attack()
        assert a.status == AttackStatus.DRAFT
        assert a.is_executable is False

    def test_sets_fields(self) -> None:
        a = _create_attack(AttackCategory.JAILBREAK, AttackSeverity.CRITICAL)
        assert a.category == AttackCategory.JAILBREAK
        assert a.severity == AttackSeverity.CRITICAL
        assert a.technique.full_name == "Prompt Injection: Direct"

    def test_default_safety_and_maturity(self) -> None:
        a = _create_attack()
        assert a.safety == SafetyClassification.SAFE
        assert a.maturity == AttackMaturity.EXPERIMENTAL

    def test_default_universal_compatibility(self) -> None:
        a = _create_attack()
        assert a.compatibility.is_universal is True

    def test_name_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 3"):
            AttackDefinition.create(
                name="ab", display_name="Valid", description="",
                category=AttackCategory.JAILBREAK,
                technique=AttackTechnique(technique="X"),
                severity=AttackSeverity.LOW,
            )

    def test_emits_created_event(self) -> None:
        a = _create_attack()
        events = a.collect_events()
        assert isinstance(events[0], AttackCreated)


class TestPublish:
    def test_publishes(self) -> None:
        a = _create_attack()
        a.collect_events()
        a.publish()
        assert a.status == AttackStatus.PUBLISHED
        assert a.is_executable is True

    def test_publish_emits_event(self) -> None:
        a = _create_attack()
        a.collect_events()
        a.publish()
        events = a.collect_events()
        assert isinstance(events[0], AttackPublished)

    def test_publish_non_draft_raises(self) -> None:
        a = _published_attack()
        with pytest.raises(InvalidAttackTransitionError):
            a.publish()


class TestDeprecate:
    def test_deprecates_published(self) -> None:
        a = _published_attack()
        a.deprecate()
        assert a.status == AttackStatus.DEPRECATED
        assert a.is_executable is True  # still executable

    def test_deprecate_emits_event(self) -> None:
        a = _published_attack()
        a.deprecate()
        events = a.collect_events()
        assert isinstance(events[0], AttackDeprecated)

    def test_deprecate_draft_raises(self) -> None:
        a = _create_attack()
        a.collect_events()
        with pytest.raises(InvalidAttackTransitionError):
            a.deprecate()


class TestArchive:
    def test_archives_published(self) -> None:
        a = _published_attack()
        a.archive()
        assert a.status == AttackStatus.ARCHIVED
        assert a.is_executable is False

    def test_archives_deprecated(self) -> None:
        a = _published_attack()
        a.deprecate()
        a.collect_events()
        a.archive()
        assert a.status == AttackStatus.ARCHIVED

    def test_archive_draft_raises(self) -> None:
        a = _create_attack()
        a.collect_events()
        with pytest.raises(InvalidAttackTransitionError):
            a.archive()

    def test_archive_emits_event(self) -> None:
        a = _published_attack()
        a.archive()
        events = a.collect_events()
        assert isinstance(events[0], AttackArchived)


class TestSupersede:
    def test_supersedes_published(self) -> None:
        a = _published_attack()
        new_id = EntityId.generate()
        a.supersede(new_id)
        assert a.status == AttackStatus.SUPERSEDED
        assert a.superseded_by == new_id

    def test_supersede_emits_event(self) -> None:
        a = _published_attack()
        a.supersede(EntityId.generate())
        events = a.collect_events()
        assert isinstance(events[0], AttackSuperseded)


class TestTags:
    def test_tag(self) -> None:
        a = _create_attack()
        a.tag("owasp-llm01")
        assert "owasp-llm01" in a.tags

    def test_untag(self) -> None:
        a = _create_attack()
        a.tag("temp")
        a.untag("temp")
        assert "temp" not in a.tags

    def test_tag_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        with pytest.raises(AttackImmutableError):
            a.tag("x")


class TestFrameworkMappings:
    def test_map_to_framework(self) -> None:
        a = _create_attack()
        m = FrameworkMapping(
            framework="MITRE_ATLAS", identifier="AML.T0051", name="Prompt Injection"
        )
        a.map_to_framework(m)
        assert m in a.framework_mappings

    def test_remove_mapping(self) -> None:
        a = _create_attack()
        m = FrameworkMapping(framework="OWASP", identifier="LLM01")
        a.map_to_framework(m)
        a.remove_framework_mapping(m)
        assert m not in a.framework_mappings

    def test_map_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        m = FrameworkMapping(framework="X", identifier="Y")
        with pytest.raises(AttackImmutableError):
            a.map_to_framework(m)


class TestKnowledgeLinks:
    def test_link_knowledge(self) -> None:
        a = _create_attack()
        kid = EntityId.generate()
        a.link_knowledge(kid)
        assert kid in a.knowledge_refs

    def test_unlink_knowledge(self) -> None:
        a = _create_attack()
        kid = EntityId.generate()
        a.link_knowledge(kid)
        a.unlink_knowledge(kid)
        assert kid not in a.knowledge_refs


class TestDefaults:
    """New Sprint 13 fields must default sanely for every existing
    caller of create() that doesn't know about them."""

    def test_new_fields_have_safe_defaults(self) -> None:
        a = _create_attack()
        assert a.taxonomy_node_id is None
        assert a.required_capabilities == frozenset()
        assert a.prerequisites == frozenset()
        assert a.execution_strategy == ExecutionStrategy.SINGLE_TURN
        assert a.expected_outcomes == frozenset()
        assert a.evaluation_requirements == frozenset()
        assert a.references == frozenset()
        assert a.cvss is None
        assert a.relationships == frozenset()

    def test_create_accepts_new_optional_kwargs(self) -> None:
        node_id = EntityId.generate()
        a = AttackDefinition.create(
            name="mcp-tool-poisoning",
            display_name="MCP Tool Poisoning",
            description="Poisons an MCP tool description to hijack behavior",
            category=AttackCategory.TOOL_ABUSE,
            technique=AttackTechnique(technique="MCP Abuse"),
            severity=AttackSeverity.HIGH,
            taxonomy_node_id=node_id,
            required_capabilities=frozenset({Capability.MCP, Capability.TOOL_CALLING}),
            execution_strategy=ExecutionStrategy.MULTI_TURN,
            cvss=CvssMetadata(version="3.1", vector="CVSS:3.1/AV:N", base_score=7.5),
        )
        assert a.taxonomy_node_id == node_id
        assert a.required_capabilities == {Capability.MCP, Capability.TOOL_CALLING}
        assert a.execution_strategy == ExecutionStrategy.MULTI_TURN
        assert a.cvss is not None
        assert a.cvss.base_score == 7.5


class TestCapabilities:
    def test_require_capability(self) -> None:
        a = _create_attack()
        a.require_capability(Capability.RAG)
        assert Capability.RAG in a.required_capabilities

    def test_unrequire_capability(self) -> None:
        a = _create_attack()
        a.require_capability(Capability.RAG)
        a.unrequire_capability(Capability.RAG)
        assert Capability.RAG not in a.required_capabilities

    def test_require_capability_on_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        with pytest.raises(AttackImmutableError):
            a.require_capability(Capability.MEMORY)


class TestPrerequisites:
    def test_add_prerequisite(self) -> None:
        a = _create_attack()
        prereq = AttackPrerequisite(description="Target must expose tool calling")
        a.add_prerequisite(prereq)
        assert prereq in a.prerequisites

    def test_prerequisite_with_capabilities(self) -> None:
        prereq = AttackPrerequisite(
            description="Requires memory + agents",
            required_capabilities=frozenset({Capability.MEMORY, Capability.AGENTS}),
        )
        assert Capability.AGENTS in prereq.required_capabilities

    def test_prerequisite_empty_description_raises(self) -> None:
        with pytest.raises(ValueError, match="description"):
            AttackPrerequisite(description="")

    def test_remove_prerequisite(self) -> None:
        a = _create_attack()
        prereq = AttackPrerequisite(description="Needs reconnaissance")
        a.add_prerequisite(prereq)
        a.remove_prerequisite(prereq)
        assert prereq not in a.prerequisites


class TestExecutionStrategy:
    def test_set_execution_strategy(self) -> None:
        a = _create_attack()
        a.set_execution_strategy(ExecutionStrategy.ADAPTIVE)
        assert a.execution_strategy == ExecutionStrategy.ADAPTIVE

    def test_set_on_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        with pytest.raises(AttackImmutableError):
            a.set_execution_strategy(ExecutionStrategy.CHAINED)


class TestExpectedOutcomesAndEvaluation:
    def test_add_expected_outcome(self) -> None:
        a = _create_attack()
        outcome = ExpectedOutcome(
            description="Model discloses system prompt",
            indicator="response contains verbatim system prompt text",
        )
        a.add_expected_outcome(outcome)
        assert outcome in a.expected_outcomes

    def test_expected_outcome_empty_description_raises(self) -> None:
        with pytest.raises(ValueError, match="description"):
            ExpectedOutcome(description="")

    def test_add_evaluation_requirement(self) -> None:
        a = _create_attack()
        req = EvaluationRequirement(method="llm_judge", description="Judge for leakage")
        a.add_evaluation_requirement(req)
        assert req in a.evaluation_requirements

    def test_evaluation_requirement_empty_method_raises(self) -> None:
        with pytest.raises(ValueError, match="method"):
            EvaluationRequirement(method="")

    def test_remove_evaluation_requirement(self) -> None:
        a = _create_attack()
        req = EvaluationRequirement(method="keyword_match")
        a.add_evaluation_requirement(req)
        a.remove_evaluation_requirement(req)
        assert req not in a.evaluation_requirements


class TestReferencesAndCvss:
    def test_add_reference(self) -> None:
        a = _create_attack()
        ref = AttackReference(url="https://example.com/paper", title="Paper")
        a.add_reference(ref)
        assert ref in a.references

    def test_reference_requires_url_and_title(self) -> None:
        with pytest.raises(ValueError, match="url"):
            AttackReference(url="", title="X")
        with pytest.raises(ValueError, match="title"):
            AttackReference(url="https://x.test", title="")

    def test_set_cvss(self) -> None:
        a = _create_attack()
        cvss = CvssMetadata(version="3.1", vector="CVSS:3.1/AV:N/AC:L", base_score=9.8)
        a.set_cvss(cvss)
        assert a.cvss == cvss

    def test_cvss_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="base_score"):
            CvssMetadata(version="3.1", vector="CVSS:3.1", base_score=10.1)
        with pytest.raises(ValueError, match="base_score"):
            CvssMetadata(version="3.1", vector="CVSS:3.1", base_score=-0.1)

    def test_clear_cvss(self) -> None:
        a = _create_attack()
        a.set_cvss(CvssMetadata(version="3.1", vector="CVSS:3.1", base_score=5.0))
        a.set_cvss(None)
        assert a.cvss is None


class TestTaxonomyClassification:
    def test_classify_under(self) -> None:
        a = _create_attack()
        node_id = EntityId.generate()
        a.classify_under(node_id)
        assert a.taxonomy_node_id == node_id

    def test_reclassify_to_none(self) -> None:
        a = _create_attack()
        a.classify_under(EntityId.generate())
        a.classify_under(None)
        assert a.taxonomy_node_id is None

    def test_classify_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        with pytest.raises(AttackImmutableError):
            a.classify_under(EntityId.generate())


class TestRelationships:
    def test_relate_to(self) -> None:
        a = _create_attack()
        other_id = EntityId.generate()
        a.relate_to(other_id, AttackRelationshipType.DERIVED_FROM)
        assert any(
            r.related_attack_id == other_id
            and r.relationship_type == AttackRelationshipType.DERIVED_FROM
            for r in a.relationships
        )

    def test_relate_to_self_raises(self) -> None:
        a = _create_attack()
        with pytest.raises(ValueError, match="itself"):
            a.relate_to(a.id, AttackRelationshipType.PARENT_OF)

    def test_unrelate(self) -> None:
        a = _create_attack()
        other_id = EntityId.generate()
        a.relate_to(other_id, AttackRelationshipType.COMPOSED_OF)
        a.unrelate(other_id, AttackRelationshipType.COMPOSED_OF)
        assert len(a.relationships) == 0

    def test_unrelate_only_removes_matching_type(self) -> None:
        """Two different relationship types to the same attack are
        independent edges — removing one must not remove the other."""
        a = _create_attack()
        other_id = EntityId.generate()
        a.relate_to(other_id, AttackRelationshipType.PARENT_OF)
        a.relate_to(other_id, AttackRelationshipType.PREREQUISITE_OF)
        a.unrelate(other_id, AttackRelationshipType.PARENT_OF)
        remaining_types = {r.relationship_type for r in a.relationships}
        assert remaining_types == {AttackRelationshipType.PREREQUISITE_OF}

    def test_relate_on_archived_raises(self) -> None:
        a = _published_attack()
        a.archive()
        with pytest.raises(AttackImmutableError):
            a.relate_to(EntityId.generate(), AttackRelationshipType.PARENT_OF)

    def test_multiple_relationships_to_different_attacks(self) -> None:
        a = _create_attack()
        first = EntityId.generate()
        second = EntityId.generate()
        a.relate_to(first, AttackRelationshipType.PARENT_OF)
        a.relate_to(second, AttackRelationshipType.DERIVED_FROM)
        assert len(a.relationships) == 2


class TestEquality:
    def test_same_id_equal(self) -> None:
        a = _create_attack()
        a2 = AttackDefinition(
            id=a.id, name="x", display_name="x", description="",
            category=AttackCategory.JAILBREAK,
            technique=AttackTechnique(technique="X"),
            severity=AttackSeverity.LOW, safety=SafetyClassification.SAFE,
            maturity=AttackMaturity.WELL_KNOWN, version=AttackVersion(2, 0, 0),
            status=AttackStatus.PUBLISHED,
            compatibility=ProviderCompatibility.universal(),
            tags=set(), framework_mappings=set(), knowledge_refs=set(),
            metadata={}, superseded_by=None, timestamps=a.timestamps,
        )
        assert a == a2

    def test_different_id_not_equal(self) -> None:
        assert _create_attack() != _create_attack()

    def test_hashable(self) -> None:
        a = _create_attack()
        assert len({a, a}) == 1
