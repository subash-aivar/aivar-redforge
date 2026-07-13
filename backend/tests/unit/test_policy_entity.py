"""Unit tests for ValidationPolicy aggregate root."""

import pytest

from redforge.domain.policies.entity import ValidationPolicy
from redforge.domain.policies.events import (
    PolicyArchived,
    PolicyCreated,
    PolicyPublished,
    PolicySuperseded,
)
from redforge.domain.policies.exceptions import (
    InvalidPolicyTransitionError,
    PolicyEmptyError,
    PolicyImmutableError,
)
from redforge.domain.policies.value_objects import (
    ExecutionStrategy,
    PolicyStatus,
    PolicyVersion,
    TargetScope,
    TriggerRule,
)
from redforge.shared.identifiers import EntityId


def _create_policy() -> ValidationPolicy:
    return ValidationPolicy.create(name="OWASP LLM Top 10 Basic")


def _policy_with_attack() -> ValidationPolicy:
    p = _create_policy()
    p.attach_attack(EntityId.generate())
    p.collect_events()
    return p


def _published_policy() -> ValidationPolicy:
    p = _policy_with_attack()
    p.publish()
    p.collect_events()
    return p


class TestCreate:
    def test_creates_draft(self) -> None:
        p = _create_policy()
        assert p.status == PolicyStatus.DRAFT
        assert p.is_executable is False

    def test_sets_name(self) -> None:
        p = _create_policy()
        assert p.name == "OWASP LLM Top 10 Basic"

    def test_default_strategy(self) -> None:
        p = _create_policy()
        assert p.execution_strategy == ExecutionStrategy.SEQUENTIAL

    def test_default_trigger(self) -> None:
        p = _create_policy()
        assert TriggerRule.ON_DEMAND in p.trigger_rules

    def test_default_universal_scope(self) -> None:
        p = _create_policy()
        assert p.scope.is_universal is True

    def test_name_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 3"):
            ValidationPolicy.create(name="AB")

    def test_emits_event(self) -> None:
        p = _create_policy()
        events = p.collect_events()
        assert isinstance(events[0], PolicyCreated)


class TestPublish:
    def test_publishes_with_attacks(self) -> None:
        p = _policy_with_attack()
        p.publish()
        assert p.status == PolicyStatus.PUBLISHED
        assert p.is_executable is True

    def test_publish_empty_raises(self) -> None:
        p = _create_policy()
        p.collect_events()
        with pytest.raises(PolicyEmptyError):
            p.publish()

    def test_publish_non_draft_raises(self) -> None:
        p = _published_policy()
        with pytest.raises(InvalidPolicyTransitionError):
            p.publish()

    def test_publish_emits_event(self) -> None:
        p = _policy_with_attack()
        p.publish()
        events = p.collect_events()
        assert isinstance(events[0], PolicyPublished)
        assert events[0].attack_count == 1


class TestArchive:
    def test_archives_published(self) -> None:
        p = _published_policy()
        p.archive()
        assert p.status == PolicyStatus.ARCHIVED

    def test_archive_draft_raises(self) -> None:
        p = _create_policy()
        p.collect_events()
        with pytest.raises(InvalidPolicyTransitionError):
            p.archive()

    def test_archive_emits_event(self) -> None:
        p = _published_policy()
        p.archive()
        events = p.collect_events()
        assert isinstance(events[0], PolicyArchived)


class TestSupersede:
    def test_supersedes(self) -> None:
        p = _published_policy()
        new_id = EntityId.generate()
        p.supersede(new_id)
        assert p.status == PolicyStatus.SUPERSEDED
        assert p.superseded_by == new_id

    def test_supersede_emits_event(self) -> None:
        p = _published_policy()
        p.supersede(EntityId.generate())
        events = p.collect_events()
        assert isinstance(events[0], PolicySuperseded)


class TestComposition:
    def test_attach_attack(self) -> None:
        p = _create_policy()
        aid = EntityId.generate()
        p.attach_attack(aid)
        assert aid in p.attack_refs
        assert p.attack_count == 1

    def test_detach_attack(self) -> None:
        p = _create_policy()
        aid = EntityId.generate()
        p.attach_attack(aid)
        p.detach_attack(aid)
        assert aid not in p.attack_refs

    def test_attach_knowledge(self) -> None:
        p = _create_policy()
        kid = EntityId.generate()
        p.attach_knowledge(kid)
        assert kid in p.knowledge_refs

    def test_add_trigger_rule(self) -> None:
        p = _create_policy()
        p.add_trigger_rule(TriggerRule.CONTINUOUS)
        assert TriggerRule.CONTINUOUS in p.trigger_rules

    def test_tag(self) -> None:
        p = _create_policy()
        p.tag("owasp")
        assert "owasp" in p.tags

    def test_modify_archived_raises(self) -> None:
        p = _published_policy()
        p.archive()
        with pytest.raises(PolicyImmutableError):
            p.attach_attack(EntityId.generate())


class TestEquality:
    def test_same_id_equal(self) -> None:
        p = _create_policy()
        p2 = ValidationPolicy(
            id=p.id, name="X", description="", version=PolicyVersion(2, 0, 0),
            status=PolicyStatus.PUBLISHED, scope=TargetScope.universal(),
            execution_strategy=ExecutionStrategy.PARALLEL,
            trigger_rules=set(), attack_refs=set(), knowledge_refs=set(),
            tags=set(), metadata={}, superseded_by=None, timestamps=p.timestamps,
        )
        assert p == p2

    def test_different_id_not_equal(self) -> None:
        assert _create_policy() != _create_policy()

    def test_hashable(self) -> None:
        p = _create_policy()
        assert len({p, p}) == 1
