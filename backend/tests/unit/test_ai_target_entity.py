"""Unit tests for AITarget aggregate root."""

import pytest

from redforge.domain.ai_targets.entity import AITarget
from redforge.domain.ai_targets.events import (
    TargetActivated,
    TargetArchived,
    TargetDeactivated,
    TargetEndpointChanged,
    TargetProviderChanged,
    TargetRegistered,
    TargetRenamed,
    TargetRestored,
    ValidationPolicyAttached,
    ValidationPolicyDetached,
)
from redforge.domain.ai_targets.exceptions import (
    DuplicateTagError,
    InvalidTargetTransitionError,
    PolicyAlreadyAttachedError,
    PolicyNotAttachedError,
    TargetArchivedError,
    TargetInactiveError,
)
from redforge.domain.ai_targets.value_objects import (
    EndpointUrl,
    Provider,
    Tag,
    TargetName,
    TargetStatus,
    TargetType,
    ValidationPolicyReference,
)
from redforge.shared.identifiers import EntityId


def _register_target(**kwargs) -> AITarget:
    defaults = {
        "organization_id": EntityId.generate(),
        "name": TargetName("Test LLM App"),
        "description": "A test AI target",
        "target_type": TargetType.LLM_APPLICATION,
        "provider": Provider.OPENAI,
        "endpoint": EndpointUrl("https://api.openai.com/v1/chat"),
    }
    defaults.update(kwargs)
    return AITarget.register(**defaults)


class TestRegistration:
    def test_register_sets_active(self) -> None:
        t = _register_target()
        assert t.status == TargetStatus.ACTIVE
        assert t.is_active is True

    def test_register_sets_fields(self) -> None:
        org_id = EntityId.generate()
        t = _register_target(
            organization_id=org_id,
            name=TargetName("My App"),
            target_type=TargetType.RAG_SYSTEM,
            provider=Provider.ANTHROPIC,
        )
        assert t.organization_id == org_id
        assert t.name == TargetName("My App")
        assert t.target_type == TargetType.RAG_SYSTEM
        assert t.provider == Provider.ANTHROPIC

    def test_register_emits_event(self) -> None:
        t = _register_target()
        events = t.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], TargetRegistered)

    def test_register_starts_with_no_tags(self) -> None:
        t = _register_target()
        assert len(t.tags) == 0

    def test_register_starts_with_no_policies(self) -> None:
        t = _register_target()
        assert len(t.policies) == 0


class TestRename:
    def test_rename(self) -> None:
        t = _register_target()
        t.collect_events()
        t.rename(TargetName("New Name"))
        assert t.name == TargetName("New Name")

    def test_rename_emits_event(self) -> None:
        t = _register_target(name=TargetName("Old"))
        t.collect_events()
        t.rename(TargetName("New"))
        events = t.collect_events()
        assert isinstance(events[0], TargetRenamed)
        assert events[0].old_name == "Old"
        assert events[0].new_name == "New"

    def test_rename_archived_raises(self) -> None:
        t = _register_target()
        t.archive()
        t.collect_events()
        with pytest.raises(TargetArchivedError):
            t.rename(TargetName("XX"))

    def test_rename_inactive_raises(self) -> None:
        t = _register_target()
        t.deactivate()
        t.collect_events()
        with pytest.raises(TargetInactiveError):
            t.rename(TargetName("XX"))


class TestChangeProvider:
    def test_change_provider(self) -> None:
        t = _register_target(provider=Provider.OPENAI)
        t.collect_events()
        t.change_provider(Provider.ANTHROPIC)
        assert t.provider == Provider.ANTHROPIC

    def test_same_provider_no_op(self) -> None:
        t = _register_target(provider=Provider.OPENAI)
        t.collect_events()
        t.change_provider(Provider.OPENAI)
        assert t.collect_events() == []

    def test_change_provider_emits_event(self) -> None:
        t = _register_target(provider=Provider.OPENAI)
        t.collect_events()
        t.change_provider(Provider.GOOGLE)
        events = t.collect_events()
        assert isinstance(events[0], TargetProviderChanged)


class TestChangeEndpoint:
    def test_change_endpoint(self) -> None:
        t = _register_target()
        t.collect_events()
        new_url = EndpointUrl("https://new-api.com/v2")
        t.change_endpoint(new_url)
        assert t.endpoint == new_url

    def test_change_endpoint_emits_event(self) -> None:
        t = _register_target()
        t.collect_events()
        t.change_endpoint(EndpointUrl("https://new.com"))
        events = t.collect_events()
        assert isinstance(events[0], TargetEndpointChanged)

    def test_same_endpoint_no_op(self) -> None:
        url = EndpointUrl("https://api.openai.com/v1/chat")
        t = _register_target(endpoint=url)
        t.collect_events()
        t.change_endpoint(url)
        assert t.collect_events() == []


class TestStatusTransitions:
    def test_deactivate(self) -> None:
        t = _register_target()
        t.collect_events()
        t.deactivate()
        assert t.status == TargetStatus.INACTIVE

    def test_activate_inactive(self) -> None:
        t = _register_target()
        t.deactivate()
        t.collect_events()
        t.activate()
        assert t.is_active is True

    def test_archive_active(self) -> None:
        t = _register_target()
        t.collect_events()
        t.archive()
        assert t.is_archived is True

    def test_archive_inactive(self) -> None:
        t = _register_target()
        t.deactivate()
        t.collect_events()
        t.archive()
        assert t.is_archived is True

    def test_restore_archived(self) -> None:
        t = _register_target()
        t.archive()
        t.collect_events()
        t.restore()
        assert t.status == TargetStatus.INACTIVE

    def test_activate_already_active_raises(self) -> None:
        t = _register_target()
        t.collect_events()
        with pytest.raises(InvalidTargetTransitionError):
            t.activate()

    def test_deactivate_inactive_raises(self) -> None:
        t = _register_target()
        t.deactivate()
        t.collect_events()
        with pytest.raises(InvalidTargetTransitionError):
            t.deactivate()

    def test_restore_non_archived_raises(self) -> None:
        t = _register_target()
        t.collect_events()
        with pytest.raises(InvalidTargetTransitionError):
            t.restore()

    def test_events_emitted(self) -> None:
        t = _register_target()
        t.collect_events()
        t.deactivate()
        t.activate()
        t.archive()
        events = t.collect_events()
        assert isinstance(events[0], TargetDeactivated)
        assert isinstance(events[1], TargetActivated)
        assert isinstance(events[2], TargetArchived)

    def test_restore_emits_event(self) -> None:
        t = _register_target()
        t.archive()
        t.collect_events()
        t.restore()
        events = t.collect_events()
        assert isinstance(events[0], TargetRestored)


class TestTags:
    def test_add_tag(self) -> None:
        t = _register_target()
        t.add_tag(Tag("env:prod"))
        assert Tag("env:prod") in t.tags

    def test_remove_tag(self) -> None:
        t = _register_target()
        t.add_tag(Tag("temp"))
        t.remove_tag(Tag("temp"))
        assert Tag("temp") not in t.tags

    def test_duplicate_tag_raises(self) -> None:
        t = _register_target()
        t.add_tag(Tag("env:prod"))
        with pytest.raises(DuplicateTagError):
            t.add_tag(Tag("env:prod"))

    def test_add_tag_archived_raises(self) -> None:
        t = _register_target()
        t.archive()
        with pytest.raises(TargetArchivedError):
            t.add_tag(Tag("x"))

    def test_tags_returns_frozenset(self) -> None:
        t = _register_target()
        t.add_tag(Tag("a"))
        assert isinstance(t.tags, frozenset)


class TestValidationPolicies:
    def test_attach_policy(self) -> None:
        t = _register_target()
        ref = ValidationPolicyReference("policy-1")
        t.attach_validation_policy(ref)
        assert ref in t.policies

    def test_detach_policy(self) -> None:
        t = _register_target()
        ref = ValidationPolicyReference("policy-1")
        t.attach_validation_policy(ref)
        t.detach_validation_policy(ref)
        assert ref not in t.policies

    def test_duplicate_attach_raises(self) -> None:
        t = _register_target()
        ref = ValidationPolicyReference("policy-1")
        t.attach_validation_policy(ref)
        with pytest.raises(PolicyAlreadyAttachedError):
            t.attach_validation_policy(ref)

    def test_detach_not_attached_raises(self) -> None:
        t = _register_target()
        with pytest.raises(PolicyNotAttachedError):
            t.detach_validation_policy(ValidationPolicyReference("nope"))

    def test_attach_emits_event(self) -> None:
        t = _register_target()
        t.collect_events()
        t.attach_validation_policy(ValidationPolicyReference("p1"))
        events = t.collect_events()
        assert isinstance(events[0], ValidationPolicyAttached)

    def test_detach_emits_event(self) -> None:
        t = _register_target()
        ref = ValidationPolicyReference("p1")
        t.attach_validation_policy(ref)
        t.collect_events()
        t.detach_validation_policy(ref)
        events = t.collect_events()
        assert isinstance(events[0], ValidationPolicyDetached)

    def test_attach_archived_raises(self) -> None:
        t = _register_target()
        t.archive()
        with pytest.raises(TargetArchivedError):
            t.attach_validation_policy(ValidationPolicyReference("policy-x"))

    def test_attach_inactive_raises(self) -> None:
        t = _register_target()
        t.deactivate()
        with pytest.raises(TargetInactiveError):
            t.attach_validation_policy(ValidationPolicyReference("policy-x"))


class TestMetadata:
    def test_update_metadata(self) -> None:
        t = _register_target()
        t.update_metadata("model", "gpt-4")
        assert t.metadata.get("model") == "gpt-4"

    def test_remove_metadata(self) -> None:
        t = _register_target()
        t.update_metadata("k", "v")
        t.remove_metadata("k")
        assert t.metadata.get("k") is None

    def test_metadata_archived_raises(self) -> None:
        t = _register_target()
        t.archive()
        with pytest.raises(TargetArchivedError):
            t.update_metadata("k", "v")


class TestEquality:
    def test_same_id_equal(self) -> None:
        t = _register_target()
        t2 = AITarget(
            id=t.id,
            organization_id=EntityId.generate(),
            name=TargetName("Different"),
            description="",
            target_type=TargetType.AI_API,
            provider=Provider.CUSTOM,
            endpoint=EndpointUrl("https://x.com"),
            auth_reference=None,
            status=TargetStatus.INACTIVE,
            tags=set(),
            policies=set(),
            metadata=t.metadata,
            timestamps=t.timestamps,
        )
        assert t == t2

    def test_different_id_not_equal(self) -> None:
        t1 = _register_target()
        t2 = _register_target()
        assert t1 != t2

    def test_hashable(self) -> None:
        t = _register_target()
        assert len({t, t}) == 1
