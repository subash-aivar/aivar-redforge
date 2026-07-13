"""Unit tests for AttackTaxonomyNode and TaxonomyNodeKey."""

import pytest

from redforge.domain.attack_library.taxonomy import (
    AttackTaxonomyNode,
    TaxonomyNodeInactiveError,
    TaxonomyNodeKey,
)
from redforge.domain.attack_library.value_objects import FrameworkMapping
from redforge.shared.identifiers import EntityId


class TestTaxonomyNodeKey:
    def test_normalizes_case_and_whitespace(self) -> None:
        assert str(TaxonomyNodeKey("  Prompt_Injection  ")) == "prompt_injection"

    def test_equal_by_normalized_value(self) -> None:
        assert TaxonomyNodeKey("mcp_abuse") == TaxonomyNodeKey("MCP_Abuse")

    def test_hashable(self) -> None:
        assert len({TaxonomyNodeKey("a"), TaxonomyNodeKey("a")}) == 1

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            TaxonomyNodeKey("   ")

    def test_too_long_raises(self) -> None:
        with pytest.raises(ValueError, match="64"):
            TaxonomyNodeKey("a" * 65)

    @pytest.mark.parametrize(
        "bad_key", ["-leading-dash", "trailing_", "_leading", "has space", "Has$ymbol"]
    )
    def test_invalid_format_raises(self, bad_key: str) -> None:
        with pytest.raises(ValueError, match="snake_case"):
            TaxonomyNodeKey(bad_key)

    def test_single_char_allowed(self) -> None:
        assert str(TaxonomyNodeKey("a")) == "a"


def _create_node(
    key: str = "prompt_injection", parent_id: EntityId | None = None,
) -> AttackTaxonomyNode:
    return AttackTaxonomyNode.create(
        key=key, name="Prompt Injection", description="Injecting instructions",
        parent_id=parent_id,
    )


class TestCreate:
    def test_creates_active_root_by_default(self) -> None:
        node = _create_node()
        assert node.is_active is True
        assert node.is_root is True
        assert node.parent_id is None

    def test_creates_child_with_parent(self) -> None:
        parent_id = EntityId.generate()
        node = _create_node(parent_id=parent_id)
        assert node.is_root is False
        assert node.parent_id == parent_id

    def test_short_name_raises(self) -> None:
        with pytest.raises(ValueError, match="2 characters"):
            AttackTaxonomyNode.create(key="x", name="A", description="")

    def test_each_node_gets_unique_id(self) -> None:
        assert _create_node("a").id != _create_node("b").id


class TestRename:
    def test_renames(self) -> None:
        node = _create_node()
        node.rename("Indirect Prompt Injection")
        assert node.name == "Indirect Prompt Injection"

    def test_renames_with_description(self) -> None:
        node = _create_node()
        node.rename("New Name", "New description")
        assert node.name == "New Name"
        assert node.description == "New description"

    def test_rename_keeps_description_when_not_given(self) -> None:
        node = _create_node()
        original = node.description
        node.rename("New Name")
        assert node.description == original

    def test_rename_short_raises(self) -> None:
        node = _create_node()
        with pytest.raises(ValueError, match="2 characters"):
            node.rename("A")


class TestReparent:
    def test_reparent_to_new_parent(self) -> None:
        node = _create_node()
        new_parent = EntityId.generate()
        node.reparent(new_parent)
        assert node.parent_id == new_parent

    def test_reparent_to_root(self) -> None:
        node = _create_node(parent_id=EntityId.generate())
        node.reparent(None)
        assert node.is_root is True


class TestDeprecateReactivate:
    def test_deprecate(self) -> None:
        node = _create_node()
        node.deprecate()
        assert node.is_active is False

    def test_deprecate_twice_raises(self) -> None:
        node = _create_node()
        node.deprecate()
        with pytest.raises(TaxonomyNodeInactiveError):
            node.deprecate()

    def test_reactivate(self) -> None:
        node = _create_node()
        node.deprecate()
        node.reactivate()
        assert node.is_active is True


class TestFrameworkMappings:
    def test_map_to_framework(self) -> None:
        node = _create_node()
        mapping = FrameworkMapping(framework="MITRE_ATLAS", identifier="AML.T0051")
        node.map_to_framework(mapping)
        assert mapping in node.framework_mappings

    def test_remove_framework_mapping(self) -> None:
        node = _create_node()
        mapping = FrameworkMapping(framework="OWASP_GENAI", identifier="LLM01")
        node.map_to_framework(mapping)
        node.remove_framework_mapping(mapping)
        assert mapping not in node.framework_mappings


class TestEquality:
    def test_same_id_equal(self) -> None:
        node = _create_node()
        other = AttackTaxonomyNode(
            id=node.id, key=TaxonomyNodeKey("different_key"), name="Different",
            description="", parent_id=None, is_active=False,
            framework_mappings=set(), timestamps=node.timestamps,
        )
        assert node == other

    def test_different_id_not_equal(self) -> None:
        assert _create_node("a") != _create_node("b")

    def test_hashable(self) -> None:
        assert len({_create_node(), _create_node()}) == 2
