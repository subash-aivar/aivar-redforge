"""Unit tests for Attack Taxonomy use cases — key uniqueness, parent
existence, and cycle prevention on reparent, all enforced at this layer
(the entity itself has no repository access to check these)."""

from __future__ import annotations

import pytest

from redforge.domain.attack_library.taxonomy import (
    AttackTaxonomyNode,
    DuplicateTaxonomyKeyError,
    TaxonomyCycleError,
    TaxonomyNodeNotFoundError,
)
from redforge.domain.attack_library.taxonomy_use_cases import (
    CreateTaxonomyNodeUseCase,
    DeprecateTaxonomyNodeUseCase,
    GetTaxonomyPathUseCase,
    ListChildrenUseCase,
    ListDescendantsUseCase,
    MoveTaxonomyNodeUseCase,
)
from redforge.shared.identifiers import EntityId


class InMemoryAttackTaxonomyRepository:
    """A trivial, correct-by-inspection in-memory implementation of
    AttackTaxonomyRepository — enough to exercise the use cases'
    orchestration logic without any infrastructure."""

    def __init__(self) -> None:
        self._nodes: dict[str, AttackTaxonomyNode] = {}

    async def get_by_id(self, node_id: EntityId) -> AttackTaxonomyNode | None:
        return self._nodes.get(str(node_id))

    async def get_by_key(self, key: str) -> AttackTaxonomyNode | None:
        normalized = key.strip().lower()
        for node in self._nodes.values():
            if str(node.key) == normalized:
                return node
        return None

    async def get_children(self, parent_id: EntityId | None) -> list[AttackTaxonomyNode]:
        target = str(parent_id) if parent_id is not None else None
        return [
            n for n in self._nodes.values()
            if (str(n.parent_id) if n.parent_id is not None else None) == target
        ]

    async def get_ancestors(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        chain: list[AttackTaxonomyNode] = []
        current = self._nodes.get(str(node_id))
        if current is None:
            return chain
        while current.parent_id is not None:
            parent = self._nodes.get(str(current.parent_id))
            if parent is None:
                break
            chain.append(parent)
            current = parent
        chain.reverse()
        return chain

    async def get_descendants(self, node_id: EntityId) -> list[AttackTaxonomyNode]:
        result: list[AttackTaxonomyNode] = []
        frontier = [node_id]
        while frontier:
            parent = frontier.pop()
            children = await self.get_children(parent)
            for child in children:
                result.append(child)
                frontier.append(child.id)
        return result

    async def save(self, node: AttackTaxonomyNode) -> None:
        self._nodes[str(node.id)] = node


@pytest.fixture
def repo() -> InMemoryAttackTaxonomyRepository:
    return InMemoryAttackTaxonomyRepository()


class TestCreateTaxonomyNodeUseCase:
    async def test_creates_root_node(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        result = await CreateTaxonomyNodeUseCase(repo).execute(
            key="prompt_injection", name="Prompt Injection", description="...",
        )
        assert result.key == "prompt_injection"
        assert result.parent_id is None

    async def test_creates_child_node(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        root = await CreateTaxonomyNodeUseCase(repo).execute(
            key="prompt_injection", name="Prompt Injection", description="...",
        )
        child = await CreateTaxonomyNodeUseCase(repo).execute(
            key="indirect_injection", name="Indirect", description="...",
            parent_id=root.id,
        )
        assert child.parent_id == root.id

    async def test_duplicate_key_raises(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        await CreateTaxonomyNodeUseCase(repo).execute(
            key="jailbreak", name="Jailbreak", description="...",
        )
        with pytest.raises(DuplicateTaxonomyKeyError):
            await CreateTaxonomyNodeUseCase(repo).execute(
                key="jailbreak", name="Jailbreak Again", description="...",
            )

    async def test_duplicate_key_case_insensitive(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        await CreateTaxonomyNodeUseCase(repo).execute(
            key="jailbreak", name="Jailbreak", description="...",
        )
        with pytest.raises(DuplicateTaxonomyKeyError):
            await CreateTaxonomyNodeUseCase(repo).execute(
                key="JAILBREAK", name="Jailbreak", description="...",
            )

    async def test_nonexistent_parent_raises(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        with pytest.raises(TaxonomyNodeNotFoundError):
            await CreateTaxonomyNodeUseCase(repo).execute(
                key="orphan", name="Orphan", description="...",
                parent_id=str(EntityId.generate()),
            )


class TestMoveTaxonomyNodeUseCase:
    async def _make_chain(
        self, repo: InMemoryAttackTaxonomyRepository, depth: int,
    ) -> list[str]:
        """Create a linear chain root -> child -> grandchild -> ..."""
        ids: list[str] = []
        parent_id: str | None = None
        for i in range(depth):
            node = await CreateTaxonomyNodeUseCase(repo).execute(
                key=f"node_{i}", name=f"Chain Node {i}", description="...", parent_id=parent_id,
            )
            ids.append(node.id)
            parent_id = node.id
        return ids

    async def test_moves_to_new_parent(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        b = await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...",
        )
        moved = await MoveTaxonomyNodeUseCase(repo).execute(b.id, a.id)
        assert moved.parent_id == a.id

    async def test_moves_to_root(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        b = await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...", parent_id=a.id,
        )
        moved = await MoveTaxonomyNodeUseCase(repo).execute(b.id, None)
        assert moved.parent_id is None

    async def test_self_parent_raises_cycle(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        with pytest.raises(TaxonomyCycleError):
            await MoveTaxonomyNodeUseCase(repo).execute(a.id, a.id)

    async def test_move_under_own_descendant_raises_cycle(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        """The classic cycle: A -> B -> C, then try to move A under C."""
        ids = await self._make_chain(repo, 3)
        root_id, _mid_id, leaf_id = ids
        with pytest.raises(TaxonomyCycleError):
            await MoveTaxonomyNodeUseCase(repo).execute(root_id, leaf_id)

    async def test_move_under_direct_child_raises_cycle(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        ids = await self._make_chain(repo, 2)
        root_id, child_id = ids
        with pytest.raises(TaxonomyCycleError):
            await MoveTaxonomyNodeUseCase(repo).execute(root_id, child_id)

    async def test_move_unrelated_subtree_is_fine(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        """Moving a node under an unrelated node (not its own
        descendant) must succeed — cycle check must not be overbroad."""
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        b = await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...",
        )
        c = await CreateTaxonomyNodeUseCase(repo).execute(
            key="c", name="Node C", description="...", parent_id=a.id,
        )
        moved = await MoveTaxonomyNodeUseCase(repo).execute(c.id, b.id)
        assert moved.parent_id == b.id

    async def test_nonexistent_node_raises(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        with pytest.raises(TaxonomyNodeNotFoundError):
            await MoveTaxonomyNodeUseCase(repo).execute(str(EntityId.generate()), None)

    async def test_nonexistent_new_parent_raises(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        with pytest.raises(TaxonomyNodeNotFoundError):
            await MoveTaxonomyNodeUseCase(repo).execute(a.id, str(EntityId.generate()))


class TestGetTaxonomyPathUseCase:
    async def test_root_path_is_single_node(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        path = await GetTaxonomyPathUseCase(repo).execute(a.id)
        assert [n.id for n in path] == [a.id]

    async def test_deep_path_is_root_first(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        b = await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...", parent_id=a.id,
        )
        c = await CreateTaxonomyNodeUseCase(repo).execute(
            key="c", name="Node C", description="...", parent_id=b.id,
        )
        path = await GetTaxonomyPathUseCase(repo).execute(c.id)
        assert [n.id for n in path] == [a.id, b.id, c.id]

    async def test_nonexistent_node_raises(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        with pytest.raises(TaxonomyNodeNotFoundError):
            await GetTaxonomyPathUseCase(repo).execute(str(EntityId.generate()))


class TestListChildrenAndDescendants:
    async def test_list_roots(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        await CreateTaxonomyNodeUseCase(repo).execute(key="a", name="Node A", description="...")
        await CreateTaxonomyNodeUseCase(repo).execute(key="b", name="Node B", description="...")
        roots = await ListChildrenUseCase(repo).execute(None)
        assert {r.key for r in roots} == {"a", "b"}

    async def test_list_children_of_node(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...", parent_id=a.id,
        )
        children = await ListChildrenUseCase(repo).execute(a.id)
        assert len(children) == 1
        assert children[0].key == "b"

    async def test_list_descendants_multi_level(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        b = await CreateTaxonomyNodeUseCase(repo).execute(
            key="b", name="Node B", description="...", parent_id=a.id,
        )
        await CreateTaxonomyNodeUseCase(repo).execute(
            key="c", name="Node C", description="...", parent_id=b.id,
        )
        descendants = await ListDescendantsUseCase(repo).execute(a.id)
        assert {d.key for d in descendants} == {"b", "c"}

    async def test_list_descendants_of_leaf_is_empty(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        assert await ListDescendantsUseCase(repo).execute(a.id) == []

    async def test_list_descendants_nonexistent_raises(
        self, repo: InMemoryAttackTaxonomyRepository,
    ) -> None:
        with pytest.raises(TaxonomyNodeNotFoundError):
            await ListDescendantsUseCase(repo).execute(str(EntityId.generate()))


class TestDeprecateTaxonomyNodeUseCase:
    async def test_deprecates(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        a = await CreateTaxonomyNodeUseCase(repo).execute(
            key="a", name="Node A", description="...",
        )
        deprecated = await DeprecateTaxonomyNodeUseCase(repo).execute(a.id)
        assert deprecated.is_active is False

    async def test_nonexistent_raises(self, repo: InMemoryAttackTaxonomyRepository) -> None:
        with pytest.raises(TaxonomyNodeNotFoundError):
            await DeprecateTaxonomyNodeUseCase(repo).execute(str(EntityId.generate()))
