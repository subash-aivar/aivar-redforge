"""Dependency resolver — resolves asset dependencies and detects cycles.

Builds a dependency graph from normalized asset inputs. Detects circular
dependencies using DFS before adding any edge. Returns AssetDependencyRef
objects that the inventory service attaches to their respective assets.

No switch statements. Pure graph algorithms over dict adjacency lists.
"""

from __future__ import annotations

from redforge.application.inventory.contracts import (
    NormalizedAssetInput,
)
from redforge.domain.inventory.value_objects import (
    AssetDependencyRef,
    AssetRelationshipType,
)

if False:  # TYPE_CHECKING
    from redforge.domain.inventory.entity import AIAsset

# Map from (requester_type, dependency_type) -> AssetRelationshipType
# Dict-dispatched so no switch statements are needed.
_TYPE_TO_REL: dict[tuple[str, str], AssetRelationshipType] = {
    ("ai_agent", "ai_model"): AssetRelationshipType.AGENT_USES_MODEL,
    ("ai_agent", "mcp_server"): AssetRelationshipType.AGENT_USES_MCP,
    ("ai_agent", "memory_store"): AssetRelationshipType.AGENT_USES_MEMORY,
    ("ai_agent", "rag_system"): AssetRelationshipType.AGENT_USES_RAG,
    ("ai_agent", "tool_definition"): AssetRelationshipType.AGENT_USES_TOOL,
    ("ai_application", "ai_agent"): AssetRelationshipType.APP_OWNS_AGENT,
    ("rag_system", "vector_database"): AssetRelationshipType.RAG_USES_VECTOR_DB,
    ("rag_system", "knowledge_base"): AssetRelationshipType.RAG_USES_KNOWLEDGE_BASE,
    ("rag_system", "embedding_model"): AssetRelationshipType.RAG_USES_EMBEDDING_MODEL,
    ("ai_provider", "ai_model"): AssetRelationshipType.PROVIDER_HOSTS_MODEL,
    ("ai_model", "ai_endpoint"): AssetRelationshipType.MODEL_SERVES_ENDPOINT,
    ("knowledge_base", "vector_database"): AssetRelationshipType.KNOWLEDGE_BASE_BACKED_BY,
    ("ai_application", "ai_model"): AssetRelationshipType.AGENT_USES_MODEL,
}

_DEFAULT_REL = AssetRelationshipType.CUSTOM


def _infer_relationship_type(
    requester_type: str, dependency_type: str
) -> AssetRelationshipType:
    return _TYPE_TO_REL.get((requester_type, dependency_type), _DEFAULT_REL)


class DefaultDependencyResolver:
    """Resolves asset dependencies and detects cycles.

    Implements DependencyResolverPort.
    """

    def resolve(
        self,
        assets: list[AIAsset],
        inputs: list[NormalizedAssetInput],
    ) -> list[AssetDependencyRef]:
        """Resolve all dependency references from inputs.

        Matches dependency_external_ids against the known assets by external_id.
        Returns flat list of (asset_id, dep_ref) pairs — caller attaches them.
        """
        # Build ext_id -> (asset, asset_type) index
        ext_index: dict[str, tuple[str, str]] = {}
        for asset in assets:
            ext_index[asset.external_id] = (str(asset.id), asset.asset_type.value)

        # Also include assets from this same batch (not yet persisted)
        for inp in inputs:
            if inp.external_id not in ext_index:
                # Placeholder: will be resolved after batch save
                ext_index[inp.external_id] = ("", inp.asset_type)

        results: list[AssetDependencyRef] = []
        for inp in inputs:
            for dep_ext_id in inp.dependency_external_ids:
                resolved = ext_index.get(dep_ext_id)
                if resolved is None or resolved[0] == "":
                    continue
                dep_asset_id, dep_type = resolved
                rel_type = _infer_relationship_type(inp.asset_type, dep_type)
                dep = AssetDependencyRef(
                    dependency_id=dep_asset_id,
                    relationship_type=rel_type,
                    is_required=True,
                )
                results.append(dep)

        return results

    def has_cycle(
        self,
        assets: list[AIAsset],
        candidate_dep_id: str,
        from_asset_id: str,
    ) -> bool:
        """Return True if adding candidate_dep_id as dependency of from_asset_id
        would create a cycle.

        Uses iterative DFS on the existing dependency graph.
        """
        # Build adjacency: asset_id -> set of dependency_ids
        adj: dict[str, set[str]] = {str(a.id): set() for a in assets}
        for asset in assets:
            for dep in asset.dependencies:
                adj[str(asset.id)].add(dep.dependency_id)

        # Simulate adding the new edge
        if from_asset_id not in adj:
            adj[from_asset_id] = set()
        adj[from_asset_id].add(candidate_dep_id)

        # DFS to detect if from_asset_id is reachable from candidate_dep_id
        visited: set[str] = set()
        stack = [candidate_dep_id]
        while stack:
            current = stack.pop()
            if current == from_asset_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            stack.extend(adj.get(current, set()))

        return False

    def topological_sort(self, assets: list[AIAsset]) -> list[AIAsset]:
        """Return assets in dependency order (dependencies first).

        Kahn's algorithm. Assumes no cycles (check has_cycle first).
        Returns original list order if no dependencies exist.
        """
        id_to_asset = {str(a.id): a for a in assets}
        in_degree: dict[str, int] = {str(a.id): 0 for a in assets}
        adj: dict[str, list[str]] = {str(a.id): [] for a in assets}

        for asset in assets:
            for dep in asset.dependencies:
                if dep.dependency_id in in_degree:
                    in_degree[str(asset.id)] += 1
                    adj[dep.dependency_id].append(str(asset.id))

        queue = [aid for aid, deg in in_degree.items() if deg == 0]
        result: list[AIAsset] = []

        while queue:
            node = queue.pop(0)
            if node in id_to_asset:
                result.append(id_to_asset[node])
            for neighbor in adj.get(node, []):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Append any remaining (cycle participants — defensive)
        seen = {str(a.id) for a in result}
        result.extend(a for a in assets if str(a.id) not in seen)
        return result


def build_dependency_graph(
    assets: list[AIAsset],
) -> dict[str, set[str]]:
    """Build a simple adjacency dict: asset_id -> set of dependency_ids."""
    graph: dict[str, set[str]] = {}
    for asset in assets:
        graph[str(asset.id)] = {d.dependency_id for d in asset.dependencies}
    return graph


def compute_dependency_depth(
    asset_id: str,
    graph: dict[str, set[str]],
) -> int:
    """Return the maximum dependency depth for an asset (0 = no dependencies)."""
    visited: set[str] = set()
    max_depth = 0

    def _dfs(node: str, depth: int) -> None:
        nonlocal max_depth
        if node in visited:
            return
        visited.add(node)
        max_depth = max(max_depth, depth)
        for dep_id in graph.get(node, set()):
            _dfs(dep_id, depth + 1)

    _dfs(asset_id, 0)
    return max_depth
