"""Security Graph REST API — M4.

Tenant-scoped throughout: `organization_id` is ALWAYS `tenant.organization_id`
from the verified JWT. The graph is a read-only projection surface for
ordinary tenant callers — there is deliberately no `POST /nodes` or
`POST /edges`; nodes/edges are written exclusively by
SecurityGraphProjector from trusted domain data (see
application/security_graph/projector.py).
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from redforge.api.dependencies import get_tenant_security_graph_service
from redforge.api.security import TenantContext, require_permission
from redforge.application.security_graph.query_service import Direction
from redforge.core.exceptions import NotFoundError, ValidationError
from redforge.domain.identity.value_objects import Permission

if TYPE_CHECKING:
    from redforge.application.security_graph.query_service import TenantSecurityGraphService

router = APIRouter(prefix="/security-graph", tags=["security-graph"])


class NodeResponse(BaseModel):
    id: str
    node_kind: str
    label: str
    source_domain: str
    source_entity_id: str
    attributes: dict[str, str]
    ontology_version: int


class EdgeResponse(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    relationship_kind: str
    provenance: str


class GraphOverviewResponse(BaseModel):
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]
    node_count: int
    truncated: bool


class NodeDetailResponse(BaseModel):
    node: NodeResponse
    inbound_count: int
    outbound_count: int


class NeighborResponse(BaseModel):
    node: NodeResponse
    via_edge: EdgeResponse


class PathQueryRequest(BaseModel):
    start_node_id: str
    end_node_id: str
    max_depth: int = 4
    relationship_kinds: list[str] | None = None


class SecurityRelationshipPathResponse(BaseModel):
    node_ids: list[str]
    edge_ids: list[str]


class PathQueryResponse(BaseModel):
    paths: list[SecurityRelationshipPathResponse]


@router.get("", response_model=GraphOverviewResponse)
async def get_overview(
    node_kind: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityGraphService = Depends(get_tenant_security_graph_service),
) -> GraphOverviewResponse:
    overview = await service.overview(tenant.organization_id, node_kind, limit)
    return GraphOverviewResponse(
        nodes=[NodeResponse(**dataclasses.asdict(n)) for n in overview.nodes],
        edges=[EdgeResponse(**dataclasses.asdict(e)) for e in overview.edges],
        node_count=overview.node_count,
        truncated=overview.truncated,
    )


@router.get("/nodes/{node_id}", response_model=NodeDetailResponse)
async def get_node(
    node_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityGraphService = Depends(get_tenant_security_graph_service),
) -> NodeDetailResponse:
    """404s identically for a nonexistent node ID or one owned by
    another organization."""
    try:
        detail = await service.get_node(tenant.organization_id, node_id)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return NodeDetailResponse(
        node=NodeResponse(**dataclasses.asdict(detail.node)),
        inbound_count=detail.inbound_count,
        outbound_count=detail.outbound_count,
    )


@router.get("/nodes/{node_id}/neighbors", response_model=list[NeighborResponse])
async def get_neighbors(
    node_id: str,
    direction: Direction = Query(default=Direction.BOTH),
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityGraphService = Depends(get_tenant_security_graph_service),
) -> list[NeighborResponse]:
    try:
        neighbors = await service.get_neighbors(tenant.organization_id, node_id, direction)
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    return [
        NeighborResponse(
            node=NodeResponse(**dataclasses.asdict(n.node)),
            via_edge=EdgeResponse(**dataclasses.asdict(n.via_edge)),
        )
        for n in neighbors
    ]


@router.post("/paths/query", response_model=PathQueryResponse)
async def query_paths(
    body: PathQueryRequest,
    tenant: TenantContext = Depends(require_permission(Permission.TARGETS_READ)),
    service: TenantSecurityGraphService = Depends(get_tenant_security_graph_service),
) -> PathQueryResponse:
    """Bounded, cycle-safe Security Relationship Path query — NOT an
    attack path (no exploitability/probability is computed)."""
    try:
        paths = await service.find_paths(
            tenant.organization_id,
            body.start_node_id,
            body.end_node_id,
            body.max_depth,
            body.relationship_kinds,
        )
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=exc.message) from exc
    except ValidationError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=exc.message) from exc
    return PathQueryResponse(
        paths=[SecurityRelationshipPathResponse(**dataclasses.asdict(p)) for p in paths]
    )
