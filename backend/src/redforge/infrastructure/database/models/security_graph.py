"""SQLAlchemy ORM models for the Security Graph projection — M4.

Canonical identity is NOT the primary key column — it's the unique
constraint on (organization_id, source_domain, source_entity_id) for
nodes and (organization_id, source_node_id, relationship_kind,
target_node_id) for edges. `id` is a surface identifier used by APIs
and edge foreign keys, not itself the dedup key.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class SecurityGraphNodeModel(Base):
    __tablename__ = "security_graph_nodes"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_sg_nodes_id_org"),
        UniqueConstraint(
            "organization_id", "source_domain", "source_entity_id",
            name="ux_sg_nodes_org_domain_entity",
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    node_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    source_domain: Mapped[str] = mapped_column(String(50), nullable=False)
    source_entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    ontology_version: Mapped[int] = mapped_column(Integer, nullable=False)
    first_projected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_projected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SecurityGraphEdgeModel(Base):
    __tablename__ = "security_graph_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["source_node_id", "organization_id"],
            ["security_graph_nodes.id", "security_graph_nodes.organization_id"],
            name="fk_sg_edges_source_same_tenant",
        ),
        ForeignKeyConstraint(
            ["target_node_id", "organization_id"],
            ["security_graph_nodes.id", "security_graph_nodes.organization_id"],
            name="fk_sg_edges_target_same_tenant",
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    source_node_id: Mapped[str] = mapped_column(String(26), nullable=False)
    target_node_id: Mapped[str] = mapped_column(String(26), nullable=False)
    relationship_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    provenance: Mapped[str] = mapped_column(String(100), nullable=False)
    ontology_version: Mapped[int] = mapped_column(Integer, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
