"""Security Graph ontology & projection foundation — M4.

Adds:
  - security_graph_nodes: tenant-scoped projected graph nodes. A node's
    canonical identity is (organization_id, source_domain,
    source_entity_id) — NOT the graph node's own primary key — so
    reprojecting the same domain entity is idempotent (upsert on this
    unique key, never a duplicate insert). `attributes` holds only
    safe, projection-owned display data (never full mutable aggregate
    state, never secrets — see M4 secret-leakage sentinel tests).
  - security_graph_edges: tenant-scoped projected graph edges. Canonical
    edge identity is (organization_id, source_node_id, relationship_kind,
    target_node_id) — concurrent duplicate projection of the same edge
    upserts the same row rather than creating a second one.

Tenant integrity for edges is enforced at the DATABASE level, not just
in application code: `security_graph_nodes` carries a UNIQUE(id,
organization_id) constraint (redundant with the id primary key, but
required so a composite foreign key can reference it), and
`security_graph_edges.(source_node_id, organization_id)` /
`(target_node_id, organization_id)` are composite foreign keys against
it. This makes a cross-tenant edge — a source or target node belonging
to a different organization than the edge itself — a foreign-key
violation, not merely an application-logic bug: PostgreSQL physically
cannot store the row.

Revision ID: 0014
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str = "0013"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.create_table(
        "security_graph_nodes",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("node_kind", sa.String(30), nullable=False),
        sa.Column("source_domain", sa.String(50), nullable=False),
        sa.Column("source_entity_id", sa.String(255), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column("attributes", sa.JSON, nullable=False),
        sa.Column("ontology_version", sa.Integer, nullable=False),
        sa.Column("first_projected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_projected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.UniqueConstraint("id", "organization_id", name="ux_sg_nodes_id_org"),
    )
    op.create_index("ix_sg_nodes_organization_id", "security_graph_nodes", ["organization_id"])
    op.create_index(
        "ux_sg_nodes_org_source",
        "security_graph_nodes",
        ["organization_id", "source_domain", "source_entity_id"],
        unique=True,
    )

    op.create_table(
        "security_graph_edges",
        sa.Column("id", sa.String(26), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("source_node_id", sa.String(26), nullable=False),
        sa.Column("target_node_id", sa.String(26), nullable=False),
        sa.Column("relationship_kind", sa.String(30), nullable=False),
        sa.Column("provenance", sa.String(100), nullable=False),
        sa.Column("ontology_version", sa.Integer, nullable=False),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(
            ["source_node_id", "organization_id"],
            ["security_graph_nodes.id", "security_graph_nodes.organization_id"],
            name="fk_sg_edges_source_same_tenant",
        ),
        sa.ForeignKeyConstraint(
            ["target_node_id", "organization_id"],
            ["security_graph_nodes.id", "security_graph_nodes.organization_id"],
            name="fk_sg_edges_target_same_tenant",
        ),
    )
    op.create_index("ix_sg_edges_organization_id", "security_graph_edges", ["organization_id"])
    op.create_index("ix_sg_edges_source_node_id", "security_graph_edges", ["source_node_id"])
    op.create_index("ix_sg_edges_target_node_id", "security_graph_edges", ["target_node_id"])
    op.create_index(
        "ux_sg_edges_org_source_kind_target",
        "security_graph_edges",
        ["organization_id", "source_node_id", "relationship_kind", "target_node_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ux_sg_edges_org_source_kind_target", table_name="security_graph_edges")
    op.drop_index("ix_sg_edges_target_node_id", table_name="security_graph_edges")
    op.drop_index("ix_sg_edges_source_node_id", table_name="security_graph_edges")
    op.drop_index("ix_sg_edges_organization_id", table_name="security_graph_edges")
    op.drop_table("security_graph_edges")

    op.drop_index("ux_sg_nodes_org_source", table_name="security_graph_nodes")
    op.drop_index("ix_sg_nodes_organization_id", table_name="security_graph_nodes")
    op.drop_table("security_graph_nodes")
