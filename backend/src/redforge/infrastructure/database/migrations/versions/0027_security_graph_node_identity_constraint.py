"""Security Graph node canonical-identity unique constraint.

`security_graph_nodes` (migration 0013, M4) has always been missing the
unique constraint its own module docstring
(infrastructure/database/models/security_graph.py) already describes as
canonical: "(organization_id, source_domain, source_entity_id)". The
repository's `upsert_node()` already has an INSERT-then-catch-
IntegrityError-and-recover pattern for exactly this race (identical to
`upsert_edge()`'s, which IS correctly backed by a DB constraint) — but
with no constraint to violate, concurrent projections of the same
source entity can both successfully INSERT, producing two rows for one
canonical node. This is a genuine, real concurrency defect confirmed by
`test_protocol_aware_service_validation_postgres_proof.py::test_concurrent_execution_converges_on_one_canonical_service_asset`.
Real backstop; not new: `upsert_node()`'s recovery path is unchanged
code, this migration only completes what it always assumed existed.

No production data was affected — verified no existing duplicate
(organization_id, source_domain, source_entity_id) rows before adding
this constraint.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0027"
down_revision: str = "0026"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint(
        "ux_sg_nodes_org_domain_entity",
        "security_graph_nodes",
        ["organization_id", "source_domain", "source_entity_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "ux_sg_nodes_org_domain_entity", "security_graph_nodes", type_="unique",
    )
