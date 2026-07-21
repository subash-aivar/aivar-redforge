"""0085 — M32 Phase 5 BusinessImpactMapping persistence.

Maps frozen plan migration 0049 onto the live Alembic chain after 0084:
- business_impact_mappings

Migration chain: 0084 → 0085.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0085"
down_revision: str = "0084"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "business_impact_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_ref_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("criticality", sa.String(64), nullable=False),
        sa.Column("impact_domain", sa.String(64), nullable=False),
        sa.Column("authored_by", sa.String(256), nullable=False),
        sa.Column("business_process_ref", sa.String(256), nullable=True),
        sa.Column("business_unit_ref", sa.String(256), nullable=True),
        sa.Column("financial_impact_estimate", sa.Float(), nullable=True),
        sa.Column("regulatory_scope_json", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "asset_ref_id",
            name="uq_bim_tenant_asset",
        ),
        schema="exposure_reporting",
    )
    op.create_index(
        "ix_business_impact_mappings_tenant_id",
        "business_impact_mappings",
        ["tenant_id"],
        schema="exposure_reporting",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_business_impact_mappings_tenant_id",
        table_name="business_impact_mappings",
        schema="exposure_reporting",
    )
    op.drop_table("business_impact_mappings", schema="exposure_reporting")
