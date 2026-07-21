"""0075 — M30 Phase 5 scenario platform subscription distribution.

Adds subscription_json and source_template_id to scenario.scenario_templates
so platform-published templates can be subscribed (tenant-local copies),
matching the M28 DetectionPack distribution model (freeze §17).

Migration chain: 0074 → 0075.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0075"
down_revision: str = "0074"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scenario_templates",
        sa.Column(
            "subscription_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        schema="scenario",
    )
    op.add_column(
        "scenario_templates",
        sa.Column(
            "source_template_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        schema="scenario",
    )
    op.create_index(
        "ix_scenario_templates_source_template_id",
        "scenario_templates",
        ["source_template_id"],
        schema="scenario",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scenario_templates_source_template_id",
        table_name="scenario_templates",
        schema="scenario",
    )
    op.drop_column("scenario_templates", "source_template_id", schema="scenario")
    op.drop_column("scenario_templates", "subscription_json", schema="scenario")
