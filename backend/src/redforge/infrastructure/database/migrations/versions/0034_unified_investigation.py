"""Unified Cross-Domain Investigation — M21.

Creates four tables:
  investigations                     — case aggregate with lifecycle + versioning
  investigation_evidence_links       — case-to-source-evidence mapping (idempotent)
  investigation_events               — append-only case timeline entries
  investigation_correlation_cursors  — per-source worker watermarks

The partial unique index on investigations enforces exactly-one-active-case
per (organization_id, correlation_key) while status != 'RESOLVED',
matching the DDoS/behavior advisory-lock + partial-index pattern from M19/M20.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str = "0033"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_ACTIVE_STATES = "status != 'RESOLVED'"
_ACTIVE_INDEX = "ux_inv_org_corr_active"


def upgrade() -> None:
    # investigations
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("summary", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.String(30), nullable=False, server_default="OPEN"),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(20), nullable=False),
        sa.Column("correlation_key", sa.String(600), nullable=False),
        sa.Column("source_domains", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("involved_entities", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("evidence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("first_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("investigating_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolution_reason", sa.String(60), nullable=True),
        sa.Column("resolution_notes", sa.Text, nullable=False, server_default=""),
        sa.Column("version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint("ux_inv_id_org", "investigations", ["id", "organization_id"])
    op.create_index("ix_inv_org_status", "investigations", ["organization_id", "status"])
    op.create_index("ix_inv_org_severity", "investigations", ["organization_id", "severity"])
    op.create_index("ix_inv_org_opened", "investigations", ["organization_id", "opened_at"])
    op.create_index("ix_inv_org_updated", "investigations", ["organization_id", "updated_at"])
    # Partial unique index: one active investigation per correlation_key
    op.create_index(
        _ACTIVE_INDEX,
        "investigations",
        ["organization_id", "correlation_key"],
        unique=True,
        postgresql_where=sa.text(_ACTIVE_STATES),
    )

    # investigation_evidence_links
    op.create_table(
        "investigation_evidence_links",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("case_id", sa.String(26), nullable=False),
        sa.Column("source_domain", sa.String(40), nullable=False),
        sa.Column("source_entity_type", sa.String(80), nullable=False),
        sa.Column("source_entity_id", sa.String(200), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("evidence_snapshot", sa.JSON, nullable=True),
        sa.Column("correlation_reason", sa.Text, nullable=False, server_default=""),
        sa.Column("relationship_type", sa.String(20), nullable=False, server_default="DIRECT"),
        sa.Column("observability", sa.String(20), nullable=False, server_default="OBSERVED"),
        sa.Column("dedup_key", sa.String(300), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "ux_iel_org_case_dedup",
        "investigation_evidence_links",
        ["organization_id", "case_id", "dedup_key"],
    )
    op.create_index(
        "ix_iel_org_case", "investigation_evidence_links", ["organization_id", "case_id"]
    )
    op.create_index(
        "ix_iel_org_domain",
        "investigation_evidence_links",
        ["organization_id", "source_domain"],
    )
    op.create_index(
        "ix_iel_case_observed", "investigation_evidence_links", ["case_id", "observed_at"]
    )

    # investigation_events
    op.create_table(
        "investigation_events",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("event_id", sa.String(100), nullable=False),
        sa.Column("organization_id", sa.String(26), nullable=False),
        sa.Column("case_id", sa.String(26), nullable=False),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("detail", sa.JSON, nullable=True),
        sa.Column("actor_user_id", sa.String(26), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint("ux_iev_event_id", "investigation_events", ["event_id"])
    op.create_index("ix_iev_case", "investigation_events", ["case_id"])
    op.create_index("ix_iev_org_ts", "investigation_events", ["organization_id", "occurred_at"])
    op.create_index("ix_iev_org_type", "investigation_events", ["organization_id", "event_type"])

    # investigation_correlation_cursors
    op.create_table(
        "investigation_correlation_cursors",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("source_domain", sa.String(40), nullable=False),
        sa.Column("last_processed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_processed_id", sa.String(200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint(
        "ux_icc_source_domain", "investigation_correlation_cursors", ["source_domain"]
    )


def downgrade() -> None:
    op.drop_table("investigation_correlation_cursors")

    op.drop_index("ix_iev_org_type", table_name="investigation_events")
    op.drop_index("ix_iev_org_ts", table_name="investigation_events")
    op.drop_index("ix_iev_case", table_name="investigation_events")
    op.drop_constraint("ux_iev_event_id", "investigation_events", type_="unique")
    op.drop_table("investigation_events")

    op.drop_index("ix_iel_case_observed", table_name="investigation_evidence_links")
    op.drop_index("ix_iel_org_domain", table_name="investigation_evidence_links")
    op.drop_index("ix_iel_org_case", table_name="investigation_evidence_links")
    op.drop_constraint("ux_iel_org_case_dedup", "investigation_evidence_links", type_="unique")
    op.drop_table("investigation_evidence_links")

    op.drop_index(_ACTIVE_INDEX, table_name="investigations")
    op.drop_index("ix_inv_org_updated", table_name="investigations")
    op.drop_index("ix_inv_org_opened", table_name="investigations")
    op.drop_index("ix_inv_org_severity", table_name="investigations")
    op.drop_index("ix_inv_org_status", table_name="investigations")
    op.drop_constraint("ux_inv_id_org", "investigations", type_="unique")
    op.drop_table("investigations")
