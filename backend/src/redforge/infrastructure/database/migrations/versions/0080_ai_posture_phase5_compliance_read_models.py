"""0080 — M31 Phase 5 compliance mappings, control classification, read models, graph.

Creates:
- ai_compliance_mappings
- ai_compliance_control_classifications (local M24 attestation fallback)
- ai_posture_read_models (JSONB projection views)
- ai_security_graph_nodes / ai_security_graph_edges

Migration chain: 0079 → 0080.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0080"
down_revision: str = "0079"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_compliance_control_classifications",
        sa.Column("framework_id", sa.String(64), primary_key=True),
        sa.Column("control_id", sa.String(128), primary_key=True),
        sa.Column("control_title", sa.String(512), nullable=False),
        sa.Column("requires_human_attestation", sa.Boolean(), nullable=False),
        schema="ai_posture",
    )

    op.create_table(
        "ai_compliance_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("ai_system_asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("framework_id", sa.String(64), nullable=False),
        sa.Column("control_id", sa.String(128), nullable=False),
        sa.Column("control_title", sa.String(512), nullable=False),
        sa.Column("control_status", sa.String(64), nullable=False),
        sa.Column("requires_human_attestation", sa.Boolean(), nullable=False),
        sa.Column("evaluation_mode", sa.String(64), nullable=False),
        sa.Column("attestor_id", sa.String(256), nullable=True),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attestation_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "tenant_id",
            "ai_system_asset_id",
            "framework_id",
            "control_id",
            name="uq_compliance_mapping_asset_control",
        ),
        schema="ai_posture",
    )
    op.create_index(
        "ix_ai_compliance_mappings_tenant_framework",
        "ai_compliance_mappings",
        ["tenant_id", "framework_id"],
        schema="ai_posture",
    )

    op.create_table(
        "ai_posture_read_models",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("view_key", sa.String(128), primary_key=True),
        sa.Column("payload_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_id", sa.String(128), nullable=False, server_default=""),
        sa.Column("projection_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        schema="ai_posture",
    )

    op.create_table(
        "ai_security_graph_nodes",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("node_type", sa.String(64), primary_key=True),
        sa.Column("node_key", sa.String(256), primary_key=True),
        sa.Column("properties_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_id", sa.String(128), nullable=False, server_default=""),
        schema="ai_posture",
    )

    op.create_table(
        "ai_security_graph_edges",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("edge_type", sa.String(64), primary_key=True),
        sa.Column("from_key", sa.String(256), primary_key=True),
        sa.Column("to_key", sa.String(256), primary_key=True),
        sa.Column("properties_json", postgresql.JSONB(), nullable=False),
        sa.Column("last_event_id", sa.String(128), nullable=False, server_default=""),
        schema="ai_posture",
    )

    # Seed local attestation classification catalog (Phase 5 M24 fallback)
    classifications = sa.table(
        "ai_compliance_control_classifications",
        sa.column("framework_id", sa.String),
        sa.column("control_id", sa.String),
        sa.column("control_title", sa.String),
        sa.column("requires_human_attestation", sa.Boolean),
        schema="ai_posture",
    )
    op.bulk_insert(
        classifications,
        [
            {
                "framework_id": "EU_AI_Act",
                "control_id": "Art9_RiskManagement",
                "control_title": "EU AI Act Art. 9 Risk Management",
                "requires_human_attestation": True,
            },
            {
                "framework_id": "EU_AI_Act",
                "control_id": "Art15_AccuracyRobustness",
                "control_title": "EU AI Act Art. 15 Accuracy & Robustness",
                "requires_human_attestation": False,
            },
            {
                "framework_id": "NIST_AI_RMF",
                "control_id": "GOVERN_1",
                "control_title": "NIST AI RMF GOVERN 1",
                "requires_human_attestation": True,
            },
            {
                "framework_id": "NIST_AI_RMF",
                "control_id": "MAP_1",
                "control_title": "NIST AI RMF MAP 1 Threat Mapping",
                "requires_human_attestation": False,
            },
            {
                "framework_id": "ISO_42001",
                "control_id": "Clause5_Leadership",
                "control_title": "ISO 42001 Clause 5 Leadership",
                "requires_human_attestation": True,
            },
        ],
    )


def downgrade() -> None:
    op.drop_table("ai_security_graph_edges", schema="ai_posture")
    op.drop_table("ai_security_graph_nodes", schema="ai_posture")
    op.drop_table("ai_posture_read_models", schema="ai_posture")
    op.drop_index(
        "ix_ai_compliance_mappings_tenant_framework",
        table_name="ai_compliance_mappings",
        schema="ai_posture",
    )
    op.drop_table("ai_compliance_mappings", schema="ai_posture")
    op.drop_table("ai_compliance_control_classifications", schema="ai_posture")
