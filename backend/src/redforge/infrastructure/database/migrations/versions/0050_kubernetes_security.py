"""0050 — M26 Phase 5 Kubernetes Security inventory tables."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0050"
down_revision: str = "0049"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCHEMA = "cloud_security"


def upgrade() -> None:
    op.create_table(
        "kubernetes_clusters",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("cloud_account_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cloud_asset_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("cluster_type", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("api_server_endpoint", sa.String(length=512), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("credential_ref_id", sa.String(length=256), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "pod_security_standards",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("security_score", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            name="uq_kubernetes_clusters_org_name",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_clusters_organization_id",
        "kubernetes_clusters",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_clusters_cloud_account_id",
        "kubernetes_clusters",
        ["cloud_account_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_namespaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("annotations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("pod_security_level", sa.String(length=32), nullable=False),
        sa.Column("resource_quotas", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("has_network_policy", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_namespaces_cluster_id",
        "kubernetes_namespaces",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_namespaces_organization_id",
        "kubernetes_namespaces",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_workloads",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("namespace", sa.String(length=253), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("uid", sa.String(length=128), nullable=False),
        sa.Column("service_account", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("containers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("host_network", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("host_pid", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("host_ipc", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("privileged", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("security_level", sa.String(length=32), nullable=False),
        sa.Column("exposure", sa.String(length=32), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("annotations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("replicas", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_workloads_cluster_id",
        "kubernetes_workloads",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_workloads_organization_id",
        "kubernetes_workloads",
        ["organization_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_workloads_cluster_namespace",
        "kubernetes_workloads",
        ["cluster_id", "namespace"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_nodes",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("uid", sa.String(length=128), nullable=False),
        sa.Column("kubelet_version", sa.String(length=64), nullable=False),
        sa.Column("os_image", sa.String(length=256), nullable=False),
        sa.Column("container_runtime", sa.String(length=128), nullable=False),
        sa.Column("roles", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("labels", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("taints", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unschedulable", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_nodes_cluster_id",
        "kubernetes_nodes",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_nodes_organization_id",
        "kubernetes_nodes",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("namespace", sa.String(length=253), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("service_type", sa.String(length=64), nullable=False),
        sa.Column("cluster_ip", sa.String(length=64), nullable=False),
        sa.Column("external_ips", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "load_balancer_ingress",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("ports", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("selector", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("exposure", sa.String(length=32), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_services_cluster_id",
        "kubernetes_services",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_services_organization_id",
        "kubernetes_services",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_rbac_principals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("namespace", sa.String(length=253), nullable=False),
        sa.Column("bindings", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("roles", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("cluster_roles", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("trust_references", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_rbac_principals_cluster_id",
        "kubernetes_rbac_principals",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_rbac_principals_organization_id",
        "kubernetes_rbac_principals",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_network_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("namespace", sa.String(length=253), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("pod_selector", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("policy_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ingress_rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("egress_rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "allows_cross_namespace",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_network_policies_cluster_id",
        "kubernetes_network_policies",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_network_policies_organization_id",
        "kubernetes_network_policies",
        ["organization_id"],
        schema=_SCHEMA,
    )

    op.create_table(
        "kubernetes_admission_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cluster_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", sa.String(length=26), nullable=False),
        sa.Column("name", sa.String(length=253), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False),
        sa.Column("controller", sa.String(length=128), nullable=False),
        sa.Column("rules", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("violations", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("row_version", sa.Integer(), nullable=False, server_default="1"),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_admission_policies_cluster_id",
        "kubernetes_admission_policies",
        ["cluster_id"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_kubernetes_admission_policies_organization_id",
        "kubernetes_admission_policies",
        ["organization_id"],
        schema=_SCHEMA,
    )


def downgrade() -> None:
    for table in (
        "kubernetes_admission_policies",
        "kubernetes_network_policies",
        "kubernetes_rbac_principals",
        "kubernetes_services",
        "kubernetes_nodes",
        "kubernetes_workloads",
        "kubernetes_namespaces",
        "kubernetes_clusters",
    ):
        op.drop_table(table, schema=_SCHEMA)
