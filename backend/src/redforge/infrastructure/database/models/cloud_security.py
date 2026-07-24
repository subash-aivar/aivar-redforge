"""SQLAlchemy models for M26 cloud_security schema foundation tables."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "cloud_security"

# JSONB on PostgreSQL (production), plain JSON on any other dialect — see
# redforge/infrastructure/platform/models.py for the established idiom. This
# lets a SQLite-backed test do Base.metadata.create_all() without the SQLite
# type compiler choking on a Postgres-only JSONB column.
_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


class CloudProviderModel(Base):
    __tablename__ = "cloud_providers"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uq_cloud_providers_org_type",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    discovery_config: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudAccountModel(Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint(
            "cloud_provider_id",
            "external_id",
            name="uq_cloud_accounts_provider_external",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cloud_provider_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.cloud_providers.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False)
    regions: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    credential_ref: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    sync_state: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    account_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False, default=dict
    )
    tags: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudAssetModel(Base):
    __tablename__ = "cloud_assets"
    __table_args__ = (
        UniqueConstraint(
            "cloud_account_id",
            "provider_id",
            name="uq_cloud_assets_account_provider",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cloud_account_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.cloud_accounts.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    region: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    availability_zone: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    provider_metadata: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    normalized_config: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    tags: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    relationships: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    posture_state: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudIAMPrincipalModel(Base):
    __tablename__ = "cloud_iam_principals"
    __table_args__ = (
        UniqueConstraint(
            "cloud_account_id",
            "provider_id",
            name="uq_cloud_iam_principals_account_provider",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cloud_account_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.cloud_accounts.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    principal_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provider_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    attached_policies: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    trust_relationships: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    privilege_level: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    is_federated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_human: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_activity_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    risk_indicators: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    is_disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CSPMPolicyModel(Base):
    __tablename__ = "cspm_policies"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    provider_types: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    asset_types: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", _JSONB_PORTABLE, nullable=False)
    remediation: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    compliance_mapping: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    rule: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    inherits_from: Mapped[str | None] = mapped_column(String(128), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    evaluation_strategy: Mapped[str] = mapped_column(String(64), nullable=False, default="boolean")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CSPMFindingModel(Base):
    __tablename__ = "cspm_findings"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "fingerprint",
            name="uq_cspm_findings_org_fingerprint",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    compliance_mapping: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    history: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    accepted_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    accepted_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CSPMEvaluationModel(Base):
    __tablename__ = "cspm_evaluations"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_account_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    context: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    results: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    assets_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    policies_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_opened: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CSPMDriftBaselineModel(Base):
    __tablename__ = "cspm_drift_baselines"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            "drift_kind",
            name="uq_cspm_drift_baselines_org_asset_kind",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    drift_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    baseline_snapshot: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KubernetesClusterModel(Base):
    __tablename__ = "kubernetes_clusters"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "name",
            name="uq_kubernetes_clusters_org_name",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_account_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    cluster_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    api_server_endpoint: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_ref_id: Mapped[str] = mapped_column(String(256), nullable=False)
    labels: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    pod_security_standards: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    security_score: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesNamespaceModel(Base):
    __tablename__ = "kubernetes_namespaces"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    labels: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    annotations: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    pod_security_level: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_quotas: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    has_network_policy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesWorkloadModel(Base):
    __tablename__ = "kubernetes_workloads"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    uid: Mapped[str] = mapped_column(String(128), nullable=False)
    service_account: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    containers: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    host_network: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    host_pid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    host_ipc: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    security_level: Mapped[str] = mapped_column(String(32), nullable=False)
    exposure: Mapped[str] = mapped_column(String(32), nullable=False)
    labels: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    annotations: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    replicas: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesNodeModel(Base):
    __tablename__ = "kubernetes_nodes"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    uid: Mapped[str] = mapped_column(String(128), nullable=False)
    kubelet_version: Mapped[str] = mapped_column(String(64), nullable=False)
    os_image: Mapped[str] = mapped_column(String(256), nullable=False)
    container_runtime: Mapped[str] = mapped_column(String(128), nullable=False)
    roles: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    labels: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    taints: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    unschedulable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesServiceModel(Base):
    __tablename__ = "kubernetes_services"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    service_type: Mapped[str] = mapped_column(String(64), nullable=False)
    cluster_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    external_ips: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    load_balancer_ingress: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    ports: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    selector: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    exposure: Mapped[str] = mapped_column(String(32), nullable=False)
    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesRBACPrincipalModel(Base):
    __tablename__ = "kubernetes_rbac_principals"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    bindings: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    roles: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    cluster_roles: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    trust_references: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesNetworkPolicyModel(Base):
    __tablename__ = "kubernetes_network_policies"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    namespace: Mapped[str] = mapped_column(String(253), nullable=False)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    pod_selector: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    policy_types: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    ingress_rules: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    egress_rules: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    allows_cross_namespace: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class KubernetesAdmissionPolicyModel(Base):
    __tablename__ = "kubernetes_admission_policies"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cluster_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(253), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    controller: Mapped[str] = mapped_column(String(128), nullable=False)
    rules: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    violations: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudRuntimeEventModel(Base):
    """Partitioned by RANGE (event_time); PK is (id, event_time)."""

    __tablename__ = "cloud_runtime_events"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "source",
            "provider_event_id",
            "event_time",
            name="uq_cloud_runtime_events_org_source_provider",
        ),
        {
            "schema": _SCHEMA,
            "postgresql_partition_by": "RANGE (event_time)",
        },
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_account_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(512), nullable=False)
    identity: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    host: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    container: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False, default=dict
    )
    correlation_refs: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    correlation_links: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    artifacts: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    evidence: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    source_ip: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    target_resource: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeProcessModel(Base):
    __tablename__ = "runtime_processes"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    process_name: Mapped[str] = mapped_column(String(256), nullable=False)
    executable_path: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_line: Mapped[str] = mapped_column(String(4096), nullable=False, default="")
    user_name: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeNetworkConnectionModel(Base):
    __tablename__ = "runtime_network_connections"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    direction: Mapped[str] = mapped_column(String(32), nullable=False)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False)
    local_address: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    local_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    remote_address: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    remote_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeFileActivityModel(Base):
    __tablename__ = "runtime_file_activities"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeIdentitySessionModel(Base):
    __tablename__ = "runtime_identity_sessions"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    identity: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    session_id: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    mfa_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    source_ip: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeExecutionContextModel(Base):
    __tablename__ = "runtime_execution_contexts"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    process_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    host_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    workload_ref: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    environment: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class RuntimeArtifactModel(Base):
    __tablename__ = "runtime_artifacts"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    runtime_event_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    artifact_id: Mapped[str] = mapped_column(String(128), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    digest: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    path: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudRiskScoreModel(Base):
    __tablename__ = "cloud_risk_scores"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            name="uq_cloud_risk_scores_org_asset",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    threat_intel_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    identity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    exposure_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    business_criticality_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    attack_path_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cspm_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    kubernetes_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    runtime_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    score_components: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    evidence: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    history: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    exceptions: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    weight_profile: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    calculation_version: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    trend: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    threshold: Mapped[float] = mapped_column(Float, nullable=False, default=7.0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudRiskHistoryModel(Base):
    __tablename__ = "cloud_risk_history"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    risk_score_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    overall_score: Mapped[float] = mapped_column(Float, nullable=False)
    dimensions: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    calculation_version: Mapped[str] = mapped_column(String(128), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")


class CloudRiskFactorModel(Base):
    __tablename__ = "cloud_risk_factors"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudRiskExposureModel(Base):
    __tablename__ = "cloud_risk_exposures"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "cloud_asset_id",
            name="uq_cloud_risk_exposures_org_asset",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    cloud_asset_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    public_accessibility: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    internet_exposure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    encryption_at_rest: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    privilege_level: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    lateral_movement_potential: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UNKNOWN"
    )
    exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudRiskAssessmentModel(Base):
    __tablename__ = "cloud_risk_assessments"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    assets_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risks_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risks_updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    calculation_version: Mapped[str] = mapped_column(String(128), nullable=False)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudOrchestrationRunModel(Base):
    __tablename__ = "cloud_orchestration_runs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    steps: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    diagnostics: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    operation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudPlatformValidationReportModel(Base):
    __tablename__ = "cloud_platform_validation_reports"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            name="uq_cloud_platform_validation_reports_org",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    report: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
