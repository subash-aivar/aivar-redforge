"""Threat Intelligence Reference Data — M22 Phase 1 (ATT&CK Framework +
CVE/KEV Foundation).

Schema-only migration — deliberately no bulk data inserts. Per the M22
Hardening Review (Part 3, Migration Safety): the initial MITRE ATT&CK /
NVD / CISA KEV bulk load is an application-level idempotent upsert
operation (the reference-data admin loading path), not embedded DDL,
so a large insert never makes this migration non-transactional and a
rollback never has to reason about seeded data.

Five tables:

  1. attack_tactics — GLOBAL, no organization_id. Canonical MITRE
     ATT&CK tactics (e.g. TA0001 "Initial Access").

  2. attack_techniques — GLOBAL, no organization_id. Canonical MITRE
     ATT&CK techniques/sub-techniques. A GIN full-text index on `name`
     backs `AttackTechniqueRepository.search_by_name` — flagged as a
     required-but-missing index in the Hardening Review (Part 3, Index
     Strategy); a plain LIKE/ILIKE scan over a growing technique table
     (ATT&CK for ICS/Mobile expansion) is not acceptable.

  3. attack_technique_relationships — GLOBAL, no organization_id. Raw
     STIX 2.1 relationship objects touching at least one technique.

  4. vulnerabilities — GLOBAL, no organization_id. Canonical CVE
     records with CVSS/EPSS/CISA-KEV overlay fields.

  5. stix_ingestion_log — the idempotency gate for every write above,
     and (in a future phase) per-tenant TAXII/STIX ingestion.
     Per the Hardening Review (Part 3, Table Design Issues): a single
     unique index on (org, source, stix_id) incorrectly conflates two
     different idempotency contracts — GLOBAL objects (no org) and
     TENANT objects (always an org). This migration instead adds a
     `scope` discriminator plus a CHECK constraint enforcing the
     GLOBAL-implies-no-org / TENANT-implies-org invariant, and TWO
     separate partial unique indexes so each scope has its own
     idempotency key without a future migration having to fix this.

Per the Hardening Review (Part 3, Table Design Issues — P0): global
reference tables must NEVER carry organization_id. At 1,000 tenants x
700 ATT&CK techniques x 200,000 CVEs, a per-tenant duplication strategy
would scale to ~140 billion rows. These tables are true globals.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035"
down_revision: str = "0034"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_SCOPE_CHECK = (
    "(scope = 'GLOBAL' AND organization_id IS NULL) "
    "OR (scope = 'TENANT' AND organization_id IS NOT NULL)"
)


def upgrade() -> None:
    # ── attack_tactics ───────────────────────────────────────────────────
    op.create_table(
        "attack_tactics",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("tactic_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("shortname", sa.String(100), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("url", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint("ux_att_tactic_id", "attack_tactics", ["tactic_id"])
    op.create_unique_constraint("ux_att_stix_id", "attack_tactics", ["stix_id"])

    # ── attack_techniques ────────────────────────────────────────────────
    op.create_table(
        "attack_techniques",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("name", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("is_sub_technique", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("parent_technique_id", sa.String(20), nullable=True),
        sa.Column("tactic_ids", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("platforms", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("data_sources", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("is_deprecated", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("framework_version", sa.String(20), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    # technique_id must be unique BEFORE the self-referential FK below can
    # reference it.
    op.create_unique_constraint("ux_atk_technique_id", "attack_techniques", ["technique_id"])
    op.create_unique_constraint("ux_atk_stix_id", "attack_techniques", ["stix_id"])
    # Deferred so a batch upsert can insert a sub-technique before its
    # parent within the same transaction — the FK is only checked at
    # commit, not per-row, matching the bulk-upsert access pattern the
    # admin loading service uses.
    op.create_foreign_key(
        "fk_atk_parent_technique",
        "attack_techniques",
        "attack_techniques",
        ["parent_technique_id"],
        ["technique_id"],
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_index("ix_atk_parent_technique", "attack_techniques", ["parent_technique_id"])
    op.create_index("ix_atk_is_sub_technique", "attack_techniques", ["is_sub_technique"])
    # GIN full-text index for AttackTechniqueRepository.search_by_name —
    # required per the Hardening Review; a plain LIKE scan does not scale.
    op.execute(
        "CREATE INDEX ix_atk_name_fts ON attack_techniques "
        "USING GIN (to_tsvector('english', name))"
    )

    # ── attack_technique_relationships ──────────────────────────────────
    op.create_table(
        "attack_technique_relationships",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("stix_id", sa.String(80), nullable=False),
        sa.Column("relationship_type", sa.String(30), nullable=False),
        sa.Column("source_ref", sa.String(120), nullable=False),
        sa.Column("target_ref", sa.String(120), nullable=False),
        sa.Column("source_technique_id", sa.String(20), nullable=True),
        sa.Column("target_technique_id", sa.String(20), nullable=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["source_technique_id"],
            ["attack_techniques.technique_id"],
            name="fk_atr_source_technique",
            deferrable=True,
            initially="DEFERRED",
        ),
        sa.ForeignKeyConstraint(
            ["target_technique_id"],
            ["attack_techniques.technique_id"],
            name="fk_atr_target_technique",
            deferrable=True,
            initially="DEFERRED",
        ),
    )
    op.create_unique_constraint("ux_atr_stix_id", "attack_technique_relationships", ["stix_id"])
    op.create_index(
        "ix_atr_source_technique", "attack_technique_relationships", ["source_technique_id"]
    )
    op.create_index(
        "ix_atr_target_technique", "attack_technique_relationships", ["target_technique_id"]
    )
    op.create_index(
        "ix_atr_relationship_type", "attack_technique_relationships", ["relationship_type"]
    )

    # ── vulnerabilities ──────────────────────────────────────────────────
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("cvss_v3_score", sa.Float, nullable=True),
        sa.Column("cvss_v3_vector", sa.String(100), nullable=True),
        sa.Column("cvss_v3_version", sa.String(10), nullable=True),
        sa.Column("cvss_v2_score", sa.Float, nullable=True),
        sa.Column("epss_probability", sa.Float, nullable=True),
        sa.Column("epss_percentile", sa.Float, nullable=True),
        sa.Column("epss_model_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_kev", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("kev_date_added", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_vulnerability_name", sa.String(300), nullable=True),
        sa.Column("kev_short_description", sa.Text, nullable=True),
        sa.Column("kev_required_action", sa.Text, nullable=True),
        sa.Column("kev_known_ransomware_use", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_unique_constraint("ux_vuln_cve_id", "vulnerabilities", ["cve_id"])
    op.create_index("ix_vuln_is_kev", "vulnerabilities", ["is_kev"])
    op.create_index("ix_vuln_epss_probability", "vulnerabilities", ["epss_probability"])

    # ── stix_ingestion_log ───────────────────────────────────────────────
    op.create_table(
        "stix_ingestion_log",
        sa.Column("id", sa.String(26), primary_key=True),
        sa.Column("source_system", sa.String(30), nullable=False),
        sa.Column("scope", sa.String(10), nullable=False, server_default="GLOBAL"),
        sa.Column("organization_id", sa.String(26), nullable=True),
        sa.Column("object_type", sa.String(30), nullable=False),
        sa.Column("external_id", sa.String(120), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("batch_id", sa.String(26), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_SCOPE_CHECK, name="ck_sil_scope_org_pairing"),
    )
    # Two separate idempotency keys — never one shared unique index — per
    # the Hardening Review's global/tenant conflation fix.
    op.create_index(
        "ux_sil_global_source_external",
        "stix_ingestion_log",
        ["source_system", "external_id"],
        unique=True,
        postgresql_where=sa.text("scope = 'GLOBAL'"),
    )
    op.create_index(
        "ux_sil_tenant_org_source_external",
        "stix_ingestion_log",
        ["organization_id", "source_system", "external_id"],
        unique=True,
        postgresql_where=sa.text("scope = 'TENANT'"),
    )
    op.create_index(
        "ix_sil_source_ingested", "stix_ingestion_log", ["source_system", "ingested_at"]
    )
    op.create_index("ix_sil_batch", "stix_ingestion_log", ["batch_id"])


def downgrade() -> None:
    op.drop_index("ix_sil_batch", table_name="stix_ingestion_log")
    op.drop_index("ix_sil_source_ingested", table_name="stix_ingestion_log")
    op.drop_index("ux_sil_tenant_org_source_external", table_name="stix_ingestion_log")
    op.drop_index("ux_sil_global_source_external", table_name="stix_ingestion_log")
    op.drop_table("stix_ingestion_log")

    op.drop_index("ix_vuln_epss_probability", table_name="vulnerabilities")
    op.drop_index("ix_vuln_is_kev", table_name="vulnerabilities")
    op.drop_constraint("ux_vuln_cve_id", "vulnerabilities", type_="unique")
    op.drop_table("vulnerabilities")

    op.drop_index("ix_atr_relationship_type", table_name="attack_technique_relationships")
    op.drop_index("ix_atr_target_technique", table_name="attack_technique_relationships")
    op.drop_index("ix_atr_source_technique", table_name="attack_technique_relationships")
    op.drop_constraint(
        "ux_atr_stix_id", "attack_technique_relationships", type_="unique"
    )
    op.drop_table("attack_technique_relationships")

    op.drop_index("ix_atk_name_fts", table_name="attack_techniques")
    op.drop_index("ix_atk_is_sub_technique", table_name="attack_techniques")
    op.drop_index("ix_atk_parent_technique", table_name="attack_techniques")
    op.drop_constraint("fk_atk_parent_technique", "attack_techniques", type_="foreignkey")
    op.drop_constraint("ux_atk_stix_id", "attack_techniques", type_="unique")
    op.drop_constraint("ux_atk_technique_id", "attack_techniques", type_="unique")
    op.drop_table("attack_techniques")

    op.drop_constraint("ux_att_stix_id", "attack_tactics", type_="unique")
    op.drop_constraint("ux_att_tactic_id", "attack_tactics", type_="unique")
    op.drop_table("attack_tactics")
