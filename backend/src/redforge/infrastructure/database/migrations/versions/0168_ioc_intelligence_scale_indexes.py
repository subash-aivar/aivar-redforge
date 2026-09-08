"""0168 — ioc_intelligence: two evidence-justified composite indexes
(M51.2 Slice 2.1).

Migration chain: 0167 -> 0168.

Added strictly on measured `EXPLAIN ANALYZE` evidence against a
realistic 50,000-row seeded `ioc_intelligence_iocs` table (20 synthetic
tenants + global rows), not speculatively:

- Sorting a tenant-scoped list by `lifecycle` backward-scanned the
  existing single-column `ix_ioc_intelligence_iocs_lifecycle` index
  (global, not tenant-scoped) and filtered out ~7,900 other tenants'
  rows per query — 25ms, and that filtered-row count grows with total
  platform row count, not with the requesting tenant's own row count.
- The same shape of problem measured for sorting by `valid_until`
  (~19,000 rows filtered, 9-11ms) — and `valid_until` is also the
  column the new `validity` (valid/lapsed) filter compares against.

`(tenant_id, lifecycle)` and `(tenant_id, valid_until)` let the planner
satisfy "this tenant's rows, in this sort order" from one index scan
directly, independent of total platform size.

Deliberately NOT added (measured fast already via existing indexes,
1-3ms at the same 50k-row scale): a sort by `ioc_type` (already served
by `uq_ioc_intelligence_iocs_tenant_identity`'s existing composite),
`epistemic_state`, `created_at`, or `updated_at`. A free-text `search`
over `normalized_value` (`ILIKE '%...%'`) was also measured fast
(<5ms) via the existing tenant/global partial identity indexes at this
scale — no trigram/GIN index is added without further evidence at
larger scale.

No changes to any other table.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0168"
down_revision: str = "0167"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_ioc_intelligence_iocs_tenant_lifecycle",
        "ioc_intelligence_iocs",
        ["tenant_id", "lifecycle"],
    )
    op.create_index(
        "ix_ioc_intelligence_iocs_tenant_valid_until",
        "ioc_intelligence_iocs",
        ["tenant_id", "valid_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_ioc_intelligence_iocs_tenant_valid_until", "ioc_intelligence_iocs")
    op.drop_index("ix_ioc_intelligence_iocs_tenant_lifecycle", "ioc_intelligence_iocs")
