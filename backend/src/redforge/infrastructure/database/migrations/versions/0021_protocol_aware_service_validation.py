"""Protocol-Aware Service Validation — M13.

Adds protocol-validator provenance columns to `validation_execution_steps`
only — the smallest schema change genuinely required. A reachable port
is only ever a candidate; these columns record what a real, bounded
protocol validator actually observed when dispatched against that
candidate, analogous to how migration 0020 added adaptive-plan
provenance.

Adds:
  - validation_execution_steps.validator_id / validator_version: which
    versioned ProtocolValidator (application/validation_execution/
    protocol_validators.py) produced this step's outcome. NULL for
    every non-protocol step (DNS/TCP/TLS/HTTP/port discovery keep their
    own pre-M13 status/evidence shape unchanged).
  - validation_execution_steps.protocol_validation_state: the resulting
    ProtocolValidationState (not_attempted/unreachable/inconclusive/
    hinted/validated/error) — an explicit column rather than
    string-parsed from evidence, so the API layer never has to infer
    validated-vs-hinted truth from a brittle evidence-label convention.

No new tables. No M14 schema. No credentials/tokens/cookies/private
material — same discipline as migrations 0019/0020.

Revision ID: 0021
"""

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str = "0020"
branch_labels: None = None
depends_on: None = None


def upgrade() -> None:
    op.add_column(
        "validation_execution_steps",
        sa.Column("validator_id", sa.String(60), nullable=True),
    )
    op.add_column(
        "validation_execution_steps",
        sa.Column("validator_version", sa.Integer, nullable=True),
    )
    op.add_column(
        "validation_execution_steps",
        sa.Column("protocol_validation_state", sa.String(20), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("validation_execution_steps", "protocol_validation_state")
    op.drop_column("validation_execution_steps", "validator_version")
    op.drop_column("validation_execution_steps", "validator_id")
