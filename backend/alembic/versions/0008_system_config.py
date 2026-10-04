"""system_config (runtime detection configuration).

Revision ID: 0008_system_config
Revises: 0007_users_rbac
Create Date: 2025-01-01

Adds the single-row ``system_config`` table that persists the operator's
runtime detection configuration (service thresholds, rule windows, session
correlation timeout) as one JSONB document with an optimistic-concurrency
``version`` and last-writer metadata.  When no row exists the detection
engine runs on its built-in defaults - the table is backfilled lazily by the
first ``PUT /api/v1/config/``.

The row is deliberately a singleton (``id = 1``, enforced by the CHECK
constraint) because the configuration is always read and replaced as a whole;
a key/value table would make whole-document audit and optimistic locking
harder without adding anything.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0008_system_config"
down_revision: Union[str, None] = "0007_users_rbac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "system_config",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("updated_by", sa.String(255), nullable=False, server_default="system"),
        sa.Column("updated_by_role", sa.String(50), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_system_config_singleton"),
    )


def downgrade() -> None:
    op.drop_table("system_config")
