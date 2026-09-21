from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003_add_blacklisted_ips_table"
down_revision: Union[str, None] = "0002_phase7_intelligence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "blacklisted_ips",
        sa.Column("id", sa.Integer(), primary_key=True, index=True),
        sa.Column("entry_type", sa.String(length=20), nullable=False, index=True),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
        sa.Column("ip_range_start", postgresql.INET(), nullable=True),
        sa.Column("ip_range_end", postgresql.INET(), nullable=True),
        sa.Column("region_code", sa.String(length=10), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index(op.f("ix_blacklisted_ips_id"), "blacklisted_ips", ["id"], unique=False)
    op.create_index(op.f("ix_blacklisted_ips_entry_type"), "blacklisted_ips", ["entry_type"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_blacklisted_ips_entry_type"), table_name="blacklisted_ips")
    op.drop_index(op.f("ix_blacklisted_ips_id"), table_name="blacklisted_ips")
    op.drop_table("blacklisted_ips")
