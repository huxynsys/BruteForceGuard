from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "0005_alert_lifecycle"
down_revision: Union[str, None] = "0004_add_attack_session_ended_at"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Denormalized snapshot of the latest triage transition on the alert row
    # (NULL until the alert is first triaged).
    op.add_column(
        "alerts",
        sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("status_updated_by", sa.String(255), nullable=True),
    )
    op.add_column(
        "alerts",
        sa.Column("status_reason", sa.Text(), nullable=True),
    )

    # Append-only audit trail: one row per lifecycle transition.
    op.create_table(
        "alert_status_history",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(20), nullable=False),
        sa.Column("to_status", sa.String(20), nullable=False),
        sa.Column(
            "changed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("changed_by", sa.String(255), nullable=False),
        sa.Column("changed_by_role", sa.String(50), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_alert_status_history_alert_id",
        "alert_status_history",
        ["alert_id"],
    )
    op.create_index(
        "ix_alert_status_history_changed_at",
        "alert_status_history",
        ["changed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_alert_status_history_changed_at", table_name="alert_status_history")
    op.drop_index("ix_alert_status_history_alert_id", table_name="alert_status_history")
    op.drop_table("alert_status_history")
    op.drop_column("alerts", "status_reason")
    op.drop_column("alerts", "status_updated_by")
    op.drop_column("alerts", "status_updated_at")