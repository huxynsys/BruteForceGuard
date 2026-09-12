"""Phase 7 intelligence schema upgrade.

Revision ID: 0002_phase7_intelligence
Revises: 0001_phase6_base
Create Date: 2026-09-12

Additive upgrade from the Phase 6 schema to Phase 7:
  * alerts      + risk_score, risk_level, risk_factors, threat_intelligence,
                 source_reputation, mitre_context
  * attack_sessions + risk_score, risk_level, risk_factors, behavioral_profile
  * new table   threat_indicators

Only additive operations are used (no existing table is dropped/recreated),
so an existing Phase 6 database upgrades in place and its data is preserved.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_phase7_intelligence"
down_revision: Union[str, None] = "0001_phase6_base"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- alerts -----------------------------------------------------------
    op.add_column(
        "alerts",
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "risk_level",
            sa.String(length=20),
            nullable=False,
            server_default="informational",
        ),
    )
    op.add_column("alerts", sa.Column("risk_factors", postgresql.JSONB(), nullable=True))
    op.add_column(
        "alerts", sa.Column("threat_intelligence", postgresql.JSONB(), nullable=True)
    )
    op.add_column(
        "alerts", sa.Column("source_reputation", postgresql.JSONB(), nullable=True)
    )
    op.add_column("alerts", sa.Column("mitre_context", postgresql.JSONB(), nullable=True))

    # --- attack_sessions --------------------------------------------------
    op.add_column(
        "attack_sessions",
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "attack_sessions",
        sa.Column(
            "risk_level",
            sa.String(length=20),
            nullable=False,
            server_default="informational",
        ),
    )
    op.add_column(
        "attack_sessions",
        sa.Column("risk_factors", postgresql.JSONB(), nullable=True),
    )
    op.add_column(
        "attack_sessions",
        sa.Column("behavioral_profile", postgresql.JSONB(), nullable=True),
    )

    # --- threat_indicators (new table) ------------------------------------
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("indicator", sa.String(length=255), nullable=False),
        sa.Column("indicator_type", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("threat_type", sa.String(length=100), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=False, server_default="manual"),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
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
    )
    op.create_index(
        "ix_threat_indicators_indicator", "threat_indicators", ["indicator"]
    )
    op.create_index(
        "ix_threat_indicators_indicator_type",
        "threat_indicators", ["indicator_type"],
    )
    op.create_index("ix_threat_indicators_active", "threat_indicators", ["active"])


def downgrade() -> None:
    op.drop_table("threat_indicators")
    op.drop_column("attack_sessions", "behavioral_profile")
    op.drop_column("attack_sessions", "risk_factors")
    op.drop_column("attack_sessions", "risk_level")
    op.drop_column("attack_sessions", "risk_score")
    op.drop_column("alerts", "mitre_context")
    op.drop_column("alerts", "source_reputation")
    op.drop_column("alerts", "threat_intelligence")
    op.drop_column("alerts", "risk_factors")
    op.drop_column("alerts", "risk_level")
    op.drop_column("alerts", "risk_score")
