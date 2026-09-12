"""Phase 6 base schema (auth_events, alerts, attack_sessions).

Revision ID: 0001_phase6_base
Revises:
Create Date: 2026-09-12

This is the baseline representing the pre-Phase-7 (Phase 6) database as it
would be created by SQLAlchemy ``create_all``.  A fresh database reaches the
full Phase 7 schema by running ``alembic upgrade head`` (this revision plus
``0002_phase7_intelligence``).  An *existing* Phase 6 database created with
``create_all`` (which has no ``alembic_version`` row) is stamped to this
revision with ``alembic stamp 0001_phase6_base`` then upgraded with
``alembic upgrade head`` which applies only additive Phase 7 changes -
existing data is preserved and no table is dropped/recreated.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_phase6_base"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "auth_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("result", sa.String(length=20), nullable=False),
        sa.Column("service", sa.String(length=100), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("event_id", sa.String(length=100), nullable=True),
        sa.Column("raw_event", postgresql.JSONB(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_auth_events_timestamp", "auth_events", ["timestamp"])
    op.create_index("ix_auth_events_source", "auth_events", ["source"])
    op.create_index("ix_auth_events_source_ip", "auth_events", ["source_ip"])
    op.create_index("ix_auth_events_username", "auth_events", ["username"])
    op.create_index("ix_auth_events_result", "auth_events", ["result"])
    op.create_index("ix_auth_events_service", "auth_events", ["service"])
    op.create_index("ix_auth_events_hostname", "auth_events", ["hostname"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("alert_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("username", sa.String(length=255), nullable=True),
        sa.Column("service", sa.String(length=100), nullable=True),
        sa.Column("mitre_technique", sa.String(length=50), nullable=True),
        sa.Column(
            "confidence", sa.Integer(), nullable=False, server_default="50"
        ),
        sa.Column("evidence", postgresql.JSONB(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="open",
        ),
        sa.Column("session_id", sa.Integer(), nullable=True),
    )
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])
    op.create_index("ix_alerts_alert_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_source_ip", "alerts", ["source_ip"])
    op.create_index("ix_alerts_username", "alerts", ["username"])
    op.create_index("ix_alerts_service", "alerts", ["service"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_session_id", "alerts", ["session_id"])

    op.create_table(
        "attack_sessions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "started_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), nullable=False
        ),
        sa.Column("session_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column(
            "event_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("source_ips", postgresql.JSONB(), nullable=True),
        sa.Column("usernames", postgresql.JSONB(), nullable=True),
        sa.Column("services", postgresql.JSONB(), nullable=True),
        sa.Column("detection_types", postgresql.JSONB(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="active",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_attack_sessions_started_at", "attack_sessions", ["started_at"])
    op.create_index("ix_attack_sessions_last_seen_at", "attack_sessions", ["last_seen_at"])
    op.create_index("ix_attack_sessions_session_type", "attack_sessions", ["session_type"])
    op.create_index("ix_attack_sessions_status", "attack_sessions", ["status"])


def downgrade() -> None:
    op.drop_table("attack_sessions")
    op.drop_table("alerts")
    op.drop_table("auth_events")
