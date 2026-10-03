from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0006_security_audit_log"
down_revision: Union[str, None] = "0005_alert_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _install_immutability_triggers(bind) -> None:
    """Reject UPDATE / DELETE on the audit table at the database level.

    The application already refuses to mutate audit rows (no write endpoints,
    ORM before_update/before_delete listeners), but raw SQL access bypasses
    both - so the table itself enforces append-only with dialect-specific
    triggers.  Dropping/recreating the table in a future migration remains
    possible; only row-level mutation is blocked.
    """

    dialect = bind.dialect.name

    if dialect == "postgresql":
        # A shared trigger function raises on any UPDATE or DELETE.
        bind.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION
                        'security_audit_logs is append-only (attempted %)', TG_OP;
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        bind.execute(
            sa.text(
                "CREATE TRIGGER trg_security_audit_logs_immutable "
                "BEFORE UPDATE OR DELETE ON security_audit_logs "
                "FOR EACH ROW EXECUTE FUNCTION audit_log_immutable()"
            )
        )
    elif dialect == "sqlite":
        # SQLite: RAISE(ABORT) rolls back the statement with an error.
        for operation, verb in (("UPDATE", "UPDATE"), ("DELETE", "DELETE")):
            bind.execute(
                sa.text(
                    f"""
                    CREATE TRIGGER trg_security_audit_logs_immutable_{operation}
                    BEFORE {operation} ON security_audit_logs
                    BEGIN
                        SELECT RAISE(ABORT,
                            'security_audit_logs is append-only (attempted {verb})');
                    END
                    """
                )
            )


def upgrade() -> None:
    op.create_table(
        "security_audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False, server_default="anonymous"),
        sa.Column("actor_role", sa.String(50), nullable=True),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", sa.String(255), nullable=True),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("source_ip", postgresql.INET(), nullable=True),
        sa.Column("detail", postgresql.JSONB(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_security_audit_logs_created_at",
        "security_audit_logs",
        ["created_at"],
    )
    op.create_index(
        "ix_security_audit_logs_action",
        "security_audit_logs",
        ["action"],
    )
    op.create_index(
        "ix_security_audit_logs_actor",
        "security_audit_logs",
        ["actor"],
    )
    op.create_index(
        "ix_security_audit_logs_result",
        "security_audit_logs",
        ["result"],
    )

    _install_immutability_triggers(op.get_bind())


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_security_audit_logs_immutable ON security_audit_logs"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS audit_log_immutable()"))
    elif bind.dialect.name == "sqlite":
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_security_audit_logs_immutable_UPDATE"))
        bind.execute(sa.text("DROP TRIGGER IF EXISTS trg_security_audit_logs_immutable_DELETE"))

    op.drop_index("ix_security_audit_logs_result", table_name="security_audit_logs")
    op.drop_index("ix_security_audit_logs_actor", table_name="security_audit_logs")
    op.drop_index("ix_security_audit_logs_action", table_name="security_audit_logs")
    op.drop_index("ix_security_audit_logs_created_at", table_name="security_audit_logs")
    op.drop_table("security_audit_logs")
