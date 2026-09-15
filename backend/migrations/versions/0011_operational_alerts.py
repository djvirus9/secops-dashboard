"""Opt-in SLA/coverage policies and durable operational alerts."""
from alembic import op
import sqlalchemy as sa
from app.migration_safety import assert_safe_v06_downgrade

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "automation_policies",
        sa.Column("project", sa.String(255), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("warn_before_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("reminder_hours", sa.Integer(), nullable=False, server_default="24"),
        sa.Column("notify_slack", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("next_evaluation_at", sa.DateTime(), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_automation_policies_next_evaluation_at", "automation_policies", ["next_evaluation_at"])
    op.create_table(
        "operational_alerts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("resource_id", sa.String(), nullable=False),
        sa.Column("condition", sa.String(20), nullable=False),
        sa.Column("state", sa.String(20), nullable=False, server_default="open"),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("team", sa.String(100), nullable=True),
        sa.Column("escalation_contact", sa.String(255), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("notification_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_notified_at", sa.DateTime(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by", sa.String(100), nullable=True),
        sa.UniqueConstraint("kind", "resource_id", name="uq_operational_alert_resource"),
    )
    op.create_index("ix_operational_alerts_project", "operational_alerts", ["project"])
    op.create_index("ix_operational_alerts_state", "operational_alerts", ["state"])


def downgrade():
    assert_safe_v06_downgrade(op.get_bind())
    op.drop_table("operational_alerts")
    op.drop_table("automation_policies")
