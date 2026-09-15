"""Opt-in Jira issue progress, explicit identity mapping and durable sync lease."""
from alembic import op
import sqlalchemy as sa
from app.migration_safety import assert_safe_v06_downgrade

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "jira_issue_links",
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), primary_key=True),
        sa.Column("issue_key", sa.String(80), nullable=False),
        sa.Column("base_url", sa.String(255), nullable=False),
        sa.Column("remote_status_id", sa.String(128), nullable=True),
        sa.Column("remote_status", sa.String(200), nullable=True),
        sa.Column("remote_status_category", sa.String(20), nullable=True),
        sa.Column("remote_assignee_id", sa.String(128), nullable=True),
        sa.Column("remote_assignee", sa.String(200), nullable=True),
        sa.Column("remote_updated_at", sa.String(64), nullable=True),
        sa.Column("local_snapshot_json", sa.Text(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("next_sync_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("operation", sa.String(20), nullable=False),
        sa.Column("pending_json", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("claim_token", sa.String(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_jira_issue_links_next_sync_at", "jira_issue_links", ["next_sync_at"])
    op.create_table(
        "jira_user_mappings",
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("jira_account_id", sa.String(128), nullable=False, unique=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "jira_sync_control",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("claim_token", sa.String(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("next_request_at", sa.DateTime(), nullable=False),
    )


def downgrade():
    assert_safe_v06_downgrade(op.get_bind())
    op.drop_table("jira_sync_control")
    op.drop_table("jira_user_mappings")
    op.drop_table("jira_issue_links")
