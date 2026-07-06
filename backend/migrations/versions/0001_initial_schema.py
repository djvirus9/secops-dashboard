"""Initial schema

Revision ID: 0001
Revises:
Create Date: 2026-01-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("environment", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("owner", sa.String(), nullable=False, server_default=""),
        sa.Column("criticality", sa.String(), nullable=False, server_default="medium"),
        sa.Column("exposure", sa.String(), nullable=False, server_default="internal"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("key"),
    )
    op.create_index("ix_assets_key", "assets", ["key"])

    op.create_table(
        "signals",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_signals_tool", "signals", ["tool"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("tool", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("asset", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("exposure", sa.String(), nullable=False, server_default="internal"),
        sa.Column("criticality", sa.String(), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("assignee", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("signal_id", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_tool", "findings", ["tool"])
    op.create_index("ix_findings_title", "findings", ["title"])
    op.create_index("ix_findings_asset", "findings", ["asset"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_assignee", "findings", ["assignee"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])
    op.create_index("ix_findings_signal_id", "findings", ["signal_id"])

    op.create_table(
        "comments",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("author", sa.String(), nullable=False, server_default="system"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("action_type", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_comments_finding_id", "comments", ["finding_id"])


def downgrade() -> None:
    op.drop_table("comments")
    op.drop_table("findings")
    op.drop_table("signals")
    op.drop_table("assets")
