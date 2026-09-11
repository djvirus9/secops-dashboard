"""GitHub connection jobs and durable external alert identities."""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("github_connections",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("repository", sa.String(200), nullable=False, unique=True),
        sa.Column("project", sa.String(255), nullable=False),
        sa.Column("sources_json", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("next_sync_at", sa.DateTime(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("claim_token", sa.String(36), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False))
    op.create_index("ix_github_connections_next_sync_at", "github_connections", ["next_sync_at"])
    op.create_table("github_sync_runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("connection_id", sa.String(), sa.ForeignKey("github_connections.id"), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("imported", sa.Integer(), nullable=False),
        sa.Column("new_findings", sa.Integer(), nullable=False),
        sa.Column("updated", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(500), nullable=True))
    op.create_index("ix_github_sync_runs_connection_id", "github_sync_runs", ["connection_id"])
    op.create_table("github_alerts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("connection_id", sa.String(), sa.ForeignKey("github_connections.id"), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), nullable=False, unique=True),
        sa.Column("source_state", sa.String(20), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("connection_id", "source", "number", name="uq_github_alert_identity"))
    op.create_index("ix_github_alerts_connection_id", "github_alerts", ["connection_id"])


def downgrade():
    # Refuse before dropping anything, including when a further identity
    # downgrade would refuse: SQLite does not roll DDL back transactionally.
    bind = op.get_bind()
    for name in ("github_alerts", "github_sync_runs", "github_connections", "scanner_tokens",
                 "users", "user_sessions", "saved_views", "audit_events", "auth_throttles"):
        table = sa.table(name, sa.column("key" if name == "auth_throttles" else "id"))
        if bind.execute(sa.select(table).limit(1)).first():
            raise RuntimeError(f"Cannot downgrade while {name} contains data")
    for name in ("github_alerts", "github_sync_runs", "github_connections"):
        op.drop_table(name)
