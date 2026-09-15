"""Project ownership, coverage expectations, and structured remediation states."""
from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index("ix_imports_coverage_latest", "imports", ["project", "parser", "created_at"])
    op.create_index(
        "ix_imports_coverage_success", "imports", ["project", "parser", "status", "completed_at"],
    )
    op.create_table(
        "teams",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("contact", sa.String(255), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_teams_name", "teams", ["name"], unique=True)
    op.create_table(
        "projects",
        sa.Column("name", sa.String(255), primary_key=True),
        sa.Column("display_name", sa.String(255), nullable=False, server_default=""),
        sa.Column("team_id", sa.String(), sa.ForeignKey("teams.id"), nullable=True),
        sa.Column("business_unit", sa.String(255), nullable=False, server_default=""),
        sa.Column("tier", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("repository_url", sa.String(500), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_projects_team_id", "projects", ["team_id"])
    op.create_table(
        "coverage_expectations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project", sa.String(255), nullable=False),
        sa.Column("source_type", sa.String(20), nullable=False),
        sa.Column("source", sa.String(200), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("project", "source_type", "source", name="uq_coverage_expectation_source"),
    )
    op.create_index("ix_coverage_expectations_project", "coverage_expectations", ["project"])

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("disposition_reason", sa.Text(), nullable=True))
        batch.add_column(sa.Column("duplicate_of_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("verification_requested_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("verified_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("verified_by", sa.String(100), nullable=True))
        batch.create_index("ix_findings_duplicate_of_id", ["duplicate_of_id"])


def downgrade():
    bind = op.get_bind()
    # Refuse before any SQLite batch DDL when a later downgrade would also
    # refuse. SQLite cannot roll those schema changes back transactionally.
    for name, key in (("coverage_expectations", "id"), ("projects", "name"), ("teams", "id")):
        table = sa.table(name, sa.column(key))
        if bind.execute(sa.select(table).limit(1)).first():
            raise RuntimeError(f"Cannot downgrade while {name} contains data")
    for name in ("github_alerts", "github_sync_runs", "github_connections", "scanner_tokens",
                 "users", "user_sessions", "saved_views", "audit_events", "auth_throttles"):
        table = sa.table(name, sa.column("key" if name == "auth_throttles" else "id"))
        if bind.execute(sa.select(table).limit(1)).first():
            raise RuntimeError(f"Cannot downgrade while {name} contains data")
    intelligence = sa.table("vulnerability_intelligence", sa.column("cve_id", sa.String))
    policies = sa.table("remediation_policies", sa.column("project", sa.String))
    if bind.execute(sa.select(intelligence).limit(1)).first():
        raise RuntimeError("Cannot downgrade while vulnerability intelligence is cached")
    if bind.execute(sa.select(policies).where(policies.c.project != "").limit(1)).first():
        raise RuntimeError("Cannot downgrade while project remediation policies exist")
    findings = sa.table(
        "findings",
        sa.column("status", sa.String),
        sa.column("disposition_reason", sa.Text),
        sa.column("duplicate_of_id", sa.String),
        sa.column("verification_requested_at", sa.DateTime),
        sa.column("verified_at", sa.DateTime),
        sa.column("priority_score", sa.Integer),
        sa.column("kev", sa.Boolean),
        sa.column("epss_score", sa.Float),
        sa.column("risk_accepted_at", sa.DateTime),
    )
    if bind.execute(sa.select(findings).where(sa.or_(
        findings.c.status.in_(["verification_pending", "false_positive", "duplicate"]),
        findings.c.disposition_reason.is_not(None),
        findings.c.duplicate_of_id.is_not(None),
        findings.c.verification_requested_at.is_not(None),
        findings.c.verified_at.is_not(None),
    )).limit(1)).first():
        raise RuntimeError("Cannot downgrade after structured remediation workflow has been used")
    if bind.execute(sa.select(findings).where(sa.or_(
        findings.c.priority_score != 0,
        findings.c.kev.is_(True),
        findings.c.epss_score.is_not(None),
        findings.c.risk_accepted_at.is_not(None),
    )).limit(1)).first():
        raise RuntimeError("Cannot downgrade after remediation intelligence has been applied")
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_duplicate_of_id")
        for name in (
            "verified_by", "verified_at", "verification_requested_at",
            "duplicate_of_id", "disposition_reason",
        ):
            batch.drop_column(name)
    op.drop_index("ix_imports_coverage_success", table_name="imports")
    op.drop_index("ix_imports_coverage_latest", table_name="imports")
    op.drop_table("coverage_expectations")
    op.drop_table("projects")
    op.drop_table("teams")
