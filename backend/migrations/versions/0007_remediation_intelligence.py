"""Explainable remediation priority, SLA policy, and public threat intelligence."""
from datetime import UTC, datetime

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("priority_score", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("priority_reasons_json", sa.Text(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("kev_date_added", sa.Date(), nullable=True))
        batch.add_column(sa.Column("kev_due_date", sa.Date(), nullable=True))
        batch.add_column(sa.Column("kev_ransomware", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column("epss_score", sa.Float(), nullable=True))
        batch.add_column(sa.Column("epss_percentile", sa.Float(), nullable=True))
        batch.add_column(sa.Column("intelligence_updated_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("remediation_due_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("resolved_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("risk_accepted_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("risk_accepted_until", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("risk_accepted_by", sa.String(100), nullable=True))
        batch.add_column(sa.Column("risk_acceptance_reason", sa.Text(), nullable=True))
        batch.create_index("ix_findings_priority_score", ["priority_score"])
        batch.create_index("ix_findings_kev", ["kev"])
        batch.create_index("ix_findings_remediation_due_at", ["remediation_due_at"])
        batch.create_index("ix_findings_risk_accepted_until", ["risk_accepted_until"])

    op.create_table(
        "vulnerability_intelligence",
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("kev_ransomware", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_required_action", sa.Text(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev_updated_at", sa.DateTime(), nullable=True),
        sa.Column("epss_updated_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_vulnerability_intelligence_kev", "vulnerability_intelligence", ["kev"])

    op.create_table(
        "remediation_policies",
        sa.Column("project", sa.String(255), primary_key=True),
        sa.Column("critical_days", sa.Integer(), nullable=False),
        sa.Column("high_days", sa.Integer(), nullable=False),
        sa.Column("medium_days", sa.Integer(), nullable=False),
        sa.Column("low_days", sa.Integer(), nullable=False),
        sa.Column("info_days", sa.Integer(), nullable=False),
        sa.Column("kev_days", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "intelligence_sync_states",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_hours", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("next_sync_at", sa.DateTime(), nullable=False),
        sa.Column("last_synced_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("claim_token", sa.String(36), nullable=True),
        sa.Column("claimed_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_intelligence_sync_states_next_sync_at", "intelligence_sync_states", ["next_sync_at"])

    now = datetime.now(UTC).replace(tzinfo=None)
    policies = sa.table(
        "remediation_policies",
        sa.column("project", sa.String), sa.column("critical_days", sa.Integer),
        sa.column("high_days", sa.Integer), sa.column("medium_days", sa.Integer),
        sa.column("low_days", sa.Integer), sa.column("info_days", sa.Integer),
        sa.column("kev_days", sa.Integer), sa.column("created_at", sa.DateTime),
        sa.column("updated_at", sa.DateTime),
    )
    op.bulk_insert(policies, [{
        "project": "", "critical_days": 7, "high_days": 30, "medium_days": 90,
        "low_days": 180, "info_days": 365, "kev_days": 7,
        "created_at": now, "updated_at": now,
    }])
    states = sa.table(
        "intelligence_sync_states",
        sa.column("source", sa.String), sa.column("enabled", sa.Boolean),
        sa.column("interval_hours", sa.Integer), sa.column("status", sa.String),
        sa.column("next_sync_at", sa.DateTime), sa.column("record_count", sa.Integer),
        sa.column("updated_at", sa.DateTime),
    )
    op.bulk_insert(states, [
        {"source": "cisa_kev", "enabled": False, "interval_hours": 24,
         "status": "idle", "next_sync_at": now, "record_count": 0, "updated_at": now},
        {"source": "first_epss", "enabled": False, "interval_hours": 24,
         "status": "idle", "next_sync_at": now, "record_count": 0, "updated_at": now},
    ])

    findings = sa.table(
        "findings", sa.column("status", sa.String), sa.column("last_seen", sa.DateTime),
        sa.column("resolved_at", sa.DateTime),
    )
    op.execute(findings.update().where(findings.c.status.in_(["resolved", "closed"]))
               .values(resolved_at=findings.c.last_seen))


def downgrade():
    bind = op.get_bind()
    # Refuse before any SQLite batch DDL when a later downgrade would also
    # refuse. SQLite cannot roll those schema changes back transactionally.
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
        "findings", sa.column("priority_score", sa.Integer), sa.column("kev", sa.Boolean),
        sa.column("epss_score", sa.Float), sa.column("risk_accepted_at", sa.DateTime),
    )
    if bind.execute(sa.select(findings).where(sa.or_(
        findings.c.priority_score != 0, findings.c.kev.is_(True),
        findings.c.epss_score.is_not(None), findings.c.risk_accepted_at.is_not(None),
    )).limit(1)).first():
        raise RuntimeError("Cannot downgrade after remediation intelligence has been applied")

    op.drop_table("intelligence_sync_states")
    op.drop_table("remediation_policies")
    op.drop_table("vulnerability_intelligence")
    with op.batch_alter_table("findings") as batch:
        for name in ("ix_findings_risk_accepted_until", "ix_findings_remediation_due_at",
                     "ix_findings_kev", "ix_findings_priority_score"):
            batch.drop_index(name)
        for name in (
            "risk_acceptance_reason", "risk_accepted_by", "risk_accepted_until",
            "risk_accepted_at", "resolved_at", "remediation_due_at",
            "intelligence_updated_at", "epss_percentile", "epss_score",
            "kev_ransomware", "kev_due_date", "kev_date_added", "kev",
            "priority_reasons_json", "priority_score",
        ):
            batch.drop_column(name)
