"""Read-only v0.6 downgrade preflight, independent of live ORM model versions.

SQLite does not reliably roll DDL back after a later revision refuses a
downgrade. Every v0.6 revision therefore checks the combined refusal conditions
before dropping its first table. This is intentionally conservative even for
a one-step downgrade: populated installations should restore a verified backup
with its matching application version instead of removing lifecycle evidence.

Run migrations with application/worker processes stopped; this preflight does
not attempt to coordinate with concurrently running application transactions.
"""
from __future__ import annotations

import sqlalchemy as sa


def assert_safe_v06_downgrade(bind) -> None:
    """Refuse before any DDL when any v0.6/older lifecycle guard would refuse."""
    try:
        tables = set(sa.inspect(bind).get_table_names())
    except sa.exc.NoInspectionAvailable as exc:
        raise RuntimeError("Safe downgrade requires a live database for read-only preflight") from exc

    for name in (
        "operational_alerts", "automation_policies", "jira_issue_links", "jira_user_mappings",
        "ownership_rules", "team_memberships", "coverage_expectations", "projects", "teams",
        "github_alerts", "github_sync_runs", "github_connections", "scanner_tokens",
        "users", "user_sessions", "saved_views", "audit_events", "auth_throttles",
    ):
        if name in tables and bind.execute(sa.select(1).select_from(sa.table(name)).limit(1)).first():
            raise RuntimeError(f"Cannot downgrade while {name} contains data")

    if "jira_sync_control" in tables:
        control = sa.table("jira_sync_control", sa.column("claim_token"))
        if bind.execute(sa.select(1).select_from(control).where(control.c.claim_token.is_not(None)).limit(1)).first():
            raise RuntimeError("Cannot downgrade while a Jira sync is running")

    if "vulnerability_intelligence" in tables:
        if bind.execute(sa.select(1).select_from(sa.table("vulnerability_intelligence")).limit(1)).first():
            raise RuntimeError("Cannot downgrade while vulnerability intelligence is cached")
    if "remediation_policies" in tables:
        policies = sa.table("remediation_policies", sa.column("project"))
        if bind.execute(sa.select(policies).where(policies.c.project != "").limit(1)).first():
            raise RuntimeError("Cannot downgrade while project remediation policies exist")

    if "findings" in tables:
        findings = sa.table(
            "findings", sa.column("status"), sa.column("disposition_reason"),
            sa.column("duplicate_of_id"), sa.column("verification_requested_at"),
            sa.column("verified_at"), sa.column("verified_by"),
            sa.column("priority_score"), sa.column("kev"), sa.column("epss_score"),
            sa.column("risk_accepted_at"),
        )
        if bind.execute(sa.select(1).select_from(findings).where(sa.or_(
            findings.c.status.in_(["verification_pending", "false_positive", "duplicate"]),
            findings.c.disposition_reason.is_not(None), findings.c.duplicate_of_id.is_not(None),
            findings.c.verification_requested_at.is_not(None), findings.c.verified_at.is_not(None),
            findings.c.verified_by.is_not(None),
        )).limit(1)).first():
            raise RuntimeError("Cannot downgrade after structured remediation workflow has been used")
        if bind.execute(sa.select(1).select_from(findings).where(sa.or_(
            findings.c.priority_score != 0, findings.c.kev.is_(True),
            findings.c.epss_score.is_not(None), findings.c.risk_accepted_at.is_not(None),
        )).limit(1)).first():
            raise RuntimeError("Cannot downgrade after remediation intelligence has been applied")

    # Revision 0003 also refuses when project-scoped keys cannot be collapsed.
    if "assets" in tables:
        assets = sa.table("assets", sa.column("key"))
        if bind.execute(sa.select(assets.c.key).group_by(assets.c.key)
                        .having(sa.func.count() > 1).limit(1)).first():
            raise RuntimeError("Cannot downgrade while asset keys are shared across projects")
