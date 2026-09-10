"""Project-scoped assets, component identity, import history and notification outbox.

Existing records retain their unscoped identity. Reimporting with a new project or
component is intentionally a new identity; incomplete legacy evidence is never
guessed or merged into a different remediation task.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    constraints = sa.inspect(bind).get_unique_constraints("assets")
    indexes = sa.inspect(bind).get_indexes("assets")
    # Accept both the Alembic schema and an explicitly adopted legacy ORM schema.
    for index in indexes:
        if index["unique"] and index["column_names"] == ["key"] and not index.get("duplicates_constraint"):
            op.drop_index(index["name"], table_name="assets")
    naming = {"uq": "uq_%(table_name)s_%(column_0_name)s"}
    with op.batch_alter_table("assets", naming_convention=naming) as batch:
        batch.add_column(sa.Column("project", sa.String(), nullable=False, server_default=""))
        for constraint in constraints:
            if constraint["column_names"] == ["key"]:
                batch.drop_constraint(constraint["name"] or "uq_assets_key", type_="unique")
        batch.create_unique_constraint("uq_assets_project_key", ["project", "key"])
    if not any(i["name"] == "ix_assets_key" and not i["unique"] for i in indexes):
        op.create_index("ix_assets_key", "assets", ["key"])
    op.create_index("ix_assets_project", "assets", ["project"])

    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("project", sa.String(), nullable=False, server_default=""))
        batch.add_column(sa.Column("source_id", sa.String(), nullable=True))
        batch.add_column(sa.Column("component", sa.String(), nullable=True))
        batch.add_column(sa.Column("component_version", sa.String(), nullable=True))
    op.create_index("ix_findings_project", "findings", ["project"])
    op.create_index("ix_findings_component", "findings", ["component"])
    op.create_table(
        "imports",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("parser", sa.String(), nullable=False),
        sa.Column("filename", sa.String(), nullable=True),
        sa.Column("project", sa.String(), nullable=False, server_default=""),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("imported", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_findings", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("deduplicated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
    )
    for column in ("project", "status", "created_at"):
        op.create_index(f"ix_imports_{column}", "imports", [column])
    with op.batch_alter_table("signals") as batch:
        batch.add_column(sa.Column("import_id", sa.String(), nullable=True))
        batch.create_foreign_key("fk_signals_import_id", "imports", ["import_id"], ["id"])
    op.create_index("ix_signals_import_id", "signals", ["import_id"])
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("event_key", sa.String(), nullable=False, unique=True),
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("channel", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(), nullable=False),
        sa.Column("claim_token", sa.String(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("external_id", sa.String(), nullable=True),
        sa.Column("external_url", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    for column in ("finding_id", "status", "next_attempt_at"):
        op.create_index(f"ix_notification_deliveries_{column}", "notification_deliveries", [column])


def downgrade():
    # A downgrade cannot safely restore global asset uniqueness if projects
    # contain the same key. Reject before removing any data or schema.
    duplicates = op.get_bind().execute(sa.text(
        "SELECT key FROM assets GROUP BY key HAVING COUNT(*) > 1 LIMIT 1"
    )).first()
    if duplicates:
        raise RuntimeError("Cannot downgrade while asset keys are shared across projects")
    op.drop_table("notification_deliveries")
    with op.batch_alter_table("signals") as batch:
        batch.drop_constraint("fk_signals_import_id", type_="foreignkey")
        batch.drop_index("ix_signals_import_id")
        batch.drop_column("import_id")
    op.drop_table("imports")
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_project")
        batch.drop_index("ix_findings_component")
        for column in ("project", "source_id", "component", "component_version"):
            batch.drop_column(column)
    with op.batch_alter_table("assets") as batch:
        batch.drop_constraint("uq_assets_project_key", type_="unique")
        batch.drop_index("ix_assets_project")
        batch.drop_column("project")
        batch.create_unique_constraint("uq_assets_key", ["key"])
