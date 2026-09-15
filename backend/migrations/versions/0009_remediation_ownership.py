"""Team membership and opt-in routing without changing existing assignments."""
from alembic import op
import sqlalchemy as sa
from app.migration_safety import assert_safe_v06_downgrade

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "team_memberships",
        sa.Column("team_id", sa.String(), sa.ForeignKey("teams.id"), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_team_memberships_user_id", "team_memberships", ["user_id"])
    op.create_table(
        "ownership_rules",
        sa.Column("project", sa.String(255), sa.ForeignKey("projects.name"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("default_assignee", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade():
    assert_safe_v06_downgrade(op.get_bind())
    op.drop_table("ownership_rules")
    op.drop_table("team_memberships")
