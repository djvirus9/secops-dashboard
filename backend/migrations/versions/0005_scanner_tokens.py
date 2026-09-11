"""Add hash-only, project-scoped scanner credentials without rewriting existing data."""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scanner_tokens",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("project", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_scanner_tokens_project", "scanner_tokens", ["project"])
    op.create_index("ix_scanner_tokens_token_hash", "scanner_tokens", ["token_hash"], unique=True)
    op.create_index("ix_scanner_tokens_expires_at", "scanner_tokens", ["expires_at"])


def downgrade():
    tokens = sa.table("scanner_tokens", sa.column("id"))
    if op.get_bind().execute(sa.select(tokens).limit(1)).first() is not None:
        raise RuntimeError("Cannot downgrade while scanner_tokens contains data")
    op.drop_table("scanner_tokens")
