"""Harden finding identity and preserve normalized scanner evidence.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _merge_existing_duplicates() -> None:
    bind = op.get_bind()
    fingerprints = bind.execute(
        sa.text(
            "SELECT fingerprint FROM findings "
            "GROUP BY fingerprint HAVING COUNT(*) > 1"
        )
    ).scalars().all()

    for fingerprint in fingerprints:
        rows = bind.execute(
            sa.text(
                "SELECT id, occurrences, risk_score, first_seen, last_seen, signal_id "
                "FROM findings WHERE fingerprint = :fingerprint "
                "ORDER BY first_seen ASC, id ASC"
            ),
            {"fingerprint": fingerprint},
        ).mappings().all()
        keeper, *duplicates = rows
        duplicate_ids = [row["id"] for row in duplicates]

        for duplicate_id in duplicate_ids:
            bind.execute(
                sa.text(
                    "UPDATE comments SET finding_id = :keeper_id "
                    "WHERE finding_id = :duplicate_id"
                ),
                {"keeper_id": keeper["id"], "duplicate_id": duplicate_id},
            )
            bind.execute(
                sa.text("DELETE FROM findings WHERE id = :duplicate_id"),
                {"duplicate_id": duplicate_id},
            )

        newest = max(rows, key=lambda row: row["last_seen"])
        bind.execute(
            sa.text(
                "UPDATE findings SET occurrences = :occurrences, risk_score = :risk_score, "
                "first_seen = :first_seen, last_seen = :last_seen, signal_id = :signal_id "
                "WHERE id = :keeper_id"
            ),
            {
                "keeper_id": keeper["id"],
                "occurrences": sum((row["occurrences"] or 1) for row in rows),
                "risk_score": max((row["risk_score"] or 0) for row in rows),
                "first_seen": min(row["first_seen"] for row in rows),
                "last_seen": newest["last_seen"],
                "signal_id": newest["signal_id"],
            },
        )


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("file_path", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("line_number", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("references_json", sa.Text(), nullable=False, server_default="[]")
        )
        batch_op.add_column(
            sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]")
        )

    _merge_existing_duplicates()

    with op.batch_alter_table("findings") as batch_op:
        batch_op.create_unique_constraint("uq_findings_fingerprint", ["fingerprint"])


def downgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_constraint("uq_findings_fingerprint", type_="unique")
        batch_op.drop_column("tags_json")
        batch_op.drop_column("references_json")
        batch_op.drop_column("line_number")
        batch_op.drop_column("file_path")
