"""Create upgrade_runs table for biome upgrade orchestration.

Revision ID: 20260509_1000_create_upgrade_runs_table
Revises: 20260430_1100_plan4_security
Create Date: 2026-05-09 10:00:00.000000

Adds the upgrade_runs table to track biome upgrade progress across canary,
batched, and all phases, including health check outcomes and rollback reason.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260509_1000_create_upgrade_runs_table"
down_revision = "20260430_1100_plan4_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create upgrade_runs table."""
    op.create_table(
        "upgrade_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("biome_id", sa.Integer, sa.ForeignKey("biomes.id"), nullable=False),
        sa.Column("target_version", sa.String(50), nullable=False),
        sa.Column("cluster_id", sa.String(100), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="pending"),
        sa.Column("phase", sa.String(50), nullable=False, default="canary"),
        sa.Column("nodes_total", sa.Integer, nullable=False, default=0),
        sa.Column("nodes_completed", sa.Integer, nullable=False, default=0),
        sa.Column("nodes_failed", sa.Integer, nullable=False, default=0),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
        sa.Column("rollback_reason", sa.Text, nullable=True),
        sa.Column("actor_sub", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime, default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index("ix_upgrade_runs_biome_id", "upgrade_runs", ["biome_id"])
    op.create_index("ix_upgrade_runs_status", "upgrade_runs", ["status"])
    op.create_index("ix_upgrade_runs_cluster_id", "upgrade_runs", ["cluster_id"])


def downgrade() -> None:
    """Drop upgrade_runs table."""
    op.drop_index("ix_upgrade_runs_cluster_id")
    op.drop_index("ix_upgrade_runs_status")
    op.drop_index("ix_upgrade_runs_biome_id")
    op.drop_table("upgrade_runs")
