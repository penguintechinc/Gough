"""Add Plan 3 orchestration columns and Deployment table for egg lifecycle tracking.

Revision ID: 20260430_0900_plan3_orchestration
Revises: 20260429_0900_node_events
Create Date: 2026-04-30 09:00:00.000000

Adds image_digest, signature_verified, published_at columns to eggs table for cosign
verification integration. Creates new deployments table to track egg deployment status
and lifecycle phases across nodes, supporting orchestration state machines and rollout
progress monitoring.

References:
- Plan 3: Deployment Orchestration → signature verification, image digests
- Plan 3: Deployment Orchestration → Deployment model for phase/status tracking
"""

from alembic import op
import sqlalchemy as sa


revision = "20260430_0900_plan3_orchestration"
down_revision = "20260429_0900_node_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add Plan 3 orchestration columns to eggs; create deployments table."""
    # Add signature verification and image digest columns to eggs table
    op.add_column(
        "eggs",
        sa.Column("image_digest", sa.String(255), nullable=True),
    )
    op.add_column(
        "eggs",
        sa.Column("signature_verified", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "eggs",
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Create deployments table for tracking egg deployment lifecycle
    op.create_table(
        "deployments",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "egg_id",
            sa.Integer(),
            sa.ForeignKey("eggs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "node_id",
            sa.Integer(),
            sa.ForeignKey("nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("phase", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("logs_url", sa.String(1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # Create indexes on deployments table
    op.create_index("ix_deployments_status", "deployments", ["status"])
    op.create_index("ix_deployments_egg_node", "deployments", ["egg_id", "node_id"])


def downgrade() -> None:
    """Drop deployments table and Plan 3 orchestration columns from eggs."""
    # Drop deployments table and indexes
    op.drop_index("ix_deployments_egg_node", table_name="deployments")
    op.drop_index("ix_deployments_status", table_name="deployments")
    op.drop_table("deployments")

    # Drop signature verification columns from eggs table
    op.drop_column("eggs", "published_at")
    op.drop_column("eggs", "signature_verified")
    op.drop_column("eggs", "image_digest")
