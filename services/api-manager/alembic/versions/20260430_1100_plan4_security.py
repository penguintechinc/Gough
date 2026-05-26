"""Plan 4: Security & Identity — vault bootstrap tokens and alert rules.

Revision ID: 20260430_1100_plan4_security
Revises: 20260430_1000_rename_eggs_to_biomes
Create Date: 2026-04-30 11:00:00.000000

Adds tables for:
- vault_bootstrap_tokens: Immutable audit trail of node bootstrap token usage
- alert_rules: Configurable security alert rules for metrics-driven alerting
"""

from alembic import op
import sqlalchemy as sa


revision = "20260430_1100_plan4_security"
down_revision = "20260430_1000_rename_eggs_to_biomes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create vault_bootstrap_tokens and alert_rules tables."""
    # Create vault_bootstrap_tokens table
    op.create_table(
        "vault_bootstrap_tokens",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("node_id", sa.Integer(), nullable=True),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["node_id"], ["nodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vault_bootstrap_tokens_node_id", "vault_bootstrap_tokens", ["node_id"])
    op.create_index("ix_vault_bootstrap_tokens_expires_at", "vault_bootstrap_tokens", ["expires_at"])

    # Create alert_rules table
    op.create_table(
        "alert_rules",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("metric_name", sa.Text(), nullable=False),
        sa.Column("threshold", sa.Numeric(), nullable=False),
        sa.Column("duration_seconds", sa.Integer(), nullable=False, server_default=sa.literal(60)),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )


def downgrade() -> None:
    """Drop alert_rules and vault_bootstrap_tokens tables."""
    op.drop_table("alert_rules")
    op.drop_table("vault_bootstrap_tokens")
