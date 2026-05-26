"""Create migration_policy table.

Revision ID: 20260427_1800_migration_policy
Revises: 20260427_1730_migration_events
Create Date: 2026-04-27 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1800_migration_policy'
down_revision = '20260427_1730_migration_events'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'migration_policy',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cluster_id', sa.Uuid(), nullable=False, unique=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('evaluation_interval_seconds', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('min_healthy_nodes', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('max_concurrent_migrations', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('require_target_capacity_headroom_cpu_pct', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('require_target_capacity_headroom_mem_pct', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('require_target_capacity_headroom_disk_pct', sa.Integer(), nullable=False, server_default='15'),
        sa.Column('rollback_on_destination_failure', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('rollback_window_seconds', sa.Integer(), nullable=False, server_default='300'),
        sa.Column('forbid_migration_during_partition', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('forbid_migration_during_maintenance', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('waddleai_risk_threshold', sa.Float(), nullable=False, server_default='0.75'),
        sa.Column('capacity_forecast_horizon_days', sa.Integer(), nullable=False, server_default='7'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cluster_id', name='uq_migration_policy_cluster_id')
    )
    op.create_index('ix_migration_policy_cluster_id', 'migration_policy', ['cluster_id'])


def downgrade() -> None:
    op.drop_index('ix_migration_policy_cluster_id', table_name='migration_policy')
    op.drop_table('migration_policy')
