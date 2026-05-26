"""Create slo_definitions table.

Revision ID: 20260427_1930_slo_definitions
Revises: 20260427_1900_dr_drills
Create Date: 2026-04-27 19:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1930_slo_definitions'
down_revision = '20260427_1900_dr_drills'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'slo_definitions',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('cluster_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=True),
        sa.Column('slo_name', sa.String(128), nullable=False),
        sa.Column('domain', sa.String(32), nullable=False),
        sa.Column('target_value', sa.Float(), nullable=False),
        sa.Column('target_unit', sa.String(16), nullable=False),
        sa.Column('window_seconds', sa.Integer(), nullable=False, server_default='2592000'),
        sa.Column('error_budget_seconds', sa.Integer(), nullable=True),
        sa.Column('alert_threshold_burn_rate', sa.Float(), nullable=False, server_default='2.0'),
        sa.Column('runbook_url', sa.String(1024), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cluster_id', 'tenant_id', 'slo_name', name='uq_slo_cluster_tenant_name')
    )
    op.create_index('ix_slo_cluster', 'slo_definitions', ['cluster_id'])
    op.create_index('ix_slo_name', 'slo_definitions', ['slo_name'])


def downgrade() -> None:
    op.drop_index('ix_slo_name', table_name='slo_definitions')
    op.drop_index('ix_slo_cluster', table_name='slo_definitions')
    op.drop_table('slo_definitions')
