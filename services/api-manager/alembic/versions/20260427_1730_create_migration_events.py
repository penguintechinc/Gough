"""Create migration_events table.

Revision ID: 20260427_1730_migration_events
Revises: 20260427_1700_joiner_secrets
Create Date: 2026-04-27 17:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1730_migration_events'
down_revision = '20260427_1700_joiner_secrets'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'migration_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('egg_instance_id', sa.Integer(), nullable=True),
        sa.Column('egg_id', sa.Integer(), nullable=True),
        sa.Column('egg_kind', sa.String(64), nullable=True),
        sa.Column('src_node_id', sa.Integer(), nullable=True),
        sa.Column('dst_node_id', sa.Integer(), nullable=True),
        sa.Column('reason', sa.String(512), nullable=True),
        sa.Column('result', sa.String(32), nullable=False),
        sa.Column('rejection_reason', sa.String(255), nullable=True),
        sa.Column('safety_check_details_json', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['egg_instance_id'], ['node_egg_assignments.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['src_node_id'], ['nodes.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['dst_node_id'], ['nodes.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_migration_events_egg_instance_id', 'migration_events', ['egg_instance_id'])
    op.create_index('ix_migration_events_src_node_id', 'migration_events', ['src_node_id'])
    op.create_index('ix_migration_events_dst_node_id', 'migration_events', ['dst_node_id'])
    op.create_index('ix_migration_events_tenant_id', 'migration_events', ['tenant_id'])
    op.create_index('ix_migration_events_started_at', 'migration_events', ['started_at'])
    op.create_index('ix_migration_events_result', 'migration_events', ['result'])


def downgrade() -> None:
    op.drop_index('ix_migration_events_result', table_name='migration_events')
    op.drop_index('ix_migration_events_started_at', table_name='migration_events')
    op.drop_index('ix_migration_events_tenant_id', table_name='migration_events')
    op.drop_index('ix_migration_events_dst_node_id', table_name='migration_events')
    op.drop_index('ix_migration_events_src_node_id', table_name='migration_events')
    op.drop_index('ix_migration_events_egg_instance_id', table_name='migration_events')
    op.drop_table('migration_events')
