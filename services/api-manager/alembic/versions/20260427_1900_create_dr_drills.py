"""Create dr_drills table.

Revision ID: 20260427_1900_dr_drills
Revises: 20260427_1830_leader_leases
Create Date: 2026-04-27 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1900_dr_drills'
down_revision = '20260427_1830_leader_leases'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'dr_drills',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cluster_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('target', sa.String(64), nullable=False, server_default='staging-clone'),
        sa.Column('rpo_observed_seconds', sa.Integer(), nullable=True),
        sa.Column('rto_observed_seconds', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.String(2048), nullable=True),
        sa.Column('audit_ref', sa.Uuid(), nullable=True),
        sa.Column('triggered_by', sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['audit_ref'], ['audit_events.id'], )
    )
    op.create_index('ix_dr_drills_cluster_started', 'dr_drills', ['cluster_id', 'started_at'])
    op.create_index('ix_dr_drills_status', 'dr_drills', ['status'])
    op.create_index('ix_dr_drills_tenant', 'dr_drills', ['tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_dr_drills_tenant', table_name='dr_drills')
    op.drop_index('ix_dr_drills_status', table_name='dr_drills')
    op.drop_index('ix_dr_drills_cluster_started', table_name='dr_drills')
    op.drop_table('dr_drills')
