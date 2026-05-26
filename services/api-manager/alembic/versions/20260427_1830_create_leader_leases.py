"""Create leader_leases table.

Revision ID: 20260427_1830_leader_leases
Revises: 20260427_1800_migration_policy
Create Date: 2026-04-27 18:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1830_leader_leases'
down_revision = '20260427_1800_migration_policy'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'leader_leases',
        sa.Column('lease_name', sa.String(255), nullable=False),
        sa.Column('holder_id', sa.String(255), nullable=True),
        sa.Column('acquired_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('version', sa.Integer(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('lease_name')
    )
    op.create_index('ix_leader_leases_expires_at', 'leader_leases', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_leader_leases_expires_at', table_name='leader_leases')
    op.drop_table('leader_leases')
