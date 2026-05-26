"""Create hardware firmware tracking table.

Revision ID: 20260427_1530_hardware_firmware
Revises: 20260427_1500_node_bmc
Create Date: 2026-04-27 15:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '20260427_1530_hardware_firmware'
down_revision = '20260427_1500_node_bmc'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'hardware_firmware',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('component', sa.String(32), nullable=False),
        sa.Column('component_id', sa.String(255), nullable=False),
        sa.Column('current_version', sa.String(255), nullable=False),
        sa.Column('available_version', sa.String(255), nullable=True),
        sa.Column('cve_list', sa.JSON(), nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('node_id', 'component', 'component_id', name='uq_hw_fw_node_comp_id'),
    )
    op.create_index(op.f('ix_hardware_firmware_node_id'), 'hardware_firmware', ['node_id'])
    op.create_index(op.f('ix_hardware_firmware_component'), 'hardware_firmware', ['component'])
    op.create_index(op.f('ix_hardware_firmware_tenant_id'), 'hardware_firmware', ['tenant_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_hardware_firmware_tenant_id'), table_name='hardware_firmware')
    op.drop_index(op.f('ix_hardware_firmware_component'), table_name='hardware_firmware')
    op.drop_index(op.f('ix_hardware_firmware_node_id'), table_name='hardware_firmware')
    op.drop_table('hardware_firmware')
