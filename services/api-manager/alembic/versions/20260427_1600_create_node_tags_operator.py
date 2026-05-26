"""Create operator-defined node tags table.

Revision ID: 20260427_1600_node_tags_operator
Revises: 20260427_1530_hardware_firmware
Create Date: 2026-04-27 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '20260427_1600_node_tags_operator'
down_revision = '20260427_1530_hardware_firmware'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'node_tags_operator',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('node_id', sa.Integer(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('tag_key', sa.String(255), nullable=False),
        sa.Column('tag_value', sa.String(255), nullable=False),
        sa.Column('provenance', sa.String(32), nullable=False, server_default='operator'),
        sa.Column('set_by_actor_sub', sa.String(255), nullable=True),
        sa.Column('set_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['node_id'], ['nodes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('node_id', 'tag_key', 'tag_value', name='uq_node_tags_op_node_key_val'),
    )
    op.create_index(op.f('ix_node_tags_operator_node_id'), 'node_tags_operator', ['node_id'])
    op.create_index(op.f('ix_node_tags_operator_tag_key'), 'node_tags_operator', ['tag_key'])
    op.create_index(op.f('ix_node_tags_operator_tenant_id'), 'node_tags_operator', ['tenant_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_node_tags_operator_tenant_id'), table_name='node_tags_operator')
    op.drop_index(op.f('ix_node_tags_operator_tag_key'), table_name='node_tags_operator')
    op.drop_index(op.f('ix_node_tags_operator_node_id'), table_name='node_tags_operator')
    op.drop_table('node_tags_operator')
