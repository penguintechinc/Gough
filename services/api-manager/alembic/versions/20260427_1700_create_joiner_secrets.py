"""Create joiner_secrets table.

Revision ID: 20260427_1700_joiner_secrets
Revises: 20260427_1630_audit_events
Create Date: 2026-04-27 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '20260427_1700_joiner_secrets'
down_revision = '20260427_1630_audit_events'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'joiner_secrets',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('cluster_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('egg_kind', sa.String(64), nullable=False),
        sa.Column('emitter_egg_id', sa.Integer(), nullable=False),
        sa.Column('emitter_node_id', sa.Integer(), nullable=True),
        sa.Column('extractor_name', sa.String(255), nullable=False),
        sa.Column('scope', sa.String(16), nullable=False),
        sa.Column('ciphertext', sa.LargeBinary(), nullable=False),
        sa.Column('iv', sa.LargeBinary(length=12), nullable=False),
        sa.Column('auth_tag', sa.LargeBinary(length=16), nullable=False),
        sa.Column('dek_wrapped', sa.LargeBinary(), nullable=False),
        sa.Column('vault_kek_name', sa.String(255), nullable=False),
        sa.Column('ttl_seconds', sa.Integer(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rotation_class', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('audit_event_id', sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(['emitter_egg_id'], ['eggs.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['emitter_node_id'], ['nodes.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['audit_event_id'], ['audit_events.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_joiner_secrets_cluster_egg_extractor', 'joiner_secrets',
                    ['cluster_id', 'egg_kind', 'extractor_name'],
                    postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_index('ix_joiner_secrets_expires_at', 'joiner_secrets', ['expires_at'],
                    postgresql_where=sa.text('revoked_at IS NULL'))
    op.create_index('ix_joiner_secrets_tenant_id', 'joiner_secrets', ['tenant_id'])


def downgrade() -> None:
    op.drop_index('ix_joiner_secrets_tenant_id', table_name='joiner_secrets')
    op.drop_index('ix_joiner_secrets_expires_at', table_name='joiner_secrets')
    op.drop_index('ix_joiner_secrets_cluster_egg_extractor', table_name='joiner_secrets')
    op.drop_table('joiner_secrets')
