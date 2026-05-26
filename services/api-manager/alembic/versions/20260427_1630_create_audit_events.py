"""Create audit events hash-chain table.

Revision ID: 20260427_1630_audit_events
Revises: 20260427_1600_node_tags_operator
Create Date: 2026-04-27 16:30:00.000000

Audit log with hash-chain integrity per spec Observability § Audit Log Hash-Chain Format.
INSERT-only enforcement via role-grants (2030_db_roles_and_grants).
RLS for tenant-scope reads; offsite mirror via wal2json shipper.
Genesis row (cluster initialization) inserted by app bootstrap (gough init).

"""
from alembic import op
import sqlalchemy as sa


revision = '20260427_1630_audit_events'
down_revision = '20260427_1600_node_tags_operator'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'audit_events',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('cluster_id', sa.String(255), nullable=False),
        sa.Column('tenant_id', sa.String(255), nullable=True),
        sa.Column('actor_sub', sa.String(512), nullable=False),
        sa.Column('actor_scope', sa.JSON(), nullable=True),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('resource_kind', sa.String(64), nullable=False),
        sa.Column('resource_id', sa.String(255), nullable=True),
        sa.Column('before_json', sa.JSON(), nullable=True),
        sa.Column('after_json', sa.JSON(), nullable=True),
        sa.Column('request_id', sa.String(255), nullable=True),
        sa.Column('source_ip', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(512), nullable=True),
        sa.Column('prev_hash', sa.LargeBinary(length=32), nullable=False),
        sa.Column('hash', sa.LargeBinary(length=32), nullable=False),
        sa.Column('signature', sa.LargeBinary(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_audit_events_ts'), 'audit_events', ['ts'])
    op.create_index(op.f('ix_audit_events_cluster_id_ts'), 'audit_events', ['cluster_id', 'ts'])
    op.create_index(op.f('ix_audit_events_tenant_id_ts'), 'audit_events', ['tenant_id', 'ts'])
    op.create_index(op.f('ix_audit_events_actor_sub'), 'audit_events', ['actor_sub'])
    op.create_index(op.f('ix_audit_events_action'), 'audit_events', ['action'])
    op.create_index(op.f('ix_audit_events_request_id'), 'audit_events', ['request_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_audit_events_request_id'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_action'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_actor_sub'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_tenant_id_ts'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_cluster_id_ts'), table_name='audit_events')
    op.drop_index(op.f('ix_audit_events_ts'), table_name='audit_events')
    op.drop_table('audit_events')
