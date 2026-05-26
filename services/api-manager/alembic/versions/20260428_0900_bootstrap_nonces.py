"""Create bootstrap_nonces table for one-time iPXE bootstrap JWT nonces.

Revision ID: 20260428_0900_bootstrap_nonces
Revises: 20260427_2030_db_roles_and_grants
Create Date: 2026-04-28 09:00:00.000000

Used as a fallback nonce store when the runtime Redis client is unavailable.
The Sprint 2 iPXE chain endpoints (`/api/v1/ipxe/helper/{mac}`,
`/api/v1/ipxe/deploy/{mac}`, `/api/v1/ipxe/mint-bootstrap-token`) write a row
here whenever a fresh bootstrap JWT is minted, and
`app.security.credentials.validate_one_time_bootstrap_token` reads from
Redis or this table to enforce single-use.
"""
from alembic import op
import sqlalchemy as sa


revision = '20260428_0900_bootstrap_nonces'
down_revision = '20260427_2030_db_roles_and_grants'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'bootstrap_nonces',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('nonce', sa.String(128), nullable=False, unique=True),
        sa.Column('mac', sa.String(17), nullable=False),
        sa.Column('phase', sa.String(16), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index('ix_bootstrap_nonces_mac', 'bootstrap_nonces', ['mac'])
    op.create_index('ix_bootstrap_nonces_expires_at', 'bootstrap_nonces', ['expires_at'])


def downgrade() -> None:
    op.drop_index('ix_bootstrap_nonces_expires_at', table_name='bootstrap_nonces')
    op.drop_index('ix_bootstrap_nonces_mac', table_name='bootstrap_nonces')
    op.drop_table('bootstrap_nonces')
