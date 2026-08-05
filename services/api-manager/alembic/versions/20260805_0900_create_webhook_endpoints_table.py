"""Create webhook_endpoints table.

Revision ID: 20260805_0900_create_webhook_endpoints_table
Revises: 20260509_1000_create_upgrade_runs_table
Create Date: 2026-08-05 09:00:00.000000

``app/api/webhooks.py`` and ``app/workers/webhook_dispatcher.py`` read/write a
``webhook_endpoints`` table via raw SQL, but no migration or ORM model ever
defined it -- ``alembic upgrade head`` never created the table those modules
depend on. Column set and types are derived directly from the raw SQL/usage
in both modules:

- ``id``: primary key, never supplied on INSERT (bare ``RETURNING id``) ->
  DB-native autoincrement integer, portable across Postgres (SERIAL/IDENTITY)
  and MariaDB (AUTO_INCREMENT) with no dialect-specific default expression.
- ``tenant_id``, ``url``, ``signing_mode``, ``active``, ``event_filter``,
  ``retry_policy``: exact columns selected/inserted in
  ``list_webhooks``/``create_webhook``/``test_webhook``/``_load_endpoints``.
- ``created_at``/``updated_at``: not referenced by raw SQL but added for
  parity with every other table in this schema (audit trail convention);
  additive-only, never selected by column name in existing queries so this
  cannot break anything that reads a fixed column list.
- No ``secret``/``name`` columns: HMAC/asymmetric signing material lives in
  Vault only (``WebhookKeyManager``) and is intentionally never persisted to
  this table (see ``app/api/webhooks.py`` module docstring).

Dialect-neutral: JSON columns use ``with_variant(postgresql.JSONB(), ...)``
to get JSONB on Postgres and plain (fully-supported) JSON on MariaDB, same
pattern as the ``nodes.hardware_tags`` fix in 20260427_0930_nodes. No
Postgres-only constructs are used unguarded.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '20260805_0900_create_webhook_endpoints_table'
down_revision = '20260509_1000_create_upgrade_runs_table'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create webhook_endpoints table."""
    op.create_table(
        'webhook_endpoints',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.String(255), nullable=False, server_default='__default__'),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('signing_mode', sa.String(32), nullable=False, server_default='ed25519'),
        sa.Column('active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column(
            'event_filter',
            sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'),
            nullable=True,
        ),
        sa.Column(
            'retry_policy',
            sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'),
            nullable=True,
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_index('ix_webhook_endpoints_tenant_id', 'webhook_endpoints', ['tenant_id'])
    op.create_index('ix_webhook_endpoints_active', 'webhook_endpoints', ['active'])


def downgrade() -> None:
    """Drop webhook_endpoints table."""
    op.drop_index('ix_webhook_endpoints_active', table_name='webhook_endpoints')
    op.drop_index('ix_webhook_endpoints_tenant_id', table_name='webhook_endpoints')
    op.drop_table('webhook_endpoints')
