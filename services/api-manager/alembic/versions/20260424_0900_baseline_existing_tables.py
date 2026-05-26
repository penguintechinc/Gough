"""Baseline migration: capture existing tables.

Revision ID: 20260424_0900_baseline
Revises:
Create Date: 2026-04-24 09:00:00.000000

This is the M1 Sprint 1 baseline per CQ-2 resolution. All existing SQLAlchemy
tables are captured here; future migrations build on this baseline.

Tables captured (40 total):
- Auth: auth_role, auth_user, auth_user_roles, auth_refresh_tokens, auth_password_resets
- Secrets: secrets_config, encrypted_secrets
- Storage: storage_config
- Cloud: cloud_providers, cloud_machines
- MaaS: maas_config, servers
- LXD: lxd_clusters, lxd_cluster_members
- Cloud-Init: cloud_init_templates, package_configs
- Deployment: deployment_jobs
- FleetDM: fleetdm_config, fleet_hosts, fleet_queries, query_executions,
           fleet_alerts, alert_history, osquery_results
- Elder: elder_config, elder_hosts, elder_apps
- Teams: resource_teams, team_members, resource_assignments
- Shell Access: access_agents, enrollment_keys, ssh_ca_config, shell_sessions
- System: system_logs
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = '20260424_0900_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all existing tables if they don't exist (idempotent, dialect-portable).

    Uses SQLAlchemy metadata-driven creation so PostgreSQL, MySQL/MariaDB Galera, and SQLite
    all get correct dialect-specific DDL. checkfirst=True makes this a no-op when tables already
    exist, supporting both fresh installs and brownfield Gough deployments per CQ-2 resolution.
    """
    import sys
    from pathlib import Path

    # Ensure app/ on sys.path so models_sqlalchemy import works inside the Alembic env
    app_path = Path(__file__).resolve().parent.parent.parent / "app"
    if str(app_path) not in sys.path:
        sys.path.insert(0, str(app_path))

    from models_sqlalchemy import Base

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind, checkfirst=True)


def downgrade() -> None:
    """Drop all baseline tables (reverse-FK order via SQLAlchemy metadata).

    Destructive; only run when fully reverting the M1 baseline.
    """
    import sys
    from pathlib import Path

    app_path = Path(__file__).resolve().parent.parent.parent / "app"
    if str(app_path) not in sys.path:
        sys.path.insert(0, str(app_path))

    from models_sqlalchemy import Base

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind, checkfirst=True)
