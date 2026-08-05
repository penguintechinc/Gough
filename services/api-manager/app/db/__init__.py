"""
Database layer for API Manager service.

This module provides database initialization and runtime operations:
- SQLAlchemy: Schema creation only
- PyDAL: All runtime operations and migrations
- Multi-database support: PostgreSQL, MariaDB, MariaDB Galera, SQLite
"""

from .database import (
    get_db,
    close_db,
    init_db,
    execute_query,
    get_connection_info,
)
from .init_db import init_db_schema, create_tables
from .galera import (
    is_galera_enabled,
    set_wsrep_sync_wait,
    handle_galera_deadlock,
    GaleraConfig,
)
from .rls import (
    CROSS_TENANT_SENTINEL,
    get_current_tenant,
    install_rls_events,
    set_current_tenant,
)

__all__ = [
    # penguin-dal runtime operations
    'get_db',
    'close_db',
    'init_db',
    'execute_query',
    'get_connection_info',
    # SQLAlchemy schema initialization
    'init_db_schema',
    'create_tables',
    # Galera cluster support
    'is_galera_enabled',
    'set_wsrep_sync_wait',
    'handle_galera_deadlock',
    'GaleraConfig',
    # RLS tenant GUC wiring (FIX #7a)
    'CROSS_TENANT_SENTINEL',
    'get_current_tenant',
    'install_rls_events',
    'set_current_tenant',
]
