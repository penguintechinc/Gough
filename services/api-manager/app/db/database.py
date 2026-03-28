"""
penguin-dal database configuration for runtime operations.

USAGE: penguin-dal handles ALL runtime database operations.
SQLAlchemy is only used for initial schema creation (see init_db.py).

Per CLAUDE.md standards:
- penguin-dal: ALL runtime database operations (auto-reflects tables)
- SQLAlchemy: Database initialization and schema creation only

Thread Safety:
- Thread-local storage for database connections
- Connection pooling via penguin-dal
- Safe for use with asyncio.to_thread() for blocking operations
"""

import os
from penguintechinc_utils import get_logger
import threading
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
from penguin_dal import DB
from sqlalchemy import text
from datetime import datetime

logger = get_logger(__name__)

# Thread-local storage for database connections
_thread_local = threading.local()


def init_db(
    database_url: Optional[str] = None,
    pool_size: int = 10,
) -> DB:
    """
    Initialize penguin-dal database connection.

    Args:
        database_url: Standard SQLAlchemy URI (postgresql://, mysql://, sqlite://)
                      Defaults to DATABASE_URL environment variable.
        pool_size: Connection pool size

    Returns:
        penguin-dal DB instance
    """
    database_url = database_url or os.getenv('DATABASE_URL')

    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")

    logger.info(f"Initializing penguin-dal with pool_size={pool_size}")

    db = DB(database_url, pool_size=pool_size)

    logger.info("penguin-dal initialized successfully")
    return db


def get_db() -> DB:
    """
    Get thread-local database connection.

    Returns:
        penguin-dal DB instance for current thread

    Raises:
        RuntimeError: If database not initialized for current thread
    """
    if not hasattr(_thread_local, 'db') or _thread_local.db is None:
        _thread_local.db = init_db()

    return _thread_local.db


def close_db() -> None:
    """
    Close thread-local database connection.

    Safe to call multiple times.
    """
    if hasattr(_thread_local, 'db') and _thread_local.db is not None:
        try:
            _thread_local.db.close()
            logger.debug("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}", exc_info=True)
        finally:
            _thread_local.db = None


@contextmanager
def get_db_context():
    """
    Context manager for database connections.

    Usage:
        with get_db_context() as db:
            rows = db(db.api_definitions).select()
    """
    db = get_db()
    try:
        yield db
    finally:
        db.commit()


def execute_query(
    query: str,
    params: Optional[Dict[str, Any]] = None,
    fetch: bool = True
) -> Optional[List[Dict[str, Any]]]:
    """
    Execute raw SQL query with parameter binding.

    Args:
        query: SQL query string
        params: Query parameters for binding
        fetch: Whether to fetch results

    Returns:
        List of row dictionaries if fetch=True, None otherwise
    """
    db = get_db()
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text(query), params or {})
            if fetch:
                return [dict(row._mapping) for row in result]
            conn.commit()
            return None
    except Exception as e:
        logger.error(f"Query execution failed: {e}", exc_info=True)
        raise


def get_connection_info() -> Dict[str, Any]:
    """
    Get current database connection information.

    Returns:
        Dictionary with connection details
    """
    db = get_db()
    return {
        'db_type': os.getenv('DB_TYPE', 'postgres'),
        'tables': list(db.tables.keys()),
    }


def insert_api_definition(
    name: str,
    version: str,
    path: str,
    method: str,
    description: Optional[str] = None,
    openapi_spec: Optional[Dict[str, Any]] = None,
    enabled: bool = True
) -> int:
    """
    Insert new API definition.

    Args:
        name: API name
        version: API version
        path: API path
        method: HTTP method
        description: API description
        openapi_spec: OpenAPI specification
        enabled: Whether API is enabled

    Returns:
        ID of inserted record
    """
    db = get_db()
    record_id = db.api_definitions.insert(
        name=name,
        version=version,
        path=path,
        method=method,
        description=description,
        openapi_spec=openapi_spec,
        enabled=enabled,
    )
    db.commit()
    return record_id


def get_api_definitions(
    name: Optional[str] = None,
    version: Optional[str] = None,
    enabled: Optional[bool] = None
) -> List[Dict[str, Any]]:
    """
    Get API definitions with optional filters.

    Args:
        name: Filter by API name
        version: Filter by version
        enabled: Filter by enabled status

    Returns:
        List of API definition dictionaries
    """
    db = get_db()
    query = db.api_definitions.id > 0

    if name is not None:
        query &= (db.api_definitions.name == name)
    if version is not None:
        query &= (db.api_definitions.version == version)
    if enabled is not None:
        query &= (db.api_definitions.enabled == enabled)

    rows = db(query).select()
    return [row.as_dict() for row in rows]


def insert_api_usage(
    api_id: int,
    method: str,
    path: str,
    status_code: int,
    response_time_ms: int,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> int:
    """
    Insert API usage record.

    Args:
        api_id: API definition ID
        method: HTTP method
        path: Request path
        status_code: HTTP status code
        response_time_ms: Response time in milliseconds
        user_id: User ID
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        ID of inserted record
    """
    db = get_db()
    record_id = db.api_usage.insert(
        api_id=api_id,
        method=method,
        path=path,
        status_code=status_code,
        response_time_ms=response_time_ms,
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.commit()
    return record_id


def insert_api_key(
    key_hash: str,
    name: str,
    user_id: str,
    scopes: List[str],
    enabled: bool = True,
    rate_limit: int = 1000,
    expires_at: Optional[datetime] = None
) -> int:
    """
    Insert new API key.

    Args:
        key_hash: Hashed API key
        name: Key name/description
        user_id: User ID
        scopes: List of permission scopes
        enabled: Whether key is enabled
        rate_limit: Rate limit per hour
        expires_at: Expiration datetime

    Returns:
        ID of inserted record
    """
    db = get_db()
    record_id = db.api_keys.insert(
        key_hash=key_hash,
        name=name,
        user_id=user_id,
        scopes=scopes,
        enabled=enabled,
        rate_limit=rate_limit,
        expires_at=expires_at,
    )
    db.commit()
    return record_id


def get_api_key_by_hash(key_hash: str) -> Optional[Dict[str, Any]]:
    """
    Get API key by hash.

    Args:
        key_hash: Hashed API key

    Returns:
        API key dictionary or None if not found
    """
    db = get_db()
    row = db(db.api_keys.key_hash == key_hash).select().first()
    return row.as_dict() if row else None


def update_api_key_last_used(key_id: int) -> bool:
    """
    Update API key last used timestamp.

    Args:
        key_id: API key ID

    Returns:
        True if updated, False otherwise
    """
    db = get_db()
    updated = db(db.api_keys.id == key_id).update(last_used_at=datetime.utcnow())
    db.commit()
    return updated > 0
