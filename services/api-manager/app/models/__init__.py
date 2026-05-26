"""Package initialization for models submodule.

This package re-exports functions from parent models module and constants from ipxe.py.

Note: This is a workaround for the namespace collision between models.py (file) and
models/ (directory). Since Python prefers the package, we re-export the essential
functions from the parent module here.
"""

# Re-export functions that were in models.py
# These are imported from the parent module by manipulating sys.modules
from datetime import datetime
from quart import Quart, g
from penguin_dal import DB
from ..config import Config
from ..models_sqlalchemy import create_all_tables

# Valid roles for RBAC
VALID_ROLES = ["admin", "maintainer", "viewer"]

# Cloud provider types
CLOUD_PROVIDER_TYPES = ["maas", "lxd", "aws", "gcp", "azure", "vultr"]

# Secrets backend types
SECRETS_BACKEND_TYPES = ["encrypted_db", "vault", "infisical", "aws", "gcp", "azure"]

# Job status values
JOB_STATUSES = ["pending", "running", "completed", "failed", "cancelled"]

# Machine status values - note: different from iPXE MACHINE_STATUSES
MACHINE_STATUSES = [
    "new", "commissioning", "ready", "allocated", "deploying",
    "deployed", "releasing", "disk_erasing", "failed", "broken",
    "running", "stopped", "terminated"
]


def validate_database_schema(db_uri: str) -> bool:
    """Validate database schema has expected keys.

    Checks for critical tables and columns without creating them.
    Returns True if validation passes, False if schema needs initialization.
    """
    from sqlalchemy import create_engine, inspect
    from ..models_sqlalchemy import get_sqlalchemy_engine

    engine = get_sqlalchemy_engine(db_uri)
    inspector = inspect(engine)

    # Check for critical tables
    expected_tables = ['auth_user', 'auth_role', 'auth_user_roles']
    existing_tables = inspector.get_table_names()

    for table in expected_tables:
        if table not in existing_tables:
            print(f"Missing table: {table}")
            return False

    # Check auth_user table has expected columns
    auth_user_columns = {col['name'] for col in inspector.get_columns('auth_user')}
    expected_columns = {'id', 'email', 'password', 'active', 'fs_uniquifier'}

    if not expected_columns.issubset(auth_user_columns):
        missing = expected_columns - auth_user_columns
        print(f"Missing columns in auth_user: {missing}")
        return False

    # Check if default admin exists
    from sqlalchemy import text
    with engine.connect() as conn:
        result = conn.execute(text("SELECT COUNT(*) FROM auth_user WHERE email = 'admin@gough.local'"))
        admin_count = result.scalar()

        if admin_count == 0:
            print("Default admin user not found")
            return False

    print("Database schema validation passed")
    return True


def init_db(app: Quart) -> DB:
    """Initialize database connection.

    Uses SQLAlchemy for schema creation/migration, penguin-dal for runtime operations.

    Startup workflow:
    1. Validate database schema has expected keys
    2. If validation fails, run SQLAlchemy schema creation
    3. Create default admin if missing
    4. Connect penguin-dal for runtime queries (no table definitions)
    """
    db_uri = Config.get_db_uri()

    # Step 1: Validate schema or create it
    if not validate_database_schema(db_uri):
        print(f"Database schema validation failed, creating schema with SQLAlchemy: {db_uri}")
        create_all_tables(db_uri)
        print("Database schema created successfully")
    else:
        print("Database schema already exists and is valid")

    # Step 2: Connect penguin-dal for runtime operations
    db = DB(db_uri, pool_size=Config.DB_POOL_SIZE)

    # Store db instance in app
    app.config["db"] = db

    return db


def get_db() -> DB:
    """Get database connection for current request context."""
    from quart import current_app

    if "db" not in g:
        g.db = current_app.config.get("db")
    return g.db


def get_user_by_id(user_id: int) -> dict | None:
    """Look up a user by primary key; returns dict or None."""
    db = get_db()
    if db is None:
        return None
    try:
        row = db.auth_user(user_id)
        if not row:
            return None
        return {
            "id": int(row.id),
            "email": str(row.email),
            "full_name": str(row.full_name) if hasattr(row, "full_name") else None,
            "active": bool(row.active),
            "role": _get_user_role(db, int(row.id)),
        }
    except Exception:
        return None


def _get_user_role(db: DB, user_id: int) -> str:
    """Return the first role name for a user, defaulting to 'viewer'."""
    try:
        join = db(db.auth_user_roles.user_id == user_id).select().first()
        if join:
            role = db.auth_role(join.role_id)
            if role:
                return str(role.name)
    except Exception:
        pass
    return "viewer"


# Export iPXE constants
from .ipxe import (
    DHCP_MODES,
    BOOT_MODES,
    ARCHITECTURES,
    POWER_TYPES,
    BIOME_TYPES,
    IMAGE_TYPES,
    DEPLOYMENT_STATUSES,
    BOOT_EVENT_TYPES,
    STORAGE_PROVIDERS,
)

__all__ = [
    "init_db",
    "get_db",
    "get_user_by_id",
    "VALID_ROLES",
    "CLOUD_PROVIDER_TYPES",
    "SECRETS_BACKEND_TYPES",
    "JOB_STATUSES",
    "MACHINE_STATUSES",
    "DHCP_MODES",
    "BOOT_MODES",
    "ARCHITECTURES",
    "POWER_TYPES",
    "BIOME_TYPES",
    "IMAGE_TYPES",
    "DEPLOYMENT_STATUSES",
    "BOOT_EVENT_TYPES",
    "STORAGE_PROVIDERS",
]
