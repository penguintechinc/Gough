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
    """Initialize database connection with graceful degradation.

    Uses SQLAlchemy for schema creation/migration, penguin-dal for runtime operations.

    Startup workflow:
    1. Validate database schema has expected keys
    2. If validation fails, run SQLAlchemy schema creation
    3. Create default admin if missing
    4. Connect penguin-dal for runtime queries (no table definitions)

    Graceful degradation: if penguin-dal connection fails (e.g., in-memory SQLite with
    pooling issues), logs a warning and returns None so the app can still boot with
    a degraded /health endpoint.
    """
    from ..models_sqlalchemy import convert_pydal_to_sqlalchemy_uri

    pydal_uri = Config.get_db_uri()

    # Step 1: Validate schema or create it
    try:
        if not validate_database_schema(pydal_uri):
            print(f"Database schema validation failed, creating schema with SQLAlchemy: {pydal_uri}")
            create_all_tables(pydal_uri)
            print("Database schema created successfully")
        else:
            print("Database schema already exists and is valid")
    except Exception as e:
        print(f"WARNING: Database schema validation/creation failed: {e}")
        print("Continuing with degraded database support...")

    # Step 2: Connect penguin-dal for runtime operations
    # penguin-dal expects SQLAlchemy format, so convert PyDAL URI
    try:
        sa_uri = convert_pydal_to_sqlalchemy_uri(pydal_uri)
        db = DB(sa_uri, pool_size=Config.DB_POOL_SIZE)
    except Exception as e:
        print(f"WARNING: penguin-dal DB connection failed: {e}")
        print("App will boot with degraded database support (no runtime queries)")
        # Return a None-like object that won't crash the app
        # The health endpoint will handle this gracefully
        db = None

    # Store db instance in app (may be None if connection failed)
    app.config["db"] = db

    return db


def get_db() -> DB | None:
    """Get database connection for current request context.

    Returns None if database connection is unavailable (graceful degradation).
    """
    from quart import current_app

    if "db" not in g:
        g.db = current_app.config.get("db")
    return g.db


def get_user_by_id(user_id: int) -> dict | None:
    """Get user by ID with their role information."""
    db = get_db()
    user = db(db.auth_user.id == user_id).select().first()
    if not user:
        return None

    # Get user's role
    role_name = _get_user_role(db, user_id)

    return {
        "id": user.id,
        "email": user.email,
        "password_hash": user.password,
        "full_name": user.full_name,
        "role": role_name,
        "is_active": user.active,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def get_user_by_email(email: str) -> dict | None:
    """Get user by email with their role information."""
    db = get_db()
    user = db(db.auth_user.email == email.lower()).select().first()
    if not user:
        return None

    # Get user's role
    role_name = _get_user_role(db, user.id)

    return {
        "id": user.id,
        "email": user.email,
        "password_hash": user.password,
        "full_name": user.full_name,
        "role": role_name,
        "is_active": user.active,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def _get_user_role(db: DB, user_id: int) -> str:
    """Get the primary role name for a user."""
    user_role = db(db.auth_user_roles.user_id == user_id).select().first()
    if user_role:
        role = db(db.auth_role.id == user_role.role_id).select().first()
        if role:
            return role.name
    return "viewer"  # Default role


def create_user(
    email: str,
    password_hash: str,
    full_name: str = "",
    role: str = "viewer",
) -> dict:
    """Create a new user with the specified role."""
    import uuid

    db = get_db()

    # Create user record
    user_id = db.auth_user.insert(
        email=email.lower(),
        password=password_hash,
        full_name=full_name,
        active=True,
        fs_uniquifier=str(uuid.uuid4()),
    )

    # Assign role
    role_record = db(db.auth_role.name == role).select().first()
    if role_record:
        db.auth_user_roles.insert(user_id=user_id, role_id=role_record.id)

    db.commit()

    return get_user_by_id(user_id)


def update_user(user_id: int, **kwargs) -> dict | None:
    """Update user fields."""
    db = get_db()

    # Map external field names to database field names
    field_mapping = {
        "password_hash": "password",
        "is_active": "active",
    }

    update_fields = {}
    role_update = None

    for key, value in kwargs.items():
        if key == "role":
            role_update = value
        else:
            db_field = field_mapping.get(key, key)
            update_fields[db_field] = value

    if update_fields:
        db(db.auth_user.id == user_id).update(**update_fields)

    if role_update:
        # Update role assignment
        role_record = db(db.auth_role.name == role_update).select().first()
        if role_record:
            # Remove existing role assignments
            db(db.auth_user_roles.user_id == user_id).delete()
            # Add new role assignment
            db.auth_user_roles.insert(user_id=user_id, role_id=role_record.id)

    db.commit()

    return get_user_by_id(user_id)


def delete_user(user_id: int) -> bool:
    """Delete a user and their associated records."""
    db = get_db()

    # Delete role assignments
    db(db.auth_user_roles.user_id == user_id).delete()

    # Delete refresh tokens
    db(db.auth_refresh_tokens.user_id == user_id).delete()

    # Delete password reset tokens
    db(db.auth_password_resets.user_id == user_id).delete()

    # Delete user
    deleted = db(db.auth_user.id == user_id).delete()

    db.commit()

    return deleted > 0


def list_users(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """List users with pagination."""
    db = get_db()

    # Get total count
    total = db(db.auth_user.id > 0).count()

    # Calculate offset
    offset = (page - 1) * per_page

    # Get users for page
    users = db(db.auth_user.id > 0).select(
        orderby=db.auth_user.id,
        limitby=(offset, offset + per_page),
    )

    result = []
    for user in users:
        role_name = _get_user_role(db, user.id)
        result.append({
            "id": user.id,
            "email": user.email,
            "password_hash": user.password,
            "full_name": user.full_name,
            "role": role_name,
            "is_active": user.active,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        })

    return result, total


# =============================================================================
# Refresh Token Functions
# =============================================================================

def store_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> int:
    """Store a refresh token hash in the database."""
    db = get_db()

    token_id = db.auth_refresh_tokens.insert(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked=False,
    )

    db.commit()

    return token_id


def is_refresh_token_valid(token_hash: str) -> bool:
    """Check if a refresh token is valid and not revoked."""
    db = get_db()

    token = db(
        (db.auth_refresh_tokens.token_hash == token_hash) &
        (db.auth_refresh_tokens.revoked == False) &
        (db.auth_refresh_tokens.expires_at > datetime.utcnow())
    ).select().first()

    return token is not None


def revoke_refresh_token(token_hash: str) -> bool:
    """Revoke a specific refresh token."""
    db = get_db()

    updated = db(db.auth_refresh_tokens.token_hash == token_hash).update(
        revoked=True
    )

    db.commit()

    return updated > 0


def revoke_all_user_tokens(user_id: int) -> int:
    """Revoke all refresh tokens for a user."""
    db = get_db()

    updated = db(
        (db.auth_refresh_tokens.user_id == user_id) &
        (db.auth_refresh_tokens.revoked == False)
    ).update(revoked=True)

    db.commit()

    return updated


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
    "get_user_by_email",
    "create_user",
    "update_user",
    "delete_user",
    "list_users",
    "store_refresh_token",
    "is_refresh_token_valid",
    "revoke_refresh_token",
    "revoke_all_user_tokens",
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
