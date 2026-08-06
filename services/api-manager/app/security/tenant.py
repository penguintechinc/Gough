"""Tenant isolation primitives for multi-tenant security layer 1 + 4.

Layer 1: JWT tenant claim extraction; reject if missing or mismatched.
Layer 4: Postgres GUC (app.current_tenant) for RLS policies.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field
from quart import g


# ==============================================================================
# Constants
# ==============================================================================

TENANT_CLAIM_NAME: str = "tenant"
DEFAULT_TENANT: str = "__default__"


# ==============================================================================
# Data Models
# ==============================================================================

class TenantContext(BaseModel):
    """Tenant context extracted from JWT + current request."""

    tenant_id: str = Field(..., min_length=1, description="Tenant ID from JWT claim")
    cross_tenant: bool = Field(
        default=False,
        description="Super-admin override to access cross-tenant data"
    )

    class Config:
        """Pydantic config."""
        frozen = True


# ==============================================================================
# Exceptions
# ==============================================================================

class TenantClaimMissingError(Exception):
    """Raised when tenant claim is missing from JWT payload."""

    pass


class TenantMismatchError(Exception):
    """Raised when request body tenant_id differs from JWT tenant claim."""

    pass


# ==============================================================================
# Tenant Extraction & Validation
# ==============================================================================

def extract_tenant_from_jwt(payload: dict) -> TenantContext:
    """Extract and validate tenant context from JWT payload.

    Args:
        payload: Decoded JWT payload dictionary.

    Returns:
        TenantContext with tenant_id + cross_tenant flag.

    Raises:
        TenantClaimMissingError: If tenant claim absent or empty.
    """
    tenant_id = payload.get(TENANT_CLAIM_NAME)

    if not tenant_id or not isinstance(tenant_id, str):
        raise TenantClaimMissingError(
            f"JWT missing or invalid {TENANT_CLAIM_NAME} claim"
        )

    cross_tenant = payload.get("cross_tenant", False) is True

    return TenantContext(tenant_id=tenant_id, cross_tenant=cross_tenant)


def assert_tenant_match(token_tenant: str, body_tenant: Optional[str]) -> None:
    """Validate request body tenant_id matches JWT tenant claim.

    Used by handlers that accept tenant_id in request body to prevent
    users from accessing data of a different tenant.

    Args:
        token_tenant: Tenant ID extracted from JWT.
        body_tenant: Tenant ID from request body (if provided).

    Raises:
        TenantMismatchError: If body_tenant is not None and != token_tenant.
    """
    if body_tenant is not None and body_tenant != token_tenant:
        raise TenantMismatchError(
            f"Request body tenant_id ({body_tenant}) "
            f"does not match JWT tenant ({token_tenant})"
        )


# ==============================================================================
# Middleware Integration
# ==============================================================================

async def tenant_middleware(
    app,
    request_context_setter,
) -> None:
    """Quart before_request middleware for tenant isolation.

    Responsibilities:
    1. Skip for anonymous paths (import from scope_policy.ANONYMOUS_PATHS).
    2. Decode JWT (use existing app.middleware.decode_token).
    3. Extract tenant via extract_tenant_from_jwt.
    4. Store in quart.g.tenant_context.
    5. Set Postgres GUC via penguin-dal connection.
    6. Return 403 on TenantClaimMissingError.

    Tenant GUC Enforcement (RLS Layer 4 — FIX #7a):
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    The tenant GUC ``app.current_tenant`` is pushed via a
    ``contextvars.ContextVar`` (``app.db.rls.set_current_tenant``) that a
    SQLAlchemy connection-pool ``checkout`` event listener
    (``app.db.rls.install_rls_events``) reads and applies to whichever
    physical connection penguin-dal hands out next -- i.e. the SAME
    connection that serves the request's queries, not a throwaway one set up
    and torn down separately. A ContextVar (not ``threading.local``) is used
    because blocking penguin-dal calls run via ``asyncio.to_thread()`` on a
    worker thread; ``asyncio.to_thread()`` copies the current context onto
    that thread, so the value set here is visible wherever the query
    actually executes. This ensures Postgres RLS policies enforcing tenant
    isolation actually receive the GUC value and enforce row filtering.
    Application-level tenant guards (FIX #7b, #7c, #17) provide
    defense-in-depth; RLS is the secondary layer.

    Args:
        app: Quart application instance.
        request_context_setter: Callback to store tenant in request context.

    Raises:
        TenantClaimMissingError: Handled internally; returns 403.
    """
    # Circular import avoided by importing inside function
    from quart import request, jsonify
    from app.middleware import get_token_from_header, decode_token
    from app.security.scope_policy import ANONYMOUS_PATHS
    from app.db.rls import CROSS_TENANT_SENTINEL, set_current_tenant

    # Check if current request is anonymous
    method = request.method
    path = request.path

    if (method, path) in ANONYMOUS_PATHS:
        return

    # Extract and decode JWT
    token = get_token_from_header()
    if not token:
        return  # Let auth_required decorator handle missing token

    payload = decode_token(token)
    if not payload:
        return  # Let auth_required decorator handle invalid token

    # Extract tenant from JWT
    try:
        tenant_context = extract_tenant_from_jwt(payload)
    except TenantClaimMissingError:
        return jsonify({"error": "tenant_claim_missing"}), 403

    # Store tenant context in request scope
    g.tenant_context = tenant_context

    # FIX #7a: push the tenant onto the ContextVar the connection-pool
    # checkout listener reads (app.db.rls.install_rls_events). Super-admin
    # (cross_tenant=True) tokens push the CROSS_TENANT_SENTINEL instead of
    # their own tenant_id -- the generic RLS `tenant_isolation` policy
    # treats that sentinel as "match every row" (see app.db.rls docstring).
    guc_tenant = (
        CROSS_TENANT_SENTINEL if tenant_context.cross_tenant else tenant_context.tenant_id
    )
    set_current_tenant(guc_tenant)

    # Retained on g for source compatibility with any code still reading it
    # directly (the ContextVar above is the value the pool listener acts on).
    g._tenant_id_for_guc = tenant_context.tenant_id
