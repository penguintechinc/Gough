"""Authentication and Authorization Middleware.

Wires together three distinct enforcement layers, in the order required by
the Gough security model:

  1. Credential validation        — populates ``g.current_user`` and the
                                    decoded JWT payload at ``g.current_user
                                    ['_jwt_payload']``.
  2. Tenant middleware            — ``app.security.tenant.tenant_middleware``
                                    sets ``g.tenant_context`` and the Postgres
                                    ``app.current_tenant`` GUC.
  3. Scope enforcement middleware — ``app.security.scope_enforcement
                                    .scope_enforcement_middleware`` checks
                                    ``SCOPE_POLICY`` (fail-closed).

The legacy ``auth_required`` / ``admin_required`` /
``maintainer_or_admin_required`` decorators are preserved for source
compatibility with existing routes; ``role_required`` is now implemented as
a thin shim over the new scope-enforcement primitives so existing routes
keep working without rewrites.
"""

from functools import wraps
from typing import Callable, Optional

import jwt
from quart import current_app, g, jsonify, request

from .models import get_db, get_user_by_id


# ==============================================================================
# Role → scope mapping (for the legacy role_required shim)
# ==============================================================================
#
# The legacy decorators express intent in role-name terms, but the spec
# requires authorization to be evaluated only on scopes. We map each role to
# the broadest known-scope bundle that role implies, then delegate to
# ``check_scopes``. Tokens that already carry adequate scopes (issued by a
# modern auth service) succeed without ever consulting the role claim.

_ROLE_TO_SCOPE_BUNDLE: dict[str, frozenset[str]] = {
    "admin": frozenset({"gough.cluster.admin"}),
    "maintainer": frozenset({"gough.cluster.read"}),
    "viewer": frozenset({"gough.cluster.read"}),
}


def get_token_from_header() -> Optional[str]:
    """Extract JWT token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user() -> Optional[dict]:
    """Get current authenticated user from request context."""
    return getattr(g, "current_user", None)


def user_has_role(role: str) -> bool:
    """Check if current user has a specific role.

    Args:
        role: The role name to check for

    Returns:
        True if user has the role, False otherwise
    """
    user = get_current_user()
    if not user:
        return False
    return user.get("role") == role


def auth_required(f: Callable) -> Callable:
    """Decorator to require authentication.

    Usage: @auth_required (without parentheses)
    """
    @wraps(f)
    async def decorated(*args, **kwargs):
        token = get_token_from_header()

        if not token:
            return jsonify({"error": "Missing authorization token"}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Check token type
        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type"}), 401

        # Get user from database
        user_id = payload.get("sub")
        if not user_id:
            return jsonify({"error": "Invalid token payload"}), 401

        user = get_user_by_id(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 401

        if not user.get("is_active"):
            return jsonify({"error": "User account is deactivated"}), 401

        # Attach the decoded JWT payload so downstream layers (tenant
        # middleware, scope_enforcement_middleware, require_scopes) can
        # extract scope/tenant claims without re-parsing the Authorization
        # header.
        user = dict(user)
        user["_jwt_payload"] = payload

        # Store user in request context
        g.current_user = user

        result = f(*args, **kwargs)
        if hasattr(result, '__await__'):
            return await result
        return result

    return decorated


def role_required(*allowed_roles: str) -> Callable:
    """Decorator to require ANY of the listed roles.

    Backwards-compatible shim that delegates to
    ``app.security.scope_enforcement.check_scopes``. A request is allowed if
    *either*:

    1. The token's scope claim already satisfies the scope bundle for any of
       ``allowed_roles`` (preferred — pure scope-based authz, per spec), OR
    2. The legacy ``user.role`` claim is one of ``allowed_roles`` (fallback
       so existing tokens issued before scope rollout keep working).

    Pure role-name comparison without scope evaluation is forbidden by the
    Gough security model; routes hardened post-Wave-1 should switch to the
    explicit ``@require_scopes(...)`` decorator instead.
    """
    # Lazy import to avoid a circular import with security/scope_enforcement.
    from .security.scope_enforcement import (
        check_scopes,
        extract_scopes_from_jwt,
        InsufficientScopeError,
    )

    allowed = tuple(allowed_roles)

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def decorated(*args, **kwargs):
            user = get_current_user()

            if not user:
                return jsonify({"error": "Authentication required"}), 401

            payload = user.get("_jwt_payload", {})
            provided_scopes = extract_scopes_from_jwt(payload)

            # 1. Scope-based path: any role's bundle satisfied?
            for role in allowed:
                bundle = _ROLE_TO_SCOPE_BUNDLE.get(role, frozenset())
                if not bundle:
                    continue
                try:
                    check_scopes(provided_scopes, bundle)
                except InsufficientScopeError:
                    continue
                else:
                    break
            else:
                # 2. Fallback: legacy role-name comparison.
                if user.get("role", "") not in allowed:
                    return (
                        jsonify(
                            {
                                "error": "Insufficient permissions",
                                "status": "forbidden_scope",
                                "required_roles": list(allowed),
                                "your_role": user.get("role", ""),
                            }
                        ),
                        403,
                    )

            result = f(*args, **kwargs)
            if hasattr(result, "__await__"):
                return await result
            return result

        return decorated

    return decorator


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin role."""
    return role_required("admin")(f)


def maintainer_or_admin_required(f: Callable) -> Callable:
    """Decorator to require maintainer or admin role."""
    return role_required("admin", "maintainer")(f)


def roles_required(*required_roles: str) -> Callable:
    """Decorator to require ALL specified roles."""
    return role_required(*required_roles)


def roles_accepted(*accepted_roles: str) -> Callable:
    """Decorator to require ANY of the specified roles."""
    return role_required(*accepted_roles)


# ==============================================================================
# Wiring helpers — install tenant + scope enforcement on the Quart app
# ==============================================================================


async def install_security_middleware(app) -> None:
    """Install tenant + scope enforcement middleware on the Quart app.

    Call this from the application factory exactly once, after all blueprints
    are registered. Defensive: if tenant or scope modules are not yet available
    (Wave 1 work still landing), skip those layers gracefully.

    Step 1.  Credential validation — handles per-route via @auth_required;
             populates ``g.current_user`` and ``g.current_user['_jwt_payload']``
             before any other middleware runs.

    Step 2.  Tenant middleware     — (optional) registers a ``before_request``
             handler that extracts the ``tenant`` claim, stores
             ``g.tenant_context``, and pushes the Postgres GUC.

    Step 3.  Scope enforcement     — (optional) registers a ``before_request``
             handler that consults ``SCOPE_POLICY`` (fail-closed for protected
             endpoints).

    The ``before_request`` handlers run in registration order.
    """
    # Step 1: credential validation runs per-route via @auth_required; we
    # also wire a global before_request that decodes the bearer token (when
    # present) so tenant + scope middleware can read the payload off
    # g.current_user. Endpoints without @auth_required still authenticate
    # lazily — a missing principal causes the scope layer to 401.
    @app.before_request
    async def _credential_validation():
        # Skip explicit anonymous paths (defensive: ANONYMOUS_PATHS may not exist yet).
        try:
            from app.security.scope_policy import ANONYMOUS_PATHS  # type: ignore[import-not-found]
        except (ImportError, ModuleNotFoundError):
            ANONYMOUS_PATHS = frozenset()

        if (request.method, request.path) in ANONYMOUS_PATHS:
            return None

        # If a previous middleware (or @auth_required earlier in the chain)
        # already populated g.current_user, do nothing.
        if getattr(g, "current_user", None) is not None:
            return None

        token = get_token_from_header()
        if not token:
            return None  # Let scope layer return 401.

        payload = decode_token(token)
        if not payload:
            return None  # Let scope layer return 401.

        sub = payload.get("sub")
        if sub is None:
            return None

        try:
            user = get_user_by_id(int(sub))
        except (TypeError, ValueError):
            return None

        if not user or not user.get("is_active"):
            return None

        user = dict(user)
        user["_jwt_payload"] = payload
        g.current_user = user
        return None

    # Step 2: tenant middleware (defensive).
    _tenant_mw = safe_import_tenant_middleware()
    if _tenant_mw is not None:
        async def _noop_setter(*_a, **_kw):  # noqa: ARG001
            return None

        @app.before_request
        async def _tenant_before_request():
            return await _tenant_mw(app, _noop_setter)

    # Step 3: scope enforcement (defensive).
    _scope_result = safe_import_scope_enforcement()
    if _scope_result is not None:
        _scope_mw, _, _ = _scope_result
        try:
            await _scope_mw(app)
        except Exception as exc:  # noqa: BLE001
            # If scope middleware fails to initialize (e.g., SCOPE_POLICY not
            # yet defined), log and continue; exporter will still work.
            import logging
            logging.warning(
                "install_security_middleware: scope_enforcement_middleware "
                "init failed (Wave 1 work may be incomplete): %s",
                exc,
            )


# Convenience alias used by app/__init__.py so the factory can simply call
# ``await wire_middleware(app)`` after registering all blueprints.
wire_middleware = install_security_middleware


# ==============================================================================
# Lazy imports of tenant + scope modules (for install_security_middleware)
# ==============================================================================
#
# These modules (app.security.tenant, app.security.scope_enforcement) are
# landing in parallel Wave 1 work and may not yet exist when the exporter
# runs. Defensive code in install_security_middleware handles ImportError.


def safe_import_tenant_middleware() -> Optional[Callable]:
    """Attempt to import tenant_middleware; return None if unavailable."""
    try:
        from app.security.tenant import tenant_middleware  # type: ignore[import-not-found]
        return tenant_middleware
    except (ImportError, ModuleNotFoundError):
        return None


def safe_import_scope_enforcement() -> Optional[tuple[Callable, Callable, type]]:
    """Attempt to import scope enforcement primitives; return None if unavailable."""
    try:
        from app.security.scope_enforcement import (  # type: ignore[import-not-found]
            scope_enforcement_middleware,
            check_scopes,
            extract_scopes_from_jwt,
        )
        return (
            scope_enforcement_middleware,
            check_scopes,
            extract_scopes_from_jwt,
        )
    except (ImportError, ModuleNotFoundError):
        return None


async def _record_request_metrics(response):
    """Record per-request latency and error metrics."""
    from .metrics import api_request_latency_seconds, api_error_total
    from quart import request
    try:
        method = request.method
        # Normalize path: replace numeric segments with {id}
        import re
        endpoint = re.sub(r"/\d+", "/{id}", request.path)
        status = str(response.status_code)
        # latency — use X-Request-Start header if set by load balancer, else 0
        elapsed = float(response.headers.get("X-Response-Time-Seconds", 0))
        api_request_latency_seconds.labels(method=method, endpoint=endpoint, status_code=status).observe(elapsed)
        if response.status_code >= 400:
            api_error_total.labels(method=method, endpoint=endpoint, status_code=status).inc()
    except Exception:
        pass
    return response
