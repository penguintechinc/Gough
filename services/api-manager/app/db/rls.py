"""Postgres Row-Level-Security (RLS) tenant GUC wiring for penguin-dal connections.

FIX #7a. The Alembic baseline (``alembic/versions/20260805_1000_baseline_full_schema.py``)
enables RLS + a ``tenant_isolation`` policy on every tenant-scoped table::

    USING (current_setting('app.current_tenant', true) IN (tenant_id, '__default__', '__all__'))

but nothing ever attached the ``app.current_tenant`` GUC to the connection the
app's queries actually run on. ``app.security.tenant.set_tenant_guc()`` (now
removed -- see below) set it transaction-locally (``set_config(..., true)``)
on a connection object the caller had to pass in -- none of penguin-dal's
request-scoped query paths ever did, so for the scoped ``api-manager-rw``
role (table owners are RLS-exempt, which is why this went unnoticed) RLS
silently filtered every row to zero and the app has been relying entirely on
its own app-level tenant filters.

This module closes that gap for the request-path connection pool -- the
engine backing ``app.config["db"]`` (``app.models.get_db()``, wired via
``install_rls_events`` in ``app.models.init_db``) -- by hanging the GUC
set/reset off that pool's own ``checkout``/``checkin`` events, rather than by
having every call site thread a connection through a helper like the old
``set_tenant_guc`` by hand. That function's last three call sites
(``app.api.audit.verify_audit_chain``/``export_audit_log``,
``app.api.joiner_secrets.revoke_joiner_secret``) were deleted in the FIX #7a
cleanup, and the function itself was removed from
``app.security.tenant`` -- this module (installed once, at engine-init time)
is now the sole mechanism that applies the GUC. It does NOT cover the
separate thread-local ``DB`` pool in
``app.db.database`` (``get_db()`` there, keyed off ``DATABASE_URL``) --
that pool has no RLS wiring at all today; nothing in this codebase should
be using it for tenant-scoped reads until it's either wired the same way or
consolidated away (follow-up, not done here).

Why ``contextvars.ContextVar`` and not ``threading.local``: Quart request
handlers issue blocking penguin-dal calls via ``asyncio.to_thread()``, which
runs the callable on a threadpool worker thread -- NOT the event-loop
thread the tenant middleware ran on. ``asyncio.to_thread()`` copies the
*current context* (``contextvars.copy_context()``) onto that worker thread,
so a value set on a ``ContextVar`` before the ``to_thread`` call IS visible
inside it. A ``threading.local`` set on the event-loop thread would NOT be
visible there -- it is genuinely thread-local, and the worker thread is a
different thread. ``quart.g`` is itself ContextVar-backed and would also
propagate, but a dedicated ContextVar is used here so the GUC can still be
resolved from a pool checkout that fires outside of any Quart request/app
context (e.g. during app startup schema checks, or a background worker that
never goes through Quart's request machinery at all).
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# Fail-closed sentinel for "no tenant on this context". Deliberately NOT
# '__default__' or '__all__' -- both of those are literal members of the
# RLS policy's IN-list (see module docstring), so setting the GUC to either
# of them would make the policy match every row regardless of tenant_id.
# An empty string matches no real tenant_id and isn't a recognized sentinel,
# so an unset ContextVar (startup, a background task that never ran through
# tenant middleware, a bug that skipped tenant extraction) yields ZERO rows
# on every RLS-protected table -- fail closed, never fail open.
_UNSET_TENANT_GUC: str = ""

# Cross-tenant / super-admin sentinel. Literally present in the generic
# ``tenant_isolation`` policy's IN-list, so setting the GUC to this value
# matches every row on every table using that policy regardless of the
# row's own tenant_id -- this is intentional, it's how a super-admin token
# (``TenantContext.cross_tenant=True``) sees across tenants.
#
# NOTE: ``node_events`` carries its own bespoke policy that recognizes
# '__super__' instead of '__all__' for the same purpose (see the baseline
# migration's ``node_events_tenant_isolation`` policy). That is a
# pre-existing inconsistency in the schema this task did not introduce and
# is out of scope to change here -- cross-tenant callers querying
# node_events specifically will not currently get the bypass this sentinel
# grants everywhere else. Flagged for a follow-up task.
CROSS_TENANT_SENTINEL: str = "__all__"

_current_tenant: ContextVar[str | None] = ContextVar("gough_rls_current_tenant", default=None)


def set_current_tenant(tenant_id: str | None) -> None:
    """Set the tenant id the next connection-pool checkout will push as the GUC.

    Called by the tenant middleware once per request (and with ``None`` at
    request teardown to clear it). ``None`` always resolves to the
    fail-closed sentinel at checkout time -- it never falls back to an
    unrestricted value.

    Args:
        tenant_id: Tenant id to scope subsequent queries to, or ``None`` to
            clear (fail closed) -- e.g. at request teardown, or outside of
            any request context.
    """
    _current_tenant.set(tenant_id)


def get_current_tenant() -> str | None:
    """Return the tenant id currently set on this context, if any.

    Returns:
        The tenant id set via ``set_current_tenant``, or ``None`` if unset
        on the current context (event-loop task or ``asyncio.to_thread``
        worker -- the latter inherits whatever was set on the task that
        spawned it).
    """
    return _current_tenant.get()


def _resolve_guc_value() -> str:
    """Resolve the current ContextVar tenant to the literal GUC value to push."""
    tenant_id = get_current_tenant()
    return tenant_id if tenant_id else _UNSET_TENANT_GUC


def _apply_tenant_guc(dbapi_connection: Any, value: str) -> None:
    """Push ``value`` onto ``app.current_tenant`` for one DBAPI connection.

    Runs the ``SET``-equivalent in the connection's own autocommit mode so
    it never opens (and leaves hanging) an implicit transaction that
    SQLAlchemy didn't ask for -- the same pattern SQLAlchemy's own docs use
    for connect-time session variables (e.g. ``search_path``). Uses
    ``set_config(..., false)`` (session-scoped, not transaction-local) since
    the checkout may serve several statements/transactions before the
    connection is returned to the pool; a transaction-local set would
    silently revert after the first COMMIT.

    Args:
        dbapi_connection: Raw DBAPI (psycopg2) connection from the pool.
        value: Literal value to set ``app.current_tenant`` to.
    """
    previous_autocommit = dbapi_connection.autocommit
    dbapi_connection.autocommit = True
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("SELECT set_config('app.current_tenant', %s, false)", (value,))
    finally:
        cursor.close()
        dbapi_connection.autocommit = previous_autocommit


def install_rls_events(engine: Engine) -> None:
    """Register pool ``checkout``/``checkin`` listeners that enforce the tenant GUC.

    On checkout: pushes the current ``ContextVar`` value (or the fail-closed
    sentinel if unset) onto the connection about to be handed to a
    penguin-dal ``QuerySet``/``TableProxy`` call, so Postgres RLS policies
    see the right tenant for every statement on that connection.

    On checkin: resets the GUC before the connection goes back into the
    pool, so a connection reused for a different tenant's request (or no
    tenant at all) never starts out carrying a stale value.

    A no-op for any non-Postgres engine (sqlite in unit tests, etc.) -- RLS
    and this GUC are Postgres-specific.

    Args:
        engine: The SQLAlchemy engine backing ``penguin_dal.DB`` (i.e.
            ``app.config["db"].engine``). Call once, during app init,
            immediately after the ``DB`` instance is constructed.
    """
    if engine.dialect.name != "postgresql":
        return

    @event.listens_for(engine, "checkout")
    def _rls_checkout(dbapi_connection: Any, connection_record: Any, connection_proxy: Any) -> None:  # noqa: ARG001
        value = _resolve_guc_value()
        try:
            _apply_tenant_guc(dbapi_connection, value)
        except Exception:
            # Fail closed: if we can't prove the GUC is set correctly, the
            # connection must not be handed out for use -- surface the
            # error rather than letting a query run with an unknown/stale
            # tenant scope.
            logger.exception("Failed to set app.current_tenant GUC at pool checkout")
            raise

    @event.listens_for(engine, "checkin")
    def _rls_checkin(dbapi_connection: Any, connection_record: Any) -> None:  # noqa: ARG001
        try:
            _apply_tenant_guc(dbapi_connection, _UNSET_TENANT_GUC)
        except Exception:
            # Don't crash checkin over a reset failure on what may already
            # be a broken/closed connection -- the pool invalidates
            # connections that fail here on their own. The checkout
            # listener re-applies the correct value (or fails closed) the
            # next time this connection (or its replacement) is checked
            # out, so there is no window where a stale tenant leaks.
            logger.warning(
                "Failed to reset app.current_tenant GUC at pool checkin", exc_info=True
            )
