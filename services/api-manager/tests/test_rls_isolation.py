"""Two-tenant Row-Level-Security isolation test (FIX #7a).

Proves the actual production bug and its fix: Postgres RLS policies filter
every row to zero for the scoped ``api-manager-rw`` role unless the
``app.current_tenant`` GUC is pushed onto the SAME connection penguin-dal's
queries run on (``app.db.rls.install_rls_events`` + ``set_current_tenant``).

``pg_db`` (tests/pg_fixtures.py) connects as the migration/table OWNER,
which Postgres exempts from RLS entirely -- no test built on ``pg_db`` could
ever have caught this bug, which is exactly why it shipped unnoticed. Every
test here uses ``pg_db_scoped`` instead, which connects as the actual
``api-manager-rw`` role the baseline migration ``GRANT``s to, so RLS is
genuinely enforced.

Proof this test is sensitive to the wiring (not just to seed data): with
``install_rls_events()`` never called (or its checkout listener gutted), a
freshly checked-out ``api-manager-rw`` connection never has
``app.current_tenant`` set at all. ``current_setting('app.current_tenant',
true)`` then returns SQL NULL, ``NULL IN (tenant_id, '__default__',
'__all__')`` evaluates to NULL (not TRUE), and the RLS ``USING`` clause
treats NULL as "filter this row out" -- every assertion below expecting
tenant A to see its own row fails (0 rows instead of 1). Verified manually
while writing this test by commenting out the ``install_rls_events(...)``
call in each test below: every non-fail-closed assertion failed as
expected.
"""

from __future__ import annotations

import pytest
from penguin_dal import DB

from app.db.rls import CROSS_TENANT_SENTINEL, install_rls_events, set_current_tenant

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"


def _seed_biome(owner_db: DB, *, name: str, tenant_id: str) -> int:
    """Insert a minimal ``biomes`` row as the table OWNER (bypasses RLS on insert)."""
    return owner_db.biomes.insert(name=name, tenant_id=tenant_id)


@pytest.fixture
def two_tenant_biomes(pg_db: DB) -> tuple[int, int]:
    """Seed one ``biomes`` row each for TENANT_A and TENANT_B, as the table owner.

    ``biomes`` is one of the tables the baseline migration enables RLS +
    the generic ``tenant_isolation`` policy on.
    """
    id_a = _seed_biome(pg_db, name="biome-a", tenant_id=TENANT_A)
    id_b = _seed_biome(pg_db, name="biome-b", tenant_id=TENANT_B)
    return id_a, id_b


def test_tenant_a_sees_only_own_row(
    pg_db_scoped: DB, two_tenant_biomes: tuple[int, int]
) -> None:
    """With the GUC set to tenant A, a scoped-role query returns ONLY tenant A's row."""
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_A)
    try:
        rows = pg_db_scoped(pg_db_scoped.biomes.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A}
    assert len(rows) == 1


def test_tenant_b_sees_only_own_row(
    pg_db_scoped: DB, two_tenant_biomes: tuple[int, int]
) -> None:
    """Symmetric check: tenant B's GUC value returns only tenant B's row, never tenant A's."""
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_B)
    try:
        rows = pg_db_scoped(pg_db_scoped.biomes.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_B}
    assert len(rows) == 1


def test_unset_tenant_is_fail_closed(
    pg_db_scoped: DB, two_tenant_biomes: tuple[int, int]
) -> None:
    """No tenant on the ContextVar -> zero rows, never every row (fail closed, not fail open).

    This is the case that most directly distinguishes "wiring present but no
    tenant set" from "wiring absent": both look like "zero rows" from this
    test alone, which is why ``test_tenant_a_sees_only_own_row`` (expecting
    a *non-empty*, tenant-scoped result) is the assertion that actually
    catches the GUC wiring being removed.
    """
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(None)

    rows = pg_db_scoped(pg_db_scoped.biomes.id > 0).select()

    assert len(rows) == 0


def test_cross_tenant_sentinel_sees_all_rows(
    pg_db_scoped: DB, two_tenant_biomes: tuple[int, int]
) -> None:
    """Super-admin (``__all__`` sentinel) bypasses tenant filtering on the generic RLS policy.

    ``__all__`` is a literal member of the ``tenant_isolation`` policy's
    ``IN`` list (see the baseline migration), so it matches every row
    regardless of that row's own ``tenant_id`` -- this is how
    ``TenantContext.cross_tenant=True`` tokens see across tenants.
    """
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(CROSS_TENANT_SENTINEL)
    try:
        rows = pg_db_scoped(pg_db_scoped.biomes.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A, TENANT_B}
    assert len(rows) == 2


def test_owner_connection_is_rls_exempt(
    pg_db: DB, two_tenant_biomes: tuple[int, int]
) -> None:
    """Documents WHY ``pg_db`` can't be used to catch FIX #7a: owners bypass RLS entirely.

    Not a test of ``app.db.rls`` -- a regression guard on the test
    infrastructure itself, proving ``pg_db_scoped`` is exercising something
    ``pg_db`` structurally cannot (no GUC set here at all, and every row
    from both tenants still comes back).
    """
    rows = pg_db(pg_db.biomes.id > 0).select()

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A, TENANT_B}


# =============================================================================
# webhook_endpoints -- added to rls_tables by the penguin-dal runtime
# migration (task 6b); previously missing from the baseline's rls_tables
# list entirely, so it had no RLS policy at all regardless of GUC wiring.
#
# Queried directly here (``pg_db_scoped.webhook_endpoints.id > 0``, no
# ``tenant_id ==`` filter) rather than through the HTTP endpoint, because
# ``app.api.webhooks.list_webhooks`` already applies its own app-level
# ``tenant_id ==`` filter -- a test that goes through the endpoint can't
# distinguish "RLS isolates the rows" from "the app-level filter isolates
# the rows" (see tests/api/test_webhooks.py's
# ``test_list_rls_isolates_two_tenants`` docstring for that endpoint-level
# smoke test instead).
# =============================================================================


def _seed_webhook_endpoint(owner_db: DB, *, url: str, tenant_id: str) -> int:
    """Insert a minimal ``webhook_endpoints`` row as the table OWNER (bypasses
    RLS on insert). created_at/updated_at have no server-side DEFAULT (see
    the note in app.api.webhooks.create_webhook) -- supplied explicitly."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return owner_db.webhook_endpoints.insert(
        tenant_id=tenant_id, url=url, signing_mode="ed25519", active=True,
        event_filter=[], retry_policy={"mode": "standard"},
        created_at=now, updated_at=now,
    )


@pytest.fixture
def two_tenant_webhook_endpoints(pg_db: DB) -> tuple[int, int]:
    id_a = _seed_webhook_endpoint(
        pg_db, url="https://a.example.com/hook", tenant_id=TENANT_A
    )
    id_b = _seed_webhook_endpoint(
        pg_db, url="https://b.example.com/hook", tenant_id=TENANT_B
    )
    return id_a, id_b


def test_webhook_endpoints_tenant_a_sees_only_own_row(
    pg_db_scoped: DB, two_tenant_webhook_endpoints: tuple[int, int]
) -> None:
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_A)
    try:
        rows = pg_db_scoped(pg_db_scoped.webhook_endpoints.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A}
    assert len(rows) == 1


def test_webhook_endpoints_tenant_b_sees_only_own_row(
    pg_db_scoped: DB, two_tenant_webhook_endpoints: tuple[int, int]
) -> None:
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_B)
    try:
        rows = pg_db_scoped(pg_db_scoped.webhook_endpoints.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_B}
    assert len(rows) == 1


def test_webhook_endpoints_unset_tenant_is_fail_closed(
    pg_db_scoped: DB, two_tenant_webhook_endpoints: tuple[int, int]
) -> None:
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(None)

    rows = pg_db_scoped(pg_db_scoped.webhook_endpoints.id > 0).select()

    assert len(rows) == 0


def test_webhook_endpoints_owner_connection_is_rls_exempt(
    pg_db: DB, two_tenant_webhook_endpoints: tuple[int, int]
) -> None:
    rows = pg_db(pg_db.webhook_endpoints.id > 0).select()

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A, TENANT_B}


# =============================================================================
# node_events -- regression: gh-22. Two distinct, previously-broken things:
#
# 1. This table carries its own bespoke RLS policy
#    (``node_events_tenant_isolation``, distinct from the generic
#    ``tenant_isolation`` policy every other table above uses) that used to
#    recognize the cross-tenant override sentinel as the literal string
#    '__super__' instead of ``app.db.rls.CROSS_TENANT_SENTINEL`` ('__all__').
#    Nothing in this codebase ever set '__super__' on the GUC, so a
#    cross-tenant/super-admin caller got RLS bypass on every other table but
#    NOT on node_events -- silently.
# 2. Unlike every other table this file exercises, the baseline migration's
#    ``m1_tables`` GRANT loop omitted ``node_events`` entirely --
#    "api-manager-rw" (the role app.api.nodes' POST /nodes/{id}/events
#    handler actually runs as in production) had no SELECT/INSERT grant on
#    it at all, so ``pg_db_scoped`` got "permission denied" before RLS was
#    even evaluated -- the sentinel fix above would have been moot in prod
#    without this, since the role couldn't reach the table regardless of
#    policy correctness.
#
# Both are now fixed in the baseline migration. These tests prove: the
# ordinary per-tenant isolation case (worked before, must keep working), the
# cross-tenant-bypass case (was broken, now fixed), and that the granted
# operations actually succeed as the real scoped role under a tenant GUC
# (the test that would have caught the missing-grant gap in the first
# place).
# =============================================================================


def _seed_node(owner_db: DB, *, name: str, tenant_id: str) -> int:
    """Insert a minimal ``nodes`` row as the table OWNER (bypasses RLS on
    insert). ``node_events.node_id`` is a NOT NULL FK to it. created_at/
    updated_at have no server-side DEFAULT (ORM-side Python default only,
    invisible to penguin-dal's reflected-table insert) -- supplied
    explicitly, same convention as every other direct-insert seed helper in
    this test suite."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return int(
        owner_db.nodes.insert(
            name=name,
            state="new",
            tenant_id=tenant_id,
            created_at=now,
            updated_at=now,
        )
    )


def _seed_node_event(db: DB, *, node_id: int, tenant_id: str, stage: str) -> int:
    """Insert a minimal ``node_events`` row via ``db`` -- either the table
    OWNER (``pg_db``, bypasses RLS) or the scoped role (``pg_db_scoped``,
    subject to RLS/grants -- see ``test_node_events_insert_and_select_
    succeed_as_scoped_role`` below). ``ts``/``created_at`` have no
    server-side DEFAULT either (same ORM-side-only gap as ``nodes``) --
    supplied explicitly."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return int(
        db.node_events.insert(
            node_id=node_id,
            tenant_id=tenant_id,
            ts=now,
            stage=stage,
            message=f"{stage} for {tenant_id}",
            created_at=now,
        )
    )


@pytest.fixture
def two_tenant_node_events(pg_db: DB) -> tuple[int, int]:
    node_a = _seed_node(pg_db, name="node-a", tenant_id=TENANT_A)
    node_b = _seed_node(pg_db, name="node-b", tenant_id=TENANT_B)
    id_a = _seed_node_event(pg_db, node_id=node_a, tenant_id=TENANT_A, stage="boot")
    id_b = _seed_node_event(pg_db, node_id=node_b, tenant_id=TENANT_B, stage="boot")
    return id_a, id_b


def test_node_events_tenant_a_sees_only_own_row(
    pg_db_scoped: DB, two_tenant_node_events: tuple[int, int]
) -> None:
    """Ordinary per-tenant isolation on node_events' bespoke policy -- this
    half already worked before the fix; must keep working."""
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_A)
    try:
        rows = pg_db_scoped(pg_db_scoped.node_events.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A}
    assert len(rows) == 1


def test_node_events_unset_tenant_is_fail_closed(
    pg_db_scoped: DB, two_tenant_node_events: tuple[int, int]
) -> None:
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(None)

    rows = pg_db_scoped(pg_db_scoped.node_events.id > 0).select()

    assert len(rows) == 0


def test_node_events_cross_tenant_sentinel_sees_all_rows(
    pg_db_scoped: DB, two_tenant_node_events: tuple[int, int]
) -> None:
    """Regression: gh-22. Pre-fix, the bespoke ``node_events_tenant_isolation``
    policy only recognized '__super__' (which nothing ever sets) for the
    cross-tenant override -- ``CROSS_TENANT_SENTINEL`` ('__all__') got NO
    bypass here even though it bypasses every other RLS-protected table.
    Post-fix, the policy matches '__all__' like the generic
    ``tenant_isolation`` policy every other table uses, so both tenants'
    rows become visible under the sentinel exactly as they do on
    ``biomes``/``webhook_endpoints`` above.
    """
    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(CROSS_TENANT_SENTINEL)
    try:
        rows = pg_db_scoped(pg_db_scoped.node_events.id > 0).select()
    finally:
        set_current_tenant(None)

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A, TENANT_B}
    assert len(rows) == 2


def test_node_events_owner_connection_is_rls_exempt(
    pg_db: DB, two_tenant_node_events: tuple[int, int]
) -> None:
    rows = pg_db(pg_db.node_events.id > 0).select()

    tenant_ids = {row.tenant_id for row in rows}
    assert tenant_ids == {TENANT_A, TENANT_B}


def test_node_events_insert_and_select_succeed_as_scoped_role(
    pg_db: DB, pg_db_scoped: DB
) -> None:
    """Regression: gh-22. The baseline migration's ``m1_tables`` GRANT loop
    omitted ``node_events`` entirely -- "api-manager-rw" (the role
    ``app.api.nodes``' ``POST /nodes/{id}/events`` handler actually runs as
    in production) had no SELECT/INSERT grant on it at all, so every write
    through that handler would have failed with "permission denied for
    table node_events" regardless of the RLS policy fix above.

    This is the test that would have caught that gap: it issues an INSERT
    (mirroring ``db.node_events.insert(**row_data)`` in
    ``app.api.nodes.post_node_event``) and a follow-up SELECT, both as the
    real scoped role (``pg_db_scoped``, never the table-owner ``pg_db``)
    under an ordinary per-tenant GUC -- not just proving the RLS policy is
    correct, but that the role can reach the table at all. SELECT is
    required in addition to INSERT here for the same reason it's required
    in production: penguin-dal's ``insert()`` uses SQLAlchemy's
    ``INSERT ... RETURNING``, and Postgres requires SELECT privilege on any
    column named in a RETURNING clause.
    """
    node_id = _seed_node(pg_db, name="node-scoped", tenant_id=TENANT_A)

    install_rls_events(pg_db_scoped.engine)
    set_current_tenant(TENANT_A)
    try:
        new_id = _seed_node_event(
            pg_db_scoped, node_id=node_id, tenant_id=TENANT_A, stage="boot"
        )
        rows = pg_db_scoped(pg_db_scoped.node_events.id == new_id).select()
    finally:
        set_current_tenant(None)

    assert len(rows) == 1
    assert rows[0].stage == "boot"
    assert rows[0].tenant_id == TENANT_A
