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
