"""Tests for ``app.workers.smart_sweeper``.

Coverage targets ≥90%: warning detection across SATA/NVMe fixtures, status
derivation, leader-lease respect, NATS publish on transitions, capacity-metric
refresh, and run_once behaviour with both leader / non-leader outcomes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.workers import smart_sweeper as sw


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


HEALTHY_SATA = {
    "smart_status": {"passed": True},
    "ata_smart_attributes": {
        "table": [
            {"name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
            {"name": "Current_Pending_Sector", "raw": {"value": 0}},
            {"name": "Temperature_Celsius", "raw": {"value": 32}},
            {"name": "Power_On_Hours", "raw": {"value": 1000}},
        ]
    },
}

HOT_SATA = {
    "smart_status": {"passed": True},
    "ata_smart_attributes": {
        "table": [
            {"name": "Temperature_Celsius", "raw": {"value": 65}},
        ]
    },
}

REALLOC_SATA = {
    "smart_status": {"passed": True},
    "ata_smart_attributes": {
        "table": [
            {"name": "Reallocated_Sector_Ct", "raw": {"value": 4}},
            {"name": "Pending_Sector_Ct", "raw": {"value": 2}},
        ]
    },
}

OLD_SATA = {
    "smart_status": {"passed": True},
    "ata_smart_attributes": {
        "table": [
            {"name": "Power_On_Hours", "raw": {"value": 50000}},
        ]
    },
}

FAILED_SATA = {
    "smart_status": {"passed": False},
    "ata_smart_attributes": {"table": []},
}

NVME_CRITICAL = {
    "smart_status": {"passed": True},
    "nvme_smart_health_information_log": {
        "critical_warning": 4,
        "temperature": 35,
        "power_on_hours": 100,
    },
}

NVME_HOT = {
    "smart_status": {"passed": True},
    "nvme_smart_health_information_log": {
        "critical_warning": 0,
        "temperature": 70,
        "power_on_hours": 100,
    },
}

UNKNOWN = {"smart_status": {}}


# ---------------------------------------------------------------------------
# detect_warnings + derive_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "blob,expected_reason",
    [
        (HOT_SATA, "temperature_celsius_over_50"),
        (REALLOC_SATA, "reallocated_sector_ct_gt_0"),
        (REALLOC_SATA, "pending_sector_ct_gt_0"),
        (OLD_SATA, "power_on_hours_over_45000"),
        (FAILED_SATA, "smart_overall_health_failed"),
        (NVME_CRITICAL, "nvme_critical_warning_nonzero"),
        (NVME_HOT, "temperature_celsius_over_50"),
    ],
)
def test_detect_warnings_flags(blob, expected_reason):
    reasons = sw.detect_warnings(blob)
    assert expected_reason in reasons


def test_detect_warnings_healthy_returns_empty():
    assert sw.detect_warnings(HEALTHY_SATA) == []


def test_derive_status_failed_when_overall_false():
    assert sw.derive_status(["smart_overall_health_failed"], FAILED_SATA) == "failed"


def test_derive_status_warning_when_reasons_present():
    assert sw.derive_status(["temperature_celsius_over_50"], HOT_SATA) == "warning"


def test_derive_status_passed_when_clean():
    assert sw.derive_status([], HEALTHY_SATA) == "passed"


def test_derive_status_unknown_when_empty():
    assert sw.derive_status([], UNKNOWN) == "unknown"


# ---------------------------------------------------------------------------
# Leader lease behaviour
# ---------------------------------------------------------------------------


class _FakeLease:
    """Records acquire/release to verify the sweeper honours leader status."""

    def __init__(self, will_grant: bool = True) -> None:
        self.will_grant = will_grant
        self.acquired = 0
        self.released = 0

    def acquire(self, conn, name, ttl_seconds, holder_id=None):
        self.acquired += 1
        if not self.will_grant:
            return None
        return SimpleNamespace(
            lease_name=name, holder_id=holder_id or "test", ttl_seconds=ttl_seconds,
            acquired_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc), version=1, extra={},
        )

    def release(self, conn, handle):
        self.released += 1
        return True


# ---------------------------------------------------------------------------
# Sweep semantics
# ---------------------------------------------------------------------------


@pytest.fixture()
def ready_node(dal):
    """Insert a ready node + two disks."""
    now = datetime.now(timezone.utc)
    node_id = dal.nodes.insert(
        tenant_id="acme", name="n1", state="ready",
        dmi_uuid="0", primary_nic_mac="00:00:00:00:00:01",
    )
    sda = dal.disks.insert(
        node_id=node_id, tenant_id="acme", device_path="/dev/sda",
        capacity_bytes=512_000_000_000, rotational=False, smart_status="passed",
        reserved_for_storage=True, storage_backend="nest", tier="fast",
        created_at=now, updated_at=now,
    )
    sdb = dal.disks.insert(
        node_id=node_id, tenant_id="acme", device_path="/dev/sdb",
        capacity_bytes=2_000_000_000_000, rotational=True, smart_status="passed",
        reserved_for_storage=True, storage_backend="nest", tier="bulk",
        created_at=now, updated_at=now,
    )
    # A "new" node should be ignored.
    dal.nodes.insert(
        tenant_id="acme", name="n2", state="new",
        dmi_uuid="x", primary_nic_mac="00:00:00:00:00:02",
    )
    dal.commit()
    return SimpleNamespace(node_id=int(node_id), sda=int(sda), sdb=int(sdb))


def test_sweep_skips_when_not_leader(dal, ready_node):
    lease = _FakeLease(will_grant=False)
    publishes: list = []
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sda": HEALTHY_SATA},
        publisher=lambda subj, payload: publishes.append((subj, payload)),
        leader_lease_module=lease,
        holder_id="test-holder",
    )
    res = sweeper.run_once(ttl=60)
    assert res.leader is False
    assert res.disks_probed == 0
    assert lease.acquired == 1
    assert lease.released == 0
    assert publishes == []


def test_sweep_only_visits_ready_nodes(dal, ready_node):
    lease = _FakeLease(will_grant=True)
    visits: list = []

    def runner(node):
        visits.append(node.id)
        return {"/dev/sda": HEALTHY_SATA, "/dev/sdb": HEALTHY_SATA}

    sweeper = sw.SMARTSweeper(
        smartctl_runner=runner,
        publisher=lambda *_: None,
        leader_lease_module=lease,
        holder_id="t",
    )
    res = sweeper.run_once(ttl=60)
    assert res.leader is True
    assert visits == [ready_node.node_id]
    assert res.nodes_visited == 1
    assert res.disks_probed == 2
    assert lease.released == 1


def test_sweep_emits_warning_on_transition(dal, ready_node):
    lease = _FakeLease(will_grant=True)
    publishes: list = []

    def runner(node):
        return {"/dev/sda": HOT_SATA, "/dev/sdb": HEALTHY_SATA}

    sweeper = sw.SMARTSweeper(
        smartctl_runner=runner,
        publisher=lambda subj, payload: publishes.append((subj, payload)),
        leader_lease_module=lease,
        holder_id="t",
    )
    res = sweeper.run_once(ttl=60)
    assert res.warnings_emitted == 1
    assert publishes
    subj, payload = publishes[0]
    assert subj == "gough.smart.warning"
    assert payload["device_path"] == "/dev/sda"
    assert "temperature_celsius_over_50" in payload["reasons"]
    # disk row updated
    sda = dal(dal.disks.id == ready_node.sda).select().first()
    assert sda.smart_status == "warning"


def test_sweep_does_not_re_emit_when_already_warning(dal, ready_node):
    """Second sweep with same warning should not re-publish (transition only)."""
    lease = _FakeLease(will_grant=True)
    publishes: list = []
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sda": HOT_SATA, "/dev/sdb": HEALTHY_SATA},
        publisher=lambda s, p: publishes.append((s, p)),
        leader_lease_module=lease,
        holder_id="t",
    )
    sweeper.run_once(ttl=60)
    # Reset publish count, run again with same input
    publishes.clear()
    sweeper.run_once(ttl=60)
    assert publishes == []


def test_sweep_handles_runner_exception(dal, ready_node):
    lease = _FakeLease(will_grant=True)

    def boom(node):
        raise RuntimeError("tunnel down")

    sweeper = sw.SMARTSweeper(
        smartctl_runner=boom,
        publisher=lambda *_: None,
        leader_lease_module=lease,
        holder_id="t",
    )
    res = sweeper.run_once(ttl=60)
    assert res.leader is True
    assert res.disks_probed == 0


def test_sweep_skips_unknown_device_paths(dal, ready_node):
    lease = _FakeLease(will_grant=True)
    publishes: list = []

    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sdz": HOT_SATA},  # not in DB
        publisher=lambda s, p: publishes.append((s, p)),
        leader_lease_module=lease,
        holder_id="t",
    )
    res = sweeper.run_once(ttl=60)
    assert res.disks_probed == 0
    assert publishes == []


def test_sweep_updates_capacity_metric(dal, ready_node):
    lease = _FakeLease(will_grant=True)
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda n: {"/dev/sda": HEALTHY_SATA, "/dev/sdb": HEALTHY_SATA},
        publisher=lambda *_: None,
        leader_lease_module=lease,
        holder_id="t",
    )
    sweeper.run_once(ttl=60)
    # Both disks reserved_for_storage=True; backend=nest; sum = 2.5 TB
    metric = sw.STORAGE_CAPACITY_USED.labels(
        tenant_id="acme", storage_backend="nest", tier="fast"
    )
    assert metric._value.get() == 512_000_000_000
    bulk = sw.STORAGE_CAPACITY_USED.labels(
        tenant_id="acme", storage_backend="nest", tier="bulk"
    )
    assert bulk._value.get() == 2_000_000_000_000


def test_default_publisher_uses_logger_when_no_app(monkeypatch, caplog):
    """Resolving the publisher outside any Quart context falls back to logging."""
    publisher = sw._resolve_publisher()
    with caplog.at_level("INFO"):
        publisher("gough.smart.warning", {"node_id": 1})
    assert any("gough.smart.warning" in r.getMessage() for r in caplog.records)


def test_default_smartctl_runner_raises():
    with pytest.raises(NotImplementedError):
        sw._default_smartctl_runner(SimpleNamespace(id=1))


def test_failed_smart_emits_warning_with_failed_status(dal, ready_node):
    lease = _FakeLease(will_grant=True)
    publishes: list = []
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda n: {"/dev/sda": FAILED_SATA, "/dev/sdb": HEALTHY_SATA},
        publisher=lambda s, p: publishes.append((s, p)),
        leader_lease_module=lease,
        holder_id="t",
    )
    sweeper.run_once(ttl=60)
    assert publishes[0][1]["smart_status"] == "failed"
    sda = dal(dal.disks.id == ready_node.sda).select().first()
    assert sda.smart_status == "failed"


# ---------------------------------------------------------------------------
# Real Postgres: leader_lease cascade (Task 8b) + RLS cross-tenant sentinel
# ---------------------------------------------------------------------------
#
# The tests above exercise `_sweep`/`_update_disk`/etc. against the sqlite
# `dal` fixture with `_FakeLease` standing in for `leader_lease` -- they
# never call the real `app.workers.leader_lease.acquire()/release()`, so
# they can't prove the Task 8a cascade fix (leader_lease.acquire() now takes
# a penguin-dal DB, not the raw SQLAlchemy Connection `run_once()` used to
# pass it). These use the REAL `leader_lease` module against real Postgres
# (`pg_db`/`pg_db_scoped`) instead.


def _seed_pg_ready_node_and_disk(db, tenant_id: str = "acme", node_name: str = "pg-node-1"):
    """Insert a real ``ready`` node + one disk via penguin-dal; return their ids.

    ``created_at``/``updated_at`` have no server-side DEFAULT
    (``app.models_m1``'s columns set them via SQLAlchemy ORM-side
    ``default=``, which only applies on ORM/Core inserts) -- supplied
    explicitly here, same pattern as every other direct-insert seed helper
    in this suite (see e.g. ``app.api.webhooks.create_webhook``).
    """
    now = datetime.now(timezone.utc)
    node_id = db.nodes.insert(
        tenant_id=tenant_id, name=node_name, state="ready",
        dmi_uuid=f"dmi-{node_name}", primary_nic_mac="aa:bb:cc:dd:ee:01",
        created_at=now, updated_at=now,
    )
    disk_id = db.disks.insert(
        node_id=node_id, tenant_id=tenant_id, device_path="/dev/sda",
        capacity_bytes=512_000_000_000, rotational=False, smart_status="unknown",
        reserved_for_storage=True, storage_backend="nest", tier="fast",
        created_at=now, updated_at=now,
    )
    db.commit()
    return int(node_id), int(disk_id)


def test_run_once_real_leader_lease_module_accepts_penguin_dal_db(pg_db, monkeypatch):
    """Regression test for the Task 8a cascade: ``leader_lease.acquire()``/
    ``release()`` take a penguin-dal ``DB`` (each statement its own
    autocommitted ``executesql()`` call -- see that module's docstring), not
    a raw SQLAlchemy ``Connection`` (which has no ``.executesql()``).
    Exercises ``run_once()`` end-to-end against real Postgres using the REAL
    ``app.workers.leader_lease`` module (no ``_FakeLease`` stub).
    """
    import app.workers.smart_sweeper as sweeper_mod

    monkeypatch.setattr(sweeper_mod, "get_db", lambda: pg_db)
    node_id, disk_id = _seed_pg_ready_node_and_disk(pg_db)

    publishes: list = []
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sda": HEALTHY_SATA},
        publisher=lambda subj, payload: publishes.append((subj, payload)),
        holder_id="pg-test-holder",
    )
    res = sweeper.run_once(ttl=60)

    assert res.leader is True
    assert res.nodes_visited == 1
    assert res.disks_probed == 1

    disk = pg_db(pg_db.disks.id == disk_id).select().first()
    assert disk.smart_status == "passed"

    lease_rows = pg_db.executesql(
        "SELECT holder_id FROM leader_leases WHERE lease_name = %(name)s",
        {"name": "smart_sweeper"},
    )
    assert lease_rows == [(None,)], "release() must clear the holder after a successful sweep"


def test_run_once_second_sweep_reacquires_released_lease(pg_db, monkeypatch):
    """A released lease can be re-acquired on the next tick -- proves
    ``release()`` actually persisted the clear (not just returned truthy)
    when called with the new penguin-dal ``DB`` argument.
    """
    import app.workers.smart_sweeper as sweeper_mod

    monkeypatch.setattr(sweeper_mod, "get_db", lambda: pg_db)
    _seed_pg_ready_node_and_disk(pg_db)

    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sda": HEALTHY_SATA},
        publisher=lambda *_: None,
        holder_id="pg-test-holder",
    )
    first = sweeper.run_once(ttl=60)
    second = sweeper.run_once(ttl=60)
    assert first.leader is True
    assert second.leader is True


def test_run_once_cross_tenant_sentinel_lets_scoped_role_sweep_other_tenant(
    pg_db, pg_db_scoped, monkeypatch
):
    """``nodes``/``disks`` are RLS-protected (baseline ``rls_tables``).
    Proves the cross-tenant sentinel wrap added to ``run_once()`` lets the
    scoped, non-owner ``api-manager-rw`` role (which actually has RLS
    enforced, unlike ``pg_db``'s table-owner connection) still sweep every
    tenant's ready nodes -- instead of silently sweeping zero nodes forever
    now that ``get_db()`` resolves to the RLS-wired engine.
    """
    from app.db.rls import install_rls_events, set_current_tenant
    import app.workers.smart_sweeper as sweeper_mod

    install_rls_events(pg_db_scoped.engine)
    node_id, disk_id = _seed_pg_ready_node_and_disk(pg_db, tenant_id="tenant-a")

    monkeypatch.setattr(sweeper_mod, "get_db", lambda: pg_db_scoped)
    sweeper = sw.SMARTSweeper(
        smartctl_runner=lambda node: {"/dev/sda": HEALTHY_SATA},
        publisher=lambda *_: None,
        holder_id="pg-scoped-holder",
    )
    try:
        res = sweeper.run_once(ttl=60)
    finally:
        set_current_tenant(None)

    assert res.leader is True
    assert res.nodes_visited == 1, "sentinel must let the scoped role see the other tenant's node"
    assert res.disks_probed == 1

    disk = pg_db(pg_db.disks.id == disk_id).select().first()
    assert disk.smart_status == "passed"


def test_scoped_role_without_sentinel_sees_zero_ready_nodes(pg_db, pg_db_scoped):
    """Negative control: proves the failure mode the sentinel wrap in
    ``run_once()`` prevents -- an unset tenant GUC on the scoped role sees
    none of another tenant's ``ready`` nodes.
    """
    from app.db.rls import install_rls_events, set_current_tenant

    install_rls_events(pg_db_scoped.engine)
    _seed_pg_ready_node_and_disk(pg_db, tenant_id="tenant-a")

    set_current_tenant(None)
    rows = pg_db_scoped.executesql(
        "SELECT COUNT(*) FROM nodes WHERE state = %(state)s", {"state": "ready"}
    )
    assert rows[0][0] == 0, "unset tenant GUC must fail closed on RLS-protected nodes"
