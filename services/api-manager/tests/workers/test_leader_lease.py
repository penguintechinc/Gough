"""Tests for the generic leader-lease primitive."""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock

import pytest

from app.workers import leader_lease as ll
from app.workers.leader_lease import (
    LeaderLeaseHandle,
    LeaseLostError,
    acquire,
    is_leader,
    release,
    renew,
    wait_for_leader,
)


class _LeaseRow:
    """In-memory row mimicking a SQLAlchemy Row with mapping access."""

    def __init__(self, **kwargs: Any) -> None:
        self.data = kwargs

    @property
    def _mapping(self) -> dict[str, Any]:
        return self.data

    def __getitem__(self, item: int) -> Any:
        order = ["lease_name", "holder_id", "acquired_at", "expires_at", "version"]
        return self.data[order[item]]


class FakeSession:
    """Minimal fake SQLAlchemy session that backs ``leader_leases`` with a dict.

    Implements just enough of the ``execute(text(...), params)`` protocol to
    satisfy the leader-lease primitive. Thread-safe via a coarse lock so the
    contention test below is meaningful.
    """

    def __init__(self, rows: Optional[dict[str, dict[str, Any]]] = None) -> None:
        self.rows = rows if rows is not None else {}
        self.lock = threading.Lock()

    def execute(self, statement: Any, params: Optional[dict[str, Any]] = None) -> Any:
        sql = str(statement).strip().lower()
        params = params or {}
        with self.lock:
            if sql.startswith("select lease_name"):
                row = self.rows.get(params["name"])
                if row is None:
                    return MagicMock(first=MagicMock(return_value=None))
                lease_row = _LeaseRow(**row)
                return MagicMock(first=MagicMock(return_value=lease_row))
            if sql.startswith("select holder_id"):
                row = self.rows.get(params["name"])
                if row is None:
                    return MagicMock(first=MagicMock(return_value=None))
                return MagicMock(
                    first=MagicMock(return_value=_LeaseRow(**row))
                )
            if sql.startswith("insert into leader_leases"):
                if params["name"] in self.rows:
                    raise RuntimeError("duplicate lease row (simulated IntegrityError)")
                self.rows[params["name"]] = {
                    "lease_name": params["name"],
                    "holder_id": params["holder"],
                    "acquired_at": params["acquired"],
                    "expires_at": params["expires"],
                    "version": 1,
                }
                result = MagicMock()
                result.rowcount = 1
                return result
            if sql.startswith("update leader_leases set holder_id = :holder"):
                # acquire CAS update
                row = self.rows.get(params["name"])
                if row is None or row["version"] != params["old_version"]:
                    result = MagicMock()
                    result.rowcount = 0
                    return result
                row["holder_id"] = params["holder"]
                row["acquired_at"] = params["acquired"]
                row["expires_at"] = params["expires"]
                row["version"] = params["new_version"]
                result = MagicMock()
                result.rowcount = 1
                return result
            if sql.startswith("update leader_leases set expires_at = :expires"):
                row = self.rows.get(params["name"])
                if (
                    row is None
                    or row["holder_id"] != params["holder"]
                    or row["version"] != params["old_version"]
                ):
                    result = MagicMock()
                    result.rowcount = 0
                    return result
                row["expires_at"] = params["expires"]
                row["version"] = params["new_version"]
                result = MagicMock()
                result.rowcount = 1
                return result
            if sql.startswith("update leader_leases set holder_id = null"):
                row = self.rows.get(params["name"])
                if (
                    row is None
                    or row["holder_id"] != params["holder"]
                    or row["version"] != params["old_version"]
                ):
                    result = MagicMock()
                    result.rowcount = 0
                    return result
                row["holder_id"] = None
                row["expires_at"] = params["now"]
                row["version"] = row["version"] + 1
                result = MagicMock()
                result.rowcount = 1
                return result
            raise AssertionError(f"unexpected SQL: {sql}")

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# acquire / renew / release / is_leader
# ---------------------------------------------------------------------------


def test_acquire_inserts_row_when_missing() -> None:
    session = FakeSession()
    handle = acquire(session, "audit_chain_writer", ttl_seconds=60, holder_id="A")
    assert handle is not None
    assert handle.holder_id == "A"
    assert handle.version == 1
    assert handle.expires_at > handle.acquired_at


def test_acquire_rejects_when_other_holder_active() -> None:
    session = FakeSession()
    a = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert a is not None
    b = acquire(session, "lease", ttl_seconds=60, holder_id="B")
    assert b is None, "B must not steal an active lease from A"


def test_acquire_takes_over_after_expiry() -> None:
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    session = FakeSession(rows={
        "lease": {
            "lease_name": "lease",
            "holder_id": "A",
            "acquired_at": past,
            "expires_at": past,
            "version": 7,
        }
    })
    handle = acquire(session, "lease", ttl_seconds=60, holder_id="B")
    assert handle is not None
    assert handle.holder_id == "B"
    assert handle.version == 8


def test_acquire_returns_handle_for_self() -> None:
    session = FakeSession()
    a1 = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    a2 = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert a1 is not None and a2 is not None
    assert a2.version > a1.version


def test_renew_extends_expiry() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    h2 = renew(session, h)
    assert h2.version == h.version + 1
    assert h2.expires_at >= h.expires_at


def test_renew_raises_when_lease_lost() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    # Simulate B stealing it after expiry by mutating state.
    session.rows["lease"]["holder_id"] = "B"
    session.rows["lease"]["version"] = h.version + 5
    with pytest.raises(LeaseLostError):
        renew(session, h)


def test_release_clears_holder_and_returns_true() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    ok = release(session, h)
    assert ok is True
    assert session.rows["lease"]["holder_id"] is None


def test_release_returns_false_if_not_held() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    # Steal it.
    session.rows["lease"]["holder_id"] = "B"
    session.rows["lease"]["version"] = h.version + 1
    assert release(session, h) is False


def test_is_leader_true_for_active_handle() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    assert is_leader(session, h) is True


def test_is_leader_false_after_release() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    release(session, h)
    assert is_leader(session, h) is False


def test_is_leader_false_when_expired() -> None:
    session = FakeSession()
    h = acquire(session, "lease", ttl_seconds=60, holder_id="A")
    assert h is not None
    session.rows["lease"]["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert is_leader(session, h) is False


def test_acquire_invalid_ttl_rejected() -> None:
    with pytest.raises(ValueError):
        acquire(FakeSession(), "lease", ttl_seconds=0, holder_id="A")


def test_default_holder_id_includes_pid() -> None:
    holder = ll._default_holder_id()
    assert "/" in holder
    assert str(__import__("os").getpid()) in holder


def test_two_concurrent_acquirers_only_one_succeeds() -> None:
    """Threaded contention: only one of N callers gets the lease."""

    session = FakeSession()
    results: list[Optional[LeaderLeaseHandle]] = []
    barrier = threading.Barrier(8)

    def worker(name: str) -> None:
        barrier.wait()
        h = acquire(session, "race", ttl_seconds=60, holder_id=name)
        results.append(h)

    threads = [threading.Thread(target=worker, args=(f"replica-{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r is not None]
    assert len(successes) == 1, f"expected one winner, got {len(successes)}"


def test_wait_for_leader_returns_when_acquired() -> None:
    session = FakeSession()

    def factory() -> FakeSession:
        return session

    handle = wait_for_leader(
        factory,
        "lease",
        ttl_seconds=60,
        poll_interval_seconds=0.01,
        holder_id="A",
        max_attempts=3,
    )
    assert handle is not None
    assert handle.holder_id == "A"


def test_wait_for_leader_raises_after_max_attempts() -> None:
    session = FakeSession(rows={
        "lease": {
            "lease_name": "lease",
            "holder_id": "B",
            "acquired_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "version": 99,
        }
    })

    def factory() -> FakeSession:
        return session

    with pytest.raises(ll.LeaderLeaseError):
        wait_for_leader(
            factory,
            "lease",
            ttl_seconds=60,
            poll_interval_seconds=0.001,
            holder_id="A",
            max_attempts=2,
        )


def test_row_to_dict_handles_tuple_fallback() -> None:
    tup = ("name", "holder", None, None, 1)
    d = ll._row_to_dict(tup)
    assert d["lease_name"] == "name"
    assert d["holder_id"] == "holder"


def test_row_to_dict_returns_empty_for_none() -> None:
    assert ll._row_to_dict(None) == {}
