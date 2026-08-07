"""SMART Sweeper Worker.

Periodically polls every ``ready`` node for SMART data via the gRPC control
tunnel, parses ``smartctl --json`` output, persists raw + parsed attributes on
the disk row, and emits ``gough.smart.warning`` events on transition into a
warning state.

Per spec ``SMART & Hardware Inventory``:

- Helper image bundles ``smartmontools`` (``smartctl -H -A -x``).
- Passive only — no short/long self-tests during sweeps.
- Warning conditions:
    * SMART overall-health != PASSED
    * Reallocated_Sector_Ct > 0
    * Temperature_Celsius > 50
    * Pending_Sector_Ct > 0
    * Power_On_Hours > 45000
    * NVMe critical_warning != 0

The sweeper is a *leader-only* worker — only one replica runs at a time, gated
by the ``smart_sweeper`` row in ``leader_leases``. Non-leader replicas idle.

Scheduled by ``supercronic`` at the cluster's configured interval (default 15
minutes); ``run_forever`` is also available for environments running the
sweeper as a long-lived sidecar.

**No Quart app context required.** Regression: gh-22 (DB pool
consolidation). ``run_once()``/``run_forever()`` call
``app.db.database.get_db()`` -- the RLS-wired, app-context-free accessor
(see that module's docstring) -- rather than the app-context-bound
``app.models.get_db()`` this worker used to depend on. This worker runs
OUTSIDE Quart's request pipeline entirely (leader-only,
supercronic-scheduled or long-lived-sidecar, never an HTTP handler), so
there is no request/app context to push in the first place; the previous
``_require_app_context()`` guard existed only because the old accessor
needed one, and has been removed along with the dependency that required it.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from prometheus_client import Counter, Gauge

from ..db.database import get_db
from ..db.rls import CROSS_TENANT_SENTINEL, get_current_tenant, set_current_tenant
from . import leader_lease as _leader_lease

logger = logging.getLogger(__name__)


@contextmanager
def _cross_tenant_scope() -> Iterator[None]:
    """Push the RLS cross-tenant sentinel for one sweep's DB work.

    ``nodes``/``disks`` are RLS-protected (baseline migration ``rls_tables``
    -- see ``alembic/versions/20260805_1000_baseline_full_schema.py``), and
    the sweeper is a leader-only background worker that never runs inside
    Quart's HTTP request pipeline -- ``app.db.rls``'s tenant ContextVar is
    never set by anything upstream. The sweep is intentionally cluster-wide
    (every ``ready`` node across every tenant, per the module docstring), so
    this pushes the sentinel for the duration of ``_sweep()`` -- mirrors
    ``app.workers.audit_chain_writer._cross_tenant_scope()`` /
    ``app.grpc_server._cross_tenant_scope()`` (duplicated locally rather than
    imported, matching this codebase's existing per-module convention).
    Omitting this would silently fail-closed to zero visible nodes/disks --
    ``get_db()`` here resolves to ``app.db.database``'s RLS-wired,
    app-context-free engine (wired via ``install_rls_events`` inside that
    module's own ``init_db()`` -- see gh-22) -- not raise, just sweep
    nothing, ever.
    """
    previous = get_current_tenant()
    set_current_tenant(CROSS_TENANT_SENTINEL)
    try:
        yield
    finally:
        set_current_tenant(previous)


# =============================================================================
# Prometheus metrics
# =============================================================================


STORAGE_CAPACITY_USED = Gauge(
    "gough_storage_capacity_used_bytes",
    "Bytes of disk capacity claimed by storage backends or planned partitions.",
    labelnames=("tenant_id", "storage_backend", "tier"),
)

SMART_WARNINGS_EMITTED = Counter(
    "gough_smart_warnings_emitted_total",
    "Number of gough.smart.warning events emitted by the sweeper.",
    labelnames=("reason",),
)

DISKS_PROBED = Counter(
    "gough_smart_disks_probed_total",
    "Number of disks probed by the SMART sweeper.",
    labelnames=("status",),
)


# =============================================================================
# Warning detection
# =============================================================================


_HOURS_THRESHOLD = 45000
_TEMP_THRESHOLD = 50


def _attr_int(attrs: list[dict[str, Any]], name: str) -> Optional[int]:
    for a in attrs or []:
        if (a.get("name") or "").lower() == name.lower():
            raw = a.get("raw") or {}
            v = raw.get("value")
            if isinstance(v, (int, float)):
                return int(v)
    return None


def detect_warnings(smart: dict[str, Any]) -> list[str]:
    """Return the list of warning reasons present in a parsed SMART blob.

    The ``smart`` dict mirrors ``smartctl --json``'s schema:

    .. code-block:: json

        {
          "smart_status": {"passed": true},
          "ata_smart_attributes": {"table": [{"name": "Reallocated_Sector_Ct", "raw": {"value": 0}}, ...]},
          "nvme_smart_health_information_log": {"critical_warning": 0, "temperature": 30, "power_on_hours": 1000}
        }
    """
    reasons: list[str] = []

    overall = (smart.get("smart_status") or {}).get("passed")
    if overall is False:
        reasons.append("smart_overall_health_failed")

    attrs = (smart.get("ata_smart_attributes") or {}).get("table") or []
    realloc = _attr_int(attrs, "Reallocated_Sector_Ct")
    pending = _attr_int(attrs, "Current_Pending_Sector") or _attr_int(
        attrs, "Pending_Sector_Ct"
    )
    temp = _attr_int(attrs, "Temperature_Celsius")
    poh = _attr_int(attrs, "Power_On_Hours")

    nvme_log = smart.get("nvme_smart_health_information_log") or {}
    nvme_crit = nvme_log.get("critical_warning")
    nvme_temp = nvme_log.get("temperature")
    nvme_poh = nvme_log.get("power_on_hours")

    if realloc is not None and realloc > 0:
        reasons.append("reallocated_sector_ct_gt_0")
    if pending is not None and pending > 0:
        reasons.append("pending_sector_ct_gt_0")

    effective_temp = nvme_temp if nvme_temp is not None else temp
    if effective_temp is not None and effective_temp > _TEMP_THRESHOLD:
        reasons.append("temperature_celsius_over_50")

    effective_poh = nvme_poh if nvme_poh is not None else poh
    if effective_poh is not None and effective_poh > _HOURS_THRESHOLD:
        reasons.append("power_on_hours_over_45000")

    if isinstance(nvme_crit, int) and nvme_crit != 0:
        reasons.append("nvme_critical_warning_nonzero")

    return reasons


def derive_status(reasons: list[str], smart: dict[str, Any]) -> str:
    """Map a warning-reasons list + raw blob to the disks.smart_status enum."""
    overall = (smart.get("smart_status") or {}).get("passed")
    if overall is False or "smart_overall_health_failed" in reasons:
        return "failed"
    if reasons:
        return "warning"
    if overall is True:
        return "passed"
    return "unknown"


# =============================================================================
# Default smartctl runner — overridable for tests / different transports
# =============================================================================


def _default_smartctl_runner(node: Any) -> dict[str, Any]:
    """Stub gRPC-tunnel runner.

    The real implementation will dispatch to ``GoughAgent.SmartProbe`` over the
    mTLS gRPC tunnel established at node-deploy time. For M1 sprint 3 we expose
    it as an injectable callable so tests can drive it deterministically.
    """
    raise NotImplementedError(
        "default smartctl runner is not yet wired to the gRPC control tunnel"
    )


# =============================================================================
# Sweeper
# =============================================================================


@dataclass(slots=True)
class SweepResult:
    """Outcome of a single ``run_once`` invocation."""

    nodes_visited: int = 0
    disks_probed: int = 0
    warnings_emitted: int = 0
    transitions: list[tuple[int, str, str]] = field(default_factory=list)
    leader: bool = False


class SMARTSweeper:
    """SMART sweeper — leader-only background worker.

    Parameters
    ----------
    smartctl_runner:
        Callable ``(node_row) -> {device_path: smart_json}`` used to invoke
        ``smartctl`` on the node side. Tests override this.
    publisher:
        Callable ``(subject, payload_dict) -> None`` used to fan out
        ``gough.smart.warning`` events. Defaults to ``app.nats_client`` from a
        Quart context, falling back to a logger.info stub when absent.
    leader_lease_module:
        Indirection seam for tests; defaults to :mod:`.leader_lease`.
    holder_id:
        Optional explicit lease holder id (defaults to a per-process unique id).
    """

    LEASE_NAME = "smart_sweeper"

    def __init__(
        self,
        smartctl_runner: Optional[Callable[[Any], dict[str, dict[str, Any]]]] = None,
        publisher: Optional[Callable[[str, dict[str, Any]], None]] = None,
        leader_lease_module: Any = None,
        holder_id: Optional[str] = None,
    ) -> None:
        self._runner = smartctl_runner or _default_smartctl_runner
        self._publisher = publisher
        self._lease_mod = leader_lease_module or _leader_lease
        self._holder_id = holder_id

    # ---- public entrypoints ------------------------------------------------

    def run_once(self, ttl: int = 900) -> SweepResult:
        """Acquire the lease (best-effort), sweep all ``ready`` nodes, return
        a :class:`SweepResult`.

        If the lease is held by another replica, returns a result with
        ``leader=False`` and zero counters — caller is expected to back off and
        retry on the next supercron tick.
        """
        result = SweepResult()
        db = get_db()

        # leader_lease.acquire()/release() take a penguin-dal DB directly
        # (each of its statements is its own autocommitted db.executesql()
        # call -- see that module's docstring) -- no raw engine.connect()
        # or manual commit() needed.
        handle = self._lease_mod.acquire(
            db, self.LEASE_NAME, ttl_seconds=ttl, holder_id=self._holder_id
        )
        if handle is None:
            logger.debug("smart_sweeper: lease not held — skipping sweep")
            return result

        result.leader = True
        try:
            with _cross_tenant_scope():
                self._sweep(db, result)
        finally:
            try:
                self._lease_mod.release(db, handle)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("smart_sweeper: failed to release lease: %s", exc)
        return result

    def run_forever(self, interval_seconds: int = 900) -> None:
        """Long-lived sweep loop. Sleeps ``interval_seconds`` between ticks
        regardless of leader status — non-leaders idle-poll cheaply.
        """
        logger.info(
            "smart_sweeper: starting run_forever interval=%ss", interval_seconds
        )
        while True:
            try:
                self.run_once(ttl=interval_seconds)
            except Exception as exc:  # pragma: no cover - log-and-continue
                logger.exception("smart_sweeper: sweep tick failed: %s", exc)
            time.sleep(interval_seconds)

    # ---- internal helpers --------------------------------------------------

    def _sweep(self, db: Any, result: SweepResult) -> None:
        nodes = db(db.nodes.state == "ready").select()
        for node in nodes:
            result.nodes_visited += 1
            try:
                probe = self._runner(node) or {}
            except Exception as exc:
                logger.warning(
                    "smart_sweeper: smartctl probe failed for node=%s: %s",
                    getattr(node, "id", "?"),
                    exc,
                )
                DISKS_PROBED.labels(status="error").inc()
                continue

            for device_path, smart_blob in probe.items():
                row = db(
                    (db.disks.node_id == node.id)
                    & (db.disks.device_path == device_path)
                ).select().first()
                if row is None:
                    logger.debug(
                        "smart_sweeper: unknown disk %s on node %s", device_path, node.id
                    )
                    continue
                self._update_disk(db, row, smart_blob, result)
                result.disks_probed += 1
                DISKS_PROBED.labels(status="ok").inc()

        self._refresh_capacity_metrics(db)

    def _update_disk(
        self, db: Any, row: Any, smart: dict[str, Any], result: SweepResult
    ) -> None:
        prior = row.smart_status or "unknown"
        reasons = detect_warnings(smart)
        new_status = derive_status(reasons, smart)

        db(db.disks.id == row.id).update(
            smart_status=new_status,
            smart_attributes_json=smart,
            updated_at=datetime.now(timezone.utc),
        )
        db.commit()

        if new_status != prior:
            result.transitions.append((int(row.id), prior, new_status))

        # Emit a warning event on transition into a non-passed state.
        if new_status in {"warning", "failed"} and prior not in {"warning", "failed"}:
            payload = {
                "node_id": int(row.node_id),
                "disk_id": int(row.id),
                "device_path": row.device_path,
                "smart_status": new_status,
                "reasons": reasons,
                "emitted_at": datetime.now(timezone.utc).isoformat(),
            }
            self._emit_warning(payload)
            result.warnings_emitted += 1
            for reason in reasons or ["unspecified"]:
                SMART_WARNINGS_EMITTED.labels(reason=reason).inc()

    def _emit_warning(self, payload: dict[str, Any]) -> None:
        publisher = self._publisher or _resolve_publisher()
        try:
            publisher("gough.smart.warning", payload)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("smart_sweeper: warning publish failed: %s", exc)

    def _refresh_capacity_metrics(self, db: Any) -> None:
        """Recompute ``gough_storage_capacity_used_bytes`` from disk_plans."""
        STORAGE_CAPACITY_USED._metrics.clear()  # reset stale label series
        rows = db(db.disks.reserved_for_storage == True).select(
            db.disks.tenant_id,
            db.disks.storage_backend,
            db.disks.tier,
            db.disks.capacity_bytes,
            db.disks.reserved_for_storage,
        )
        sums: dict[tuple[str, str, str], int] = {}
        for r in rows:
            if not r.reserved_for_storage:
                continue
            key = (
                r.tenant_id or "__default__",
                r.storage_backend or "unassigned",
                r.tier or "bulk",
            )
            sums[key] = sums.get(key, 0) + int(r.capacity_bytes or 0)
        for (tenant_id, backend, tier), used in sums.items():
            STORAGE_CAPACITY_USED.labels(
                tenant_id=tenant_id, storage_backend=backend, tier=tier
            ).set(used)


def _resolve_publisher() -> Callable[[str, dict[str, Any]], None]:
    """Default publisher: NATS if a client is attached to the Quart app,
    otherwise a structured ``logger.info`` so the event is at least visible.
    """
    try:
        from quart import current_app
        from unittest.mock import MagicMock

        nats = getattr(current_app, "nats_client", None)
        if (
            nats is not None
            and not isinstance(nats, MagicMock)
            and hasattr(nats, "publish")
            and callable(nats.publish)
        ):

            def _publish(subject: str, payload: dict[str, Any]) -> None:
                nats.publish(subject, json.dumps(payload).encode("utf-8"))

            return _publish
    except (RuntimeError, ModuleNotFoundError):
        # No app context or quart not available — fall through to logger.
        pass

    def _log_publish(subject: str, payload: dict[str, Any]) -> None:
        logger.info("smart_sweeper: %s %s", subject, json.dumps(payload))

    return _log_publish


__all__ = [
    "SMARTSweeper",
    "SweepResult",
    "STORAGE_CAPACITY_USED",
    "SMART_WARNINGS_EMITTED",
    "DISKS_PROBED",
    "detect_warnings",
    "derive_status",
]
