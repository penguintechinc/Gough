"""Migration safety-envelope evaluator (pure functions).

Per spec "Capacity Prediction & Live Migration → Migration Safety Envelope":
every candidate migration goes through the same envelope check before any
``lxc move --live`` is issued. This module hosts the pure-function evaluator
so it can be unit-tested in isolation and reused by the API blueprint, the
auto-migration worker (M2), and the evacuate-node endpoint.

The evaluator never silently skips a rejection; every rejection is reported
in ``SafetyResult.violations`` with a structured reason and offending node id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


# =============================================================================
# Data structures
# =============================================================================


@dataclass(slots=True, frozen=True)
class NodeSnapshot:
    """Snapshot of a node's current capacity & forecast at safety-check time."""

    node_id: int
    state: str  # "ready" | "draining" | "failed" | "maintenance" | ...
    cpu_free_pct: float
    mem_free_pct: float
    disk_free_pct: float
    forecast_cpu_free_pct: float
    forecast_mem_free_pct: float
    forecast_disk_free_pct: float
    hardware_tags: frozenset[str] = field(default_factory=frozenset)
    composite_load_score: float = 0.0


@dataclass(slots=True, frozen=True)
class BiomeSnapshot:
    """Snapshot of the biome being migrated."""

    biome_instance_id: int
    biome_id: int
    biome_kind: str
    src_node_id: int
    lock_to_host: bool
    required_hardware_tags: frozenset[str] = field(default_factory=frozenset)
    expected_cpu_load_pct: float = 0.0
    expected_mem_load_pct: float = 0.0
    expected_disk_load_pct: float = 0.0


@dataclass(slots=True, frozen=True)
class ClusterState:
    """Snapshot of the cluster at safety-check time."""

    cluster_id: str
    nodes: tuple[NodeSnapshot, ...]
    in_flight_migrations: int
    network_partition_active: bool = False
    maintenance_window_active: bool = False


@dataclass(slots=True, frozen=True)
class MigrationPolicy:
    """In-memory image of the ``migration_policy`` row."""

    enabled: bool
    evaluation_interval_seconds: int
    min_healthy_nodes: int
    max_concurrent_migrations: int
    require_target_capacity_headroom_cpu_pct: int
    require_target_capacity_headroom_mem_pct: int
    require_target_capacity_headroom_disk_pct: int
    rollback_on_destination_failure: bool
    rollback_window_seconds: int
    forbid_migration_during_partition: bool
    forbid_migration_during_maintenance: bool
    waddleai_risk_threshold: float
    capacity_forecast_horizon_days: int


@dataclass(slots=True, frozen=True)
class MigrationPlan:
    """The candidate migration we are evaluating."""

    biome: BiomeSnapshot
    requested_target_node_id: Optional[int]  # None → engine picks
    ignore_lock: bool
    reason: str


@dataclass(slots=True, frozen=True)
class Violation:
    """A single rejection reason. Every rejection produces ≥ 1 violation."""

    code: str
    message: str
    node_id: Optional[int] = None
    field: Optional[str] = None
    actual: Optional[float] = None
    required: Optional[float] = None


@dataclass(slots=True, frozen=True)
class SafetyResult:
    """Result of evaluating a migration plan against the safety envelope."""

    verdict: str  # "pass" | "rejected"
    reason: Optional[str]  # short rejection reason code; None on pass
    candidates_considered: int
    chosen_target_node_id: Optional[int]
    violations: tuple[Violation, ...]


# =============================================================================
# Validation of policy field values (used by PATCH /migration/policy)
# =============================================================================


# (field_name, low_inclusive, high_inclusive) — matches spec table at L4738.
_INT_RANGES: dict[str, tuple[int, int]] = {
    "evaluation_interval_seconds": (60, 3600),
    "min_healthy_nodes": (2, 10_000),
    "max_concurrent_migrations": (1, 10),
    "require_target_capacity_headroom_cpu_pct": (0, 50),
    "require_target_capacity_headroom_mem_pct": (0, 50),
    "require_target_capacity_headroom_disk_pct": (0, 50),
    "rollback_window_seconds": (60, 1800),
}

_BOOL_FIELDS: frozenset[str] = frozenset({
    "enabled",
    "rollback_on_destination_failure",
    "forbid_migration_during_partition",
    "forbid_migration_during_maintenance",
})

_ALLOWED_HORIZON_DAYS: frozenset[int] = frozenset({1, 7, 30})

POLICY_FIELDS: frozenset[str] = (
    frozenset(_INT_RANGES.keys())
    | _BOOL_FIELDS
    | frozenset({"waddleai_risk_threshold", "capacity_forecast_horizon_days"})
)


def validate_policy_patch(patch: dict) -> list[Violation]:
    """Validate a JSON Merge Patch body against the policy field constraints.

    Returns a list of violations. Empty list → patch is valid.
    """
    violations: list[Violation] = []

    for key, value in patch.items():
        if key not in POLICY_FIELDS:
            violations.append(Violation(
                code="unknown_field",
                message=f"Unknown policy field: {key}",
                field=key,
            ))
            continue

        if key in _BOOL_FIELDS:
            if not isinstance(value, bool):
                violations.append(Violation(
                    code="type_error",
                    message=f"Field {key} must be boolean",
                    field=key,
                ))
            continue

        if key in _INT_RANGES:
            low, high = _INT_RANGES[key]
            if not isinstance(value, int) or isinstance(value, bool):
                violations.append(Violation(
                    code="type_error",
                    message=f"Field {key} must be integer",
                    field=key,
                ))
                continue
            if not (low <= value <= high):
                violations.append(Violation(
                    code="out_of_range",
                    message=f"Field {key} must be in [{low}, {high}]",
                    field=key,
                    actual=float(value),
                    required=float(low),
                ))
            continue

        if key == "waddleai_risk_threshold":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                violations.append(Violation(
                    code="type_error",
                    message="waddleai_risk_threshold must be a number",
                    field=key,
                ))
                continue
            if not (0.0 <= float(value) <= 1.0):
                violations.append(Violation(
                    code="out_of_range",
                    message="waddleai_risk_threshold must be in [0.0, 1.0]",
                    field=key,
                    actual=float(value),
                ))
            continue

        if key == "capacity_forecast_horizon_days":
            # Explicitly reject bool (True == 1 in Python)
            if isinstance(value, bool) or not isinstance(value, int):
                violations.append(Violation(
                    code="type_error",
                    message="capacity_forecast_horizon_days must be integer",
                    field=key,
                ))
                continue
            if value not in _ALLOWED_HORIZON_DAYS:
                violations.append(Violation(
                    code="out_of_range",
                    message="capacity_forecast_horizon_days must be one of {1, 7, 30}",
                    field=key,
                    actual=float(value),
                ))

    return violations


def validate_combination(
    merged: dict, *, cluster_size: Optional[int] = None
) -> list[Violation]:
    """Cross-field combination checks (e.g., ``min_healthy_nodes`` vs cluster).

    The single-field range checks live in ``validate_policy_patch``. Combination
    rules live here so they can be applied to the *merged* policy (existing row
    + incoming patch), not just the patch in isolation.
    """
    violations: list[Violation] = []
    if cluster_size is not None:
        mhn = merged.get("min_healthy_nodes")
        if isinstance(mhn, int) and not isinstance(mhn, bool):
            if mhn > cluster_size:
                violations.append(Violation(
                    code="impossible_floor",
                    message=(
                        f"min_healthy_nodes ({mhn}) exceeds cluster size "
                        f"({cluster_size})"
                    ),
                    field="min_healthy_nodes",
                    actual=float(mhn),
                    required=float(cluster_size),
                ))
    return violations


# =============================================================================
# Safety envelope evaluation
# =============================================================================


def _ready_nodes(state: ClusterState) -> tuple[NodeSnapshot, ...]:
    return tuple(n for n in state.nodes if n.state == "ready")


def _candidate_nodes(
    state: ClusterState, plan: MigrationPlan
) -> tuple[NodeSnapshot, ...]:
    """Filter nodes that could host the biome (excludes source, non-ready, tags)."""
    return tuple(
        n for n in state.nodes
        if n.state == "ready"
        and n.node_id != plan.biome.src_node_id
        and plan.biome.required_hardware_tags.issubset(n.hardware_tags)
    )


def _violates_headroom(
    node: NodeSnapshot, biome: BiomeSnapshot, policy: MigrationPolicy
) -> Optional[Violation]:
    """Return a violation if simulating the biome's load on the node breaches the
    headroom requirements; else ``None``."""
    cpu_after = node.forecast_cpu_free_pct - biome.expected_cpu_load_pct
    mem_after = node.forecast_mem_free_pct - biome.expected_mem_load_pct
    disk_after = node.forecast_disk_free_pct - biome.expected_disk_load_pct

    if cpu_after < policy.require_target_capacity_headroom_cpu_pct:
        return Violation(
            code="insufficient_cpu_headroom",
            message=(
                f"Target node {node.node_id} CPU free post-migration "
                f"{cpu_after:.1f}% < required "
                f"{policy.require_target_capacity_headroom_cpu_pct}%"
            ),
            node_id=node.node_id,
            field="require_target_capacity_headroom_cpu_pct",
            actual=cpu_after,
            required=float(policy.require_target_capacity_headroom_cpu_pct),
        )
    if mem_after < policy.require_target_capacity_headroom_mem_pct:
        return Violation(
            code="insufficient_mem_headroom",
            message=(
                f"Target node {node.node_id} memory free post-migration "
                f"{mem_after:.1f}% < required "
                f"{policy.require_target_capacity_headroom_mem_pct}%"
            ),
            node_id=node.node_id,
            field="require_target_capacity_headroom_mem_pct",
            actual=mem_after,
            required=float(policy.require_target_capacity_headroom_mem_pct),
        )
    if disk_after < policy.require_target_capacity_headroom_disk_pct:
        return Violation(
            code="insufficient_disk_headroom",
            message=(
                f"Target node {node.node_id} disk free post-migration "
                f"{disk_after:.1f}% < required "
                f"{policy.require_target_capacity_headroom_disk_pct}%"
            ),
            node_id=node.node_id,
            field="require_target_capacity_headroom_disk_pct",
            actual=disk_after,
            required=float(policy.require_target_capacity_headroom_disk_pct),
        )
    return None


def evaluate(
    plan: MigrationPlan,
    cluster_state: ClusterState,
    policy: MigrationPolicy,
) -> SafetyResult:
    """Evaluate a migration plan against the safety envelope.

    Steps follow spec "Pre-Migration Safety Check" (lines 4756-4770):

    1. Cluster health: ready nodes ≥ ``min_healthy_nodes``
    2. Concurrency: in-flight migrations < ``max_concurrent_migrations``
    3. Partition / maintenance gates
    4. Biome lock: ``lock_to_host`` always rejects unless ``ignore_lock``
    5. Target selection: filter by ``required_hardware_tags``
    6. Forecast headroom: simulate biome's load against each candidate
    7. Pick the lowest composite-load-score survivor

    Every rejection is recorded with a structured ``Violation`` so the
    operator dashboard can surface it (never silently skipped, per spec).
    """
    violations: list[Violation] = []

    # Step 1: cluster health ---------------------------------------------------
    ready = _ready_nodes(cluster_state)
    if len(ready) < policy.min_healthy_nodes:
        violations.append(Violation(
            code="cluster_unhealthy",
            message=(
                f"Cluster has {len(ready)} ready nodes; policy requires "
                f"≥ {policy.min_healthy_nodes}"
            ),
            field="min_healthy_nodes",
            actual=float(len(ready)),
            required=float(policy.min_healthy_nodes),
        ))
        return SafetyResult(
            verdict="rejected",
            reason="cluster_unhealthy",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 2: concurrency ------------------------------------------------------
    if cluster_state.in_flight_migrations >= policy.max_concurrent_migrations:
        violations.append(Violation(
            code="too_many_concurrent_migrations",
            message=(
                f"{cluster_state.in_flight_migrations} migrations in flight; "
                f"policy max {policy.max_concurrent_migrations}"
            ),
            field="max_concurrent_migrations",
            actual=float(cluster_state.in_flight_migrations),
            required=float(policy.max_concurrent_migrations),
        ))
        return SafetyResult(
            verdict="rejected",
            reason="too_many_concurrent_migrations",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 3: partition/maintenance gates --------------------------------------
    if (policy.forbid_migration_during_partition
            and cluster_state.network_partition_active):
        violations.append(Violation(
            code="network_partition_active",
            message="Network partition active; migrations paused by policy",
            field="forbid_migration_during_partition",
        ))
        return SafetyResult(
            verdict="rejected",
            reason="network_partition_active",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )
    if (policy.forbid_migration_during_maintenance
            and cluster_state.maintenance_window_active):
        violations.append(Violation(
            code="maintenance_window_active",
            message="Tenant maintenance window active; migrations paused",
            field="forbid_migration_during_maintenance",
        ))
        return SafetyResult(
            verdict="rejected",
            reason="maintenance_window_active",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 4: biome lock ---------------------------------------------------------
    if plan.biome.lock_to_host and not plan.ignore_lock:
        violations.append(Violation(
            code="biome_locked_to_host",
            message=(
                f"Biome {plan.biome.biome_instance_id} is locked to host; "
                f"set ignore_lock=true with override scope to migrate"
            ),
            field="lock_to_host",
        ))
        return SafetyResult(
            verdict="rejected",
            reason="biome_locked_to_host",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 5: candidate filter -------------------------------------------------
    candidates = _candidate_nodes(cluster_state, plan)
    if plan.requested_target_node_id is not None:
        candidates = tuple(
            n for n in candidates if n.node_id == plan.requested_target_node_id
        )
        if not candidates:
            violations.append(Violation(
                code="target_unavailable",
                message=(
                    f"Requested target node {plan.requested_target_node_id} is "
                    f"not a viable candidate (state, source-equality, or "
                    f"hardware-tag constraints)"
                ),
                node_id=plan.requested_target_node_id,
                field="target_node_id",
            ))
            return SafetyResult(
                verdict="rejected",
                reason="target_unavailable",
                candidates_considered=0,
                chosen_target_node_id=None,
                violations=tuple(violations),
            )

    if not candidates:
        violations.append(Violation(
            code="no_viable_candidates",
            message=(
                "No nodes satisfy hardware-tag, source-equality, and ready-state "
                "constraints"
            ),
        ))
        return SafetyResult(
            verdict="rejected",
            reason="no_viable_candidates",
            candidates_considered=0,
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 6: headroom check per candidate -------------------------------------
    survivors: list[NodeSnapshot] = []
    for node in candidates:
        viol = _violates_headroom(node, plan.biome, policy)
        if viol is None:
            survivors.append(node)
        else:
            violations.append(viol)

    if not survivors:
        return SafetyResult(
            verdict="rejected",
            reason="insufficient_headroom",
            candidates_considered=len(candidates),
            chosen_target_node_id=None,
            violations=tuple(violations),
        )

    # Step 7: pick lowest composite load score ---------------------------------
    chosen = min(survivors, key=lambda n: n.composite_load_score)

    return SafetyResult(
        verdict="pass",
        reason=None,
        candidates_considered=len(candidates),
        chosen_target_node_id=chosen.node_id,
        violations=tuple(violations),  # advisory: per-candidate rejections
    )


# =============================================================================
# Helpers for serialising results to the API response
# =============================================================================


def violations_to_dicts(violations: Iterable[Violation]) -> list[dict]:
    """Serialise violations for inclusion in a JSON response body."""
    out: list[dict] = []
    for v in violations:
        d: dict = {"code": v.code, "message": v.message}
        if v.node_id is not None:
            d["node_id"] = v.node_id
        if v.field is not None:
            d["field"] = v.field
        if v.actual is not None:
            d["actual"] = v.actual
        if v.required is not None:
            d["required"] = v.required
        out.append(d)
    return out


def safety_result_to_dict(result: SafetyResult) -> dict:
    """Serialise a SafetyResult for inclusion in a JSON response body."""
    return {
        "verdict": result.verdict,
        "reason": result.reason,
        "candidates_considered": result.candidates_considered,
        "chosen_target_node_id": result.chosen_target_node_id,
        "violations": violations_to_dicts(result.violations),
    }


# =============================================================================
# Async execution functions (for API endpoints)
# =============================================================================


async def evaluate_safety(node_id: int) -> dict[str, Any]:
    """Evaluate migration safety for a node evacuation.

    Called by nodes.py:evacuate_node to assess whether the node's workloads
    can be safely migrated off. Returns structured safety assessment.

    Returns:
        {"safe": bool, "note": str, "violations": list[dict]}
    """
    # TODO(Phase 3): Load cluster state, node, biome instances from DB
    # Fail closed: return unsafe until implemented
    return {
        "safe": False,
        "note": "safety evaluation not implemented (Phase 3)",
        "violations": [],
    }


async def execute_migration(
    biome_instance_id: int,
    src_node_id: int,
    dst_node_id: int,
    live: bool,
    reason: str,
) -> dict[str, Any]:
    """Execute a live migration of a biome instance.

    Issues ``lxc move`` (with --live flag if live=true) to move the biome
    from src to dst node. Updates migration_events table with the result.

    Args:
        biome_instance_id: biome instance ID
        src_node_id: source node ID
        dst_node_id: destination node ID
        live: if True, use lxc move --live; else stop/move/start
        reason: human-readable reason for the migration

    Returns:
        {"status": "completed"|"failed"|"not_implemented", "duration_ms": int, "verdict": str}
    """
    # TODO(Phase 3): Call lxd_extra.live_migrate() or equivalent
    # Not implemented yet — return not_implemented status
    return {
        "status": "not_implemented",
        "duration_ms": 0,
        "verdict": "execution_deferred_to_m2",
    }
