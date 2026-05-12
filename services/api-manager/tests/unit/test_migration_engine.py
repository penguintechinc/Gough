"""Tests for migration_engine async execution functions (Phase 3)."""

from __future__ import annotations

import pytest

from app.workers.migration_engine import evaluate_safety, execute_migration


class TestEvaluateSafety:
    """Tests for evaluate_safety() async function."""

    @pytest.mark.asyncio
    async def test_evaluate_safety_returns_dict(self) -> None:
        """evaluate_safety() returns a dict with safe, note, violations keys."""
        result = await evaluate_safety(node_id=1)
        assert isinstance(result, dict)
        assert "safe" in result
        assert "note" in result
        assert "violations" in result

    @pytest.mark.asyncio
    async def test_evaluate_safety_default_safe(self) -> None:
        """By default, evaluate_safety returns safe=True (no violations)."""
        result = await evaluate_safety(node_id=1)
        assert result["safe"] is True
        assert isinstance(result["violations"], list)
        assert len(result["violations"]) == 0


class TestExecuteMigration:
    """Tests for execute_migration() async function."""

    @pytest.mark.asyncio
    async def test_execute_migration_returns_dict(self) -> None:
        """execute_migration() returns a dict with status, duration_ms, verdict."""
        result = await execute_migration(
            biome_instance_id=1,
            src_node_id=1,
            dst_node_id=2,
            live=True,
            reason="test migration",
        )
        assert isinstance(result, dict)
        assert "status" in result
        assert "duration_ms" in result
        assert "verdict" in result

    @pytest.mark.asyncio
    async def test_execute_migration_status_values(self) -> None:
        """execute_migration() status is one of 'completed', 'failed', etc."""
        result = await execute_migration(
            biome_instance_id=1,
            src_node_id=1,
            dst_node_id=2,
            live=False,
            reason="test",
        )
        assert result["status"] in ("completed", "failed")
        assert isinstance(result["duration_ms"], int)
        assert result["duration_ms"] >= 0

    @pytest.mark.asyncio
    async def test_execute_migration_live_flag(self) -> None:
        """execute_migration() accepts live flag (True for lxc move --live)."""
        result_live = await execute_migration(
            biome_instance_id=1,
            src_node_id=1,
            dst_node_id=2,
            live=True,
            reason="live test",
        )
        result_stop = await execute_migration(
            biome_instance_id=2,
            src_node_id=1,
            dst_node_id=2,
            live=False,
            reason="stop/move test",
        )
        # Both should return valid result dicts
        assert "status" in result_live
        assert "status" in result_stop
