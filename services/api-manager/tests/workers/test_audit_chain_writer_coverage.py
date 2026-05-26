"""Extended coverage tests for audit_chain_writer.py missed lines."""

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from app.workers.audit_chain_writer import (
    AuditChainWriter,
    NotLeaderError,
    OffsiteMirrorConfig,
)


class TestAuditChainWriterMetrics:
    """Test metric initialization and duplicate handling."""


class TestAuditChainWriterAppendNonLeader:
    """Test append_event behavior when not leader."""

    def test_append_event_not_leader_raises_error(self):
        """append_event raises NotLeaderError when is_leader() is False."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_lease = MagicMock()
        mock_lease.is_leader.return_value = False

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=mock_vault,
            leader_lease_client=mock_lease,
        )
        # Don't set _lease_handle so is_leader() returns False
        assert writer.is_leader() is False

        with pytest.raises(NotLeaderError):
            writer.append_event(
                actor_sub="user123",
                action="create",
                resource_kind="node",
            )

    def test_append_event_isolation_level_exception_logged(self):
        """append_event logs exception when SERIALIZABLE isolation unavailable."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_writer = MagicMock()

        # Mock db.execute to raise on SERIALIZABLE, then succeed on advisory lock.
        mock_db.execute.side_effect = [
            Exception("SERIALIZABLE not supported"),  # First call
            None,  # Second call (advisory lock) — succeeds
        ]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=mock_vault,
        )
        writer._lease_handle = MagicMock()  # Pretend we're leader
        writer._writer = mock_writer
        writer._writer.append.return_value = MagicMock(id=uuid.uuid4())

        with patch("app.workers.audit_chain_writer.logger") as mock_logger:
            writer.append_event(
                actor_sub="user123",
                action="create",
                resource_kind="node",
            )
            # Verify debug log was called
            assert mock_logger.debug.called

    def test_append_event_advisory_lock_exception_logged(self):
        """append_event logs exception when advisory lock unavailable."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_writer = MagicMock()

        # Mock db.execute: success on SERIALIZABLE, fail on advisory lock.
        mock_db.execute.side_effect = [
            None,  # SERIALIZABLE succeeds
            Exception("pg_advisory_xact_lock not available"),  # Advisory lock fails
        ]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=mock_vault,
        )
        writer._lease_handle = MagicMock()
        writer._writer = mock_writer
        writer._writer.append.return_value = MagicMock(id=uuid.uuid4())

        with patch("app.workers.audit_chain_writer.logger") as mock_logger:
            writer.append_event(
                actor_sub="user123",
                action="create",
                resource_kind="node",
            )
            # Verify advisory lock exception was logged
            calls = [str(c) for c in mock_logger.debug.call_args_list]
            assert any("pg_advisory_xact_lock" in str(c) for c in calls)


class TestAuditChainWriterMirrorWatermark:
    """Test watermark reading and fallback."""

    def test_read_watermark_table_missing(self):
        """_read_watermark returns None when table missing."""
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("Table does not exist")

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        result = writer._read_watermark()
        assert result is None

    def test_read_watermark_row_none(self):
        """_read_watermark returns None when no row found."""
        mock_db = MagicMock()
        mock_db.execute.return_value.first.return_value = None

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        result = writer._read_watermark()
        assert result is None

    def test_read_watermark_row_empty(self):
        """_read_watermark returns None when row[0] is None."""
        mock_db = MagicMock()
        mock_db.execute.return_value.first.return_value = (None,)

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        result = writer._read_watermark()
        assert result is None


class TestAuditChainWriterFetchRows:
    """Test _fetch_rows_after with different row formats."""

    def test_fetch_rows_with_mapping_attribute(self):
        """_fetch_rows_after handles rows with _mapping attribute."""
        test_id = uuid.uuid4()
        mock_db = MagicMock()
        mock_row = MagicMock()
        mock_row._mapping = {
            "id": test_id,
            "ts": datetime.now(timezone.utc),
            "cluster_id": "test-cluster",
            "tenant_id": "tenant123",
            "actor_sub": "user123",
            "actor_scope": ["read"],
            "action": "create",
            "resource_kind": "node",
            "resource_id": "node123",
            "before_json": None,
            "after_json": None,
            "request_id": "req123",
            "source_ip": "1.2.3.4",
            "user_agent": "test",
            "prev_hash": "hash1",
            "hash": "hash2",
            "signature": None,
        }
        mock_db.execute.return_value.fetchall.return_value = [mock_row]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        result = writer._fetch_rows_after(None, 100)
        assert len(result) == 1
        assert result[0]["id"] == test_id

    def test_fetch_rows_without_mapping_attribute(self):
        """_fetch_rows_after handles rows without _mapping (raw tuples)."""
        test_id = uuid.uuid4()
        test_ts = datetime.now(timezone.utc)
        mock_db = MagicMock()
        mock_row = (
            test_id, test_ts, "cluster", "tenant", "user", ["read"],
            "action", "kind", "res_id", None, None, "req", "1.1.1.1", "agent", "h1", "h2", None
        )
        mock_db.execute.return_value.fetchall.return_value = [mock_row]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        result = writer._fetch_rows_after(None, 100)
        assert len(result) == 1
        assert result[0]["id"] == test_id


class TestAuditChainWriterUpdateLagGauge:
    """Test lag gauge calculation."""

    def test_update_lag_gauge_no_rows(self):
        """_update_lag_gauge sets 0 when no audit rows exist."""
        mock_db = MagicMock()
        mock_db.execute.return_value.first.return_value = None

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        with patch("app.workers.audit_chain_writer.MIRROR_LAG_GAUGE") as mock_gauge:
            writer._update_lag_gauge(None)
            mock_gauge.set.assert_called_once_with(0.0)

    def test_update_lag_gauge_watermark_not_found(self):
        """_update_lag_gauge calculates lag when watermark row doesn't exist."""
        mock_db = MagicMock()
        now_utc = datetime.now(timezone.utc)
        mock_db.execute.return_value.first.side_effect = [
            (now_utc,),  # Latest row
            None,  # Watermark row not found
        ]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        with patch("app.workers.audit_chain_writer.MIRROR_LAG_GAUGE") as mock_gauge:
            writer._update_lag_gauge(uuid.uuid4())
            # Should set a lag value > 0
            assert mock_gauge.set.called
            lag_value = mock_gauge.set.call_args[0][0]
            assert lag_value >= 0

    def test_update_lag_gauge_timezone_naive_handling(self):
        """_update_lag_gauge handles timezone-naive datetime."""
        mock_db = MagicMock()
        naive_ts = datetime.now()  # No timezone
        utc_ts = datetime.now(timezone.utc)
        mock_db.execute.return_value.first.side_effect = [
            (naive_ts,),  # Naive latest
            (naive_ts,),  # Naive shipped
        ]

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        with patch("app.workers.audit_chain_writer.MIRROR_LAG_GAUGE") as mock_gauge:
            writer._update_lag_gauge(uuid.uuid4())
            assert mock_gauge.set.called

    def test_update_lag_gauge_exception_logged(self):
        """_update_lag_gauge logs exception and continues."""
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("DB error")

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
        )

        with patch("app.workers.audit_chain_writer.logger") as mock_logger:
            writer._update_lag_gauge(None)
            assert mock_logger.debug.called


class TestAuditChainWriterVerifyChainScheduled:
    """Test verify_chain_scheduled behavior."""

    def test_verify_chain_scheduled_no_breaks(self):
        """verify_chain_scheduled returns summary when no breaks found."""
        mock_db = MagicMock()

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=None,
        )

        with patch("app.workers.audit_chain_writer.verify_chain") as mock_verify:
            mock_verify.return_value = {
                "breaks": 0,
                "rows_checked": 100,
            }

            result = writer.verify_chain_scheduled()
            assert result["breaks"] == 0
            assert result["nats_event_emitted"] is False

    def test_verify_chain_scheduled_with_breaks_no_nats(self):
        """verify_chain_scheduled emits metric but not NATS when no publisher."""
        mock_db = MagicMock()

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=None,
        )

        with patch("app.workers.audit_chain_writer.verify_chain") as mock_verify:
            with patch("app.workers.audit_chain_writer.CHAIN_BREAK_COUNTER") as mock_counter:
                mock_verify.return_value = {
                    "breaks": 2,
                    "first_break_id": uuid.uuid4(),
                    "last_break_id": uuid.uuid4(),
                    "rows_checked": 100,
                }

                result = writer.verify_chain_scheduled(emit_nats=True)
                assert result["breaks"] == 2
                assert result["nats_event_emitted"] is False
                mock_counter.inc.assert_called_with(2)

    def test_verify_chain_scheduled_nats_publish_error(self):
        """verify_chain_scheduled handles NATS publish error gracefully."""
        mock_db = MagicMock()
        mock_nats = MagicMock()
        mock_nats.side_effect = Exception("NATS error")

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=mock_nats,
        )

        with patch("app.workers.audit_chain_writer.verify_chain") as mock_verify:
            with patch("app.workers.audit_chain_writer.CHAIN_BREAK_COUNTER"):
                mock_verify.return_value = {
                    "breaks": 1,
                    "first_break_id": uuid.uuid4(),
                    "last_break_id": None,
                    "rows_checked": 50,
                }

                result = writer.verify_chain_scheduled(emit_nats=True)
                assert result["breaks"] == 1
                assert result["nats_event_emitted"] is False


@pytest.mark.asyncio
class TestAuditChainWriterMirrorConfig:
    """Test OffsiteMirrorConfig and S3 factory."""

    def test_offsite_mirror_config_defaults(self):
        """OffsiteMirrorConfig has correct defaults."""
        cfg = OffsiteMirrorConfig(
            s3_endpoint="http://localhost:9000",
            bucket="audit-bucket",
            retention_days=90,
        )
        assert cfg.region == "us-east-1"
        assert cfg.poll_interval_seconds == 1.0
        assert cfg.object_lock_mode == "COMPLIANCE"

    def test_offsite_mirror_config_object_key(self):
        """OffsiteMirrorConfig.object_key returns correct path."""
        cfg = OffsiteMirrorConfig(
            s3_endpoint="http://localhost:9000",
            bucket="audit-bucket",
            retention_days=90,
            object_prefix="audit-events/",
        )
        test_id = uuid.uuid4()
        key = cfg.object_key(test_id)
        assert key == f"audit-events/{test_id}.json"

    def test_build_s3_client_factory_with_override(self):
        """_build_s3_client_factory returns override factory when provided."""
        mock_db = MagicMock()
        mock_s3_factory = MagicMock()

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            s3_session_factory=mock_s3_factory,
        )

        cfg = OffsiteMirrorConfig(
            s3_endpoint="http://localhost:9000",
            bucket="audit-bucket",
            retention_days=90,
        )

        factory = writer._build_s3_client_factory(cfg)
        factory()
        mock_s3_factory.assert_called_once_with(cfg)

    @pytest.mark.asyncio
    async def test_start_offsite_mirror_max_iterations(self):
        """start_offsite_mirror stops after max_iterations."""
        mock_db = MagicMock()
        mock_db.execute.return_value.first.return_value = None  # No watermark

        mock_s3_client = MagicMock()
        mock_s3_client.__aenter__.return_value = mock_s3_client
        mock_s3_client.__aexit__.return_value = None
        mock_s3_client.put_object = AsyncMock()

        def client_factory():
            return mock_s3_client

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            s3_session_factory=lambda cfg: client_factory(),
        )

        result = await writer.start_offsite_mirror(
            s3_endpoint="http://localhost:9000",
            bucket="audit-bucket",
            retention_days=90,
            max_iterations=2,
        )

        assert result["iterations"] == 2


@pytest.mark.asyncio
class TestAuditChainWriterMirrorError:
    """Test mirror error handling."""

    @pytest.mark.asyncio
    async def test_start_offsite_mirror_aioboto3_import_error(self):
        """start_offsite_mirror raises OffsiteMirrorError when aioboto3 missing."""
        from app.workers.audit_chain_writer import OffsiteMirrorError

        mock_db = MagicMock()
        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            s3_session_factory=None,
        )

        with patch("builtins.__import__", side_effect=ImportError("aioboto3 not found")):
            with pytest.raises(OffsiteMirrorError, match="aioboto3 is required"):
                await writer.start_offsite_mirror(
                    s3_endpoint="http://localhost:9000",
                    bucket="audit-bucket",
                    retention_days=90,
                )


class TestAuditChainWriterNatsPublish:
    """Test NATS event publishing."""

    def test_publish_nats_break_no_publisher(self):
        """_publish_nats_break returns False when no publisher configured."""
        mock_db = MagicMock()
        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=None,
        )

        result = writer._publish_nats_break({"test": "payload"})
        assert result is False

    def test_publish_nats_break_sync_context(self):
        """_publish_nats_break handles coroutine in sync context."""
        mock_db = MagicMock()
        mock_nats = MagicMock()

        async def async_publish(subject, payload):
            pass

        mock_nats.side_effect = lambda s, p: async_publish(s, p)

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=mock_nats,
        )

        with patch("asyncio.iscoroutine", return_value=True):
            with patch("asyncio.get_running_loop", side_effect=RuntimeError):
                with patch("asyncio.run"):
                    result = writer._publish_nats_break({"test": "payload"})
                    assert result is True

    def test_publish_nats_break_with_running_loop(self):
        """_publish_nats_break schedules on existing event loop."""
        mock_db = MagicMock()
        mock_nats = MagicMock()

        async def async_publish(subject, payload):
            pass

        mock_nats.side_effect = lambda s, p: async_publish(s, p)

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=mock_nats,
        )

        with patch("asyncio.iscoroutine", return_value=True):
            mock_loop = MagicMock()
            with patch("asyncio.get_running_loop", return_value=mock_loop):
                with patch("asyncio.ensure_future"):
                    result = writer._publish_nats_break({"test": "payload"})
                    assert result is True

    def test_publish_nats_break_exception_handled(self):
        """_publish_nats_break catches and logs exceptions."""
        mock_db = MagicMock()
        mock_nats = MagicMock(side_effect=Exception("Publish failed"))

        writer = AuditChainWriter(
            db_session=mock_db,
            vault_client=None,
            nats_publisher=mock_nats,
        )

        with patch("app.workers.audit_chain_writer.logger") as mock_logger:
            result = writer._publish_nats_break({"test": "payload"})
            assert result is False
            assert mock_logger.error.called
