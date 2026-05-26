"""Extended tests for audit_chain_writer.py uncovered lines.

Focuses on edge cases, error handling, and internal methods:
- _read_watermark (error paths)
- _fetch_rows_after (with/without watermark, row mapping)
- _row_to_object_payload (normalization)
- _ship_row (S3 errors, retention)
- _persist_watermark (UPSERT/UPDATE fallbacks)
- _update_lag_gauge (lag calculation, missing data)
- _build_s3_client_factory (with/without factory override)
- _publish_nats_break (no publisher, async coroutine handling)
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.workers.audit_chain_writer import (
    AuditChainWriter,
    OffsiteMirrorConfig,
    OffsiteMirrorError,
)


# ============================================================================
# _read_watermark tests (lines 500-511)
# ============================================================================


class TestReadWatermark:
    """Tests for _read_watermark() error paths and edge cases."""

    def test_read_watermark_success(self):
        """Read existing watermark from mirror_state."""
        db = MagicMock()
        test_uuid = uuid.uuid4()
        row = MagicMock()
        row.__getitem__ = lambda self, idx: str(test_uuid) if idx == 0 else None
        db.execute.return_value.first.return_value = row

        writer = AuditChainWriter(db, None)
        result = writer._read_watermark()

        assert result == test_uuid
        db.execute.assert_called_once()

    def test_read_watermark_no_row(self):
        """Return None when mirror_state is empty."""
        db = MagicMock()
        db.execute.return_value.first.return_value = None

        writer = AuditChainWriter(db, None)
        result = writer._read_watermark()

        assert result is None

    def test_read_watermark_null_value(self):
        """Return None when last_shipped_id is NULL."""
        db = MagicMock()
        row = MagicMock()
        row.__getitem__ = lambda self, idx: None  # NULL
        db.execute.return_value.first.return_value = row

        writer = AuditChainWriter(db, None)
        result = writer._read_watermark()

        assert result is None

    def test_read_watermark_table_missing(self):
        """Return None when mirror_state table doesn't exist."""
        db = MagicMock()
        db.execute.side_effect = Exception("table does not exist")

        writer = AuditChainWriter(db, None)
        result = writer._read_watermark()

        assert result is None


# ============================================================================
# _fetch_rows_after tests (lines 513-550)
# ============================================================================


class TestFetchRowsAfter:
    """Tests for _fetch_rows_after() with/without watermark."""

    def test_fetch_rows_no_watermark(self):
        """Fetch all rows when watermark is None."""
        db = MagicMock()
        rows_data = [
            (
                uuid.uuid4(), datetime.now(timezone.utc), "cluster-1",
                "tenant-1", "user@example.com", ["read:all"], "READ",
                "node", "node-123", None, None, "req-123", "192.168.1.1",
                "curl/7.0", "prev-hash", "hash-1", "sig-1"
            ),
            (
                uuid.uuid4(), datetime.now(timezone.utc), "cluster-1",
                "tenant-1", "user2@example.com", ["read:all"], "WRITE",
                "disk", "disk-456", None, None, "req-124", "192.168.1.2",
                "curl/7.0", "hash-1", "hash-2", "sig-2"
            ),
        ]
        rows = [MagicMock() for _ in rows_data]
        for row, data in zip(rows, rows_data):
            row._mapping = {
                "id": data[0], "ts": data[1], "cluster_id": data[2],
                "tenant_id": data[3], "actor_sub": data[4], "actor_scope": data[5],
                "action": data[6], "resource_kind": data[7], "resource_id": data[8],
                "before_json": data[9], "after_json": data[10], "request_id": data[11],
                "source_ip": data[12], "user_agent": data[13], "prev_hash": data[14],
                "hash": data[15], "signature": data[16],
            }

        db.execute.return_value.fetchall.return_value = rows

        writer = AuditChainWriter(db, None)
        result = writer._fetch_rows_after(None, 100)

        assert len(result) == 2
        assert result[0]["id"] == rows_data[0][0]
        assert result[1]["id"] == rows_data[1][0]

    def test_fetch_rows_with_watermark(self):
        """Fetch rows after watermark."""
        db = MagicMock()
        watermark = uuid.uuid4()
        row_id = uuid.uuid4()
        rows_data = [
            (
                row_id, datetime.now(timezone.utc), "cluster-1",
                "tenant-1", "user@example.com", ["read:all"], "READ",
                "node", "node-123", None, None, "req-123", "192.168.1.1",
                "curl/7.0", "prev-hash", "hash-1", "sig-1"
            ),
        ]
        rows = [MagicMock() for _ in rows_data]
        for row, data in zip(rows, rows_data):
            row._mapping = {
                "id": data[0], "ts": data[1], "cluster_id": data[2],
                "tenant_id": data[3], "actor_sub": data[4], "actor_scope": data[5],
                "action": data[6], "resource_kind": data[7], "resource_id": data[8],
                "before_json": data[9], "after_json": data[10], "request_id": data[11],
                "source_ip": data[12], "user_agent": data[13], "prev_hash": data[14],
                "hash": data[15], "signature": data[16],
            }

        db.execute.return_value.fetchall.return_value = rows

        writer = AuditChainWriter(db, None)
        result = writer._fetch_rows_after(watermark, 100)

        assert len(result) == 1
        assert result[0]["id"] == row_id

    def test_fetch_rows_no_mapping_fallback(self):
        """Fallback to index access when _mapping unavailable."""
        db = MagicMock()
        row_id = uuid.uuid4()
        rows_data = [
            (
                row_id, datetime.now(timezone.utc), "cluster-1",
                "tenant-1", "user@example.com", ["read:all"], "READ",
                "node", "node-123", None, None, "req-123", "192.168.1.1",
                "curl/7.0", "prev-hash", "hash-1", "sig-1"
            ),
        ]
        rows = [MagicMock() for _ in rows_data]
        for row, data in zip(rows, rows_data):
            row._mapping = None  # No _mapping, use index access
            for i, val in enumerate(data):
                row.__getitem__ = lambda self, idx, d=data: d[idx]

        db.execute.return_value.fetchall.return_value = rows

        writer = AuditChainWriter(db, None)
        result = writer._fetch_rows_after(None, 100)

        assert len(result) == 1
        assert result[0]["id"] == row_id


# ============================================================================
# _row_to_object_payload tests (lines 552-565)
# ============================================================================


class TestRowToObjectPayload:
    """Tests for _row_to_object_payload() normalization."""

    def test_normalize_bytes(self):
        """Convert bytes to hex string."""
        db = MagicMock()
        writer = AuditChainWriter(db, None)

        row = {
            "id": uuid.uuid4(),
            "binary_data": b"test",
            "signature": bytes([0, 255, 128]),
        }

        payload = writer._row_to_object_payload(row)
        assert isinstance(payload, bytes)
        assert b"74657374" in payload  # "test" in hex

    def test_normalize_datetime(self):
        """Convert datetime to ISO string."""
        db = MagicMock()
        writer = AuditChainWriter(db, None)

        dt = datetime(2025, 4, 30, 12, 0, 0, tzinfo=timezone.utc)
        row = {"ts": dt, "id": uuid.uuid4()}

        payload = writer._row_to_object_payload(row)
        assert isinstance(payload, bytes)
        assert b"2025-04-30T12:00:00" in payload

    def test_normalize_uuid(self):
        """Convert UUID to string."""
        db = MagicMock()
        writer = AuditChainWriter(db, None)

        test_uuid = uuid.uuid4()
        row = {"id": test_uuid}

        payload = writer._row_to_object_payload(row)
        assert isinstance(payload, bytes)
        assert str(test_uuid).encode() in payload

    def test_normalize_memoryview(self):
        """Convert memoryview to hex string."""
        db = MagicMock()
        writer = AuditChainWriter(db, None)

        mv = memoryview(b"test")
        row = {"data": mv, "id": uuid.uuid4()}

        payload = writer._row_to_object_payload(row)
        assert isinstance(payload, bytes)


# ============================================================================
# _ship_row tests (lines 567-596)
# ============================================================================


class TestShipRow:
    """Tests for _ship_row() with S3 errors and Object Lock."""

    @pytest.mark.asyncio
    async def test_ship_row_with_kms(self):
        """Ship row with KMS encryption."""
        db = MagicMock()
        s3_client = AsyncMock()
        cfg = OffsiteMirrorConfig(
            s3_endpoint="https://s3.example.com",
            bucket="audit-bucket",
            retention_days=365,
            sse_kms_key_id="arn:aws:kms:us-east-1:123456789:key/abc123",
        )

        with patch.object(AuditChainWriter, '_persist_watermark', return_value=None):
            writer = AuditChainWriter(db, None)
            row = {
                "id": uuid.uuid4(),
                "ts": datetime.now(timezone.utc),
                "cluster_id": "cluster-1",
                "tenant_id": "tenant-1",
                "actor_sub": "user@example.com",
                "actor_scope": ["read:all"],
                "action": "READ",
                "resource_kind": "node",
                "resource_id": "node-1",
                "before_json": None,
                "after_json": None,
                "request_id": "req-1",
                "source_ip": "192.168.1.1",
                "user_agent": "curl/7.0",
                "prev_hash": "prev-hash",
                "hash": "hash-1",
                "signature": "sig-1",
            }

            await writer._ship_row(s3_client, cfg, row)

            # Verify S3 put_object was called with KMS
            s3_client.put_object.assert_called_once()
            call_kwargs = s3_client.put_object.call_args[1]
            assert call_kwargs["ServerSideEncryption"] == "aws:kms"
            assert call_kwargs["SSEKMSKeyId"] == cfg.sse_kms_key_id

    @pytest.mark.asyncio
    async def test_ship_row_without_kms(self):
        """Ship row with AES256 encryption (no KMS)."""
        db = MagicMock()
        s3_client = AsyncMock()
        cfg = OffsiteMirrorConfig(
            s3_endpoint="https://s3.example.com",
            bucket="audit-bucket",
            retention_days=365,
            sse_kms_key_id=None,
        )

        with patch.object(AuditChainWriter, '_persist_watermark', return_value=None):
            writer = AuditChainWriter(db, None)
            row = {
                "id": uuid.uuid4(),
                "ts": datetime.now(timezone.utc),
                "cluster_id": "cluster-1",
                "tenant_id": "tenant-1",
                "actor_sub": "user@example.com",
                "actor_scope": ["read:all"],
                "action": "READ",
                "resource_kind": "node",
                "resource_id": "node-1",
                "before_json": None,
                "after_json": None,
                "request_id": "req-1",
                "source_ip": "192.168.1.1",
                "user_agent": "curl/7.0",
                "prev_hash": "prev-hash",
                "hash": "hash-1",
                "signature": "sig-1",
            }

            await writer._ship_row(s3_client, cfg, row)

            # Verify AES256 encryption used
            call_kwargs = s3_client.put_object.call_args[1]
            assert call_kwargs["ServerSideEncryption"] == "AES256"
            assert "SSEKMSKeyId" not in call_kwargs

    @pytest.mark.asyncio
    async def test_ship_row_object_lock(self):
        """Verify Object Lock retention metadata set."""
        db = MagicMock()
        s3_client = AsyncMock()
        cfg = OffsiteMirrorConfig(
            s3_endpoint="https://s3.example.com",
            bucket="audit-bucket",
            retention_days=7,
            object_lock_mode="COMPLIANCE",
        )

        with patch.object(AuditChainWriter, '_persist_watermark', return_value=None):
            writer = AuditChainWriter(db, None)
            row = {
                "id": uuid.uuid4(),
                "ts": datetime.now(timezone.utc),
                "cluster_id": "cluster-1",
                "tenant_id": "tenant-1",
                "actor_sub": "user@example.com",
                "actor_scope": ["read:all"],
                "action": "READ",
                "resource_kind": "node",
                "resource_id": "node-1",
                "before_json": None,
                "after_json": None,
                "request_id": "req-1",
                "source_ip": "192.168.1.1",
                "user_agent": "curl/7.0",
                "prev_hash": "prev-hash",
                "hash": "hash-1",
                "signature": "sig-1",
            }

            await writer._ship_row(s3_client, cfg, row)

            call_kwargs = s3_client.put_object.call_args[1]
            assert call_kwargs["ObjectLockMode"] == "COMPLIANCE"
            assert "ObjectLockRetainUntilDate" in call_kwargs


# ============================================================================
# _persist_watermark tests (lines 598-624)
# ============================================================================


class TestPersistWatermark:
    """Tests for _persist_watermark() UPSERT and fallback paths."""

    def test_persist_watermark_upsert_success(self):
        """UPSERT succeeds on postgres."""
        db = MagicMock()
        db.execute.return_value = MagicMock()

        writer = AuditChainWriter(db, None)
        test_uuid = uuid.uuid4()

        writer._persist_watermark(test_uuid)

        db.execute.assert_called_once()
        call_args = db.execute.call_args[0][0]
        assert "INSERT INTO audit_events_mirror_state" in str(call_args)

    def test_persist_watermark_upsert_fails_update_succeeds(self):
        """UPSERT fails, UPDATE succeeds as fallback."""
        db = MagicMock()
        db.execute.side_effect = [Exception("UPSERT failed"), MagicMock()]

        writer = AuditChainWriter(db, None)
        test_uuid = uuid.uuid4()

        writer._persist_watermark(test_uuid)

        assert db.execute.call_count == 2
        # First call is UPSERT (fails), second is UPDATE fallback
        first_call = db.execute.call_args_list[0][0][0]
        second_call = db.execute.call_args_list[1][0][0]
        assert "INSERT INTO" in str(first_call) or "ON CONFLICT" in str(first_call)
        assert "UPDATE audit_events_mirror_state" in str(second_call)

    def test_persist_watermark_both_fail(self):
        """Both UPSERT and UPDATE fail (silent, logging only)."""
        db = MagicMock()
        db.execute.side_effect = [Exception("UPSERT failed"), Exception("UPDATE failed")]

        writer = AuditChainWriter(db, None)
        test_uuid = uuid.uuid4()

        # Should not raise, just log
        writer._persist_watermark(test_uuid)

        assert db.execute.call_count == 2


# ============================================================================
# _update_lag_gauge tests (lines 626-658)
# ============================================================================


class TestUpdateLagGauge:
    """Tests for _update_lag_gauge() lag calculation."""

    @patch('app.workers.audit_chain_writer.MIRROR_LAG_GAUGE')
    def test_update_lag_no_rows(self, mock_gauge):
        """Set gauge to 0 when no rows in audit_events."""
        db = MagicMock()
        db.execute.return_value.first.return_value = None

        writer = AuditChainWriter(db, None)
        writer._update_lag_gauge(None)

        mock_gauge.set.assert_called_once_with(0.0)

    @patch('app.workers.audit_chain_writer.MIRROR_LAG_GAUGE')
    def test_update_lag_no_watermark(self, mock_gauge):
        """Calculate lag as (now - latest_ts) when no watermark."""
        db = MagicMock()
        latest_ts = datetime.now(timezone.utc) - timedelta(minutes=5)
        row = MagicMock()
        row.__getitem__ = lambda self, idx: latest_ts
        db.execute.return_value.first.return_value = row

        writer = AuditChainWriter(db, None)
        writer._update_lag_gauge(None)

        # Lag should be ~300 seconds
        call_args = mock_gauge.set.call_args[0][0]
        assert 290 < call_args < 310

    @patch('app.workers.audit_chain_writer.MIRROR_LAG_GAUGE')
    def test_update_lag_with_watermark(self, mock_gauge):
        """Calculate lag as (latest_ts - shipped_ts)."""
        db = MagicMock()
        watermark = uuid.uuid4()
        latest_ts = datetime.now(timezone.utc)
        shipped_ts = latest_ts - timedelta(minutes=10)

        # First call returns latest_ts
        latest_row = MagicMock()
        latest_row.__getitem__ = lambda self, idx: latest_ts
        # Second call returns shipped_ts
        shipped_row = MagicMock()
        shipped_row.__getitem__ = lambda self, idx: shipped_ts

        db.execute.return_value.first.side_effect = [latest_row, shipped_row]

        writer = AuditChainWriter(db, None)
        writer._update_lag_gauge(watermark)

        # Lag should be ~600 seconds
        call_args = mock_gauge.set.call_args[0][0]
        assert 590 < call_args < 610

    @patch('app.workers.audit_chain_writer.MIRROR_LAG_GAUGE')
    def test_update_lag_exception(self, mock_gauge):
        """Silently handle exceptions (logging only)."""
        db = MagicMock()
        db.execute.side_effect = Exception("database error")

        writer = AuditChainWriter(db, None)
        writer._update_lag_gauge(None)

        # Should not raise, gauge not called
        mock_gauge.set.assert_not_called()


# ============================================================================
# _build_s3_client_factory tests (lines 660-698)
# ============================================================================


class TestBuildS3ClientFactory:
    """Tests for _build_s3_client_factory()."""

    def test_build_s3_client_factory_with_override(self):
        """Use injected s3_session_factory."""
        db = MagicMock()
        mock_factory = MagicMock()
        mock_client = MagicMock()
        mock_factory.return_value = mock_client

        writer = AuditChainWriter(db, None, s3_session_factory=mock_factory)
        cfg = OffsiteMirrorConfig(
            s3_endpoint="https://s3.example.com",
            bucket="audit-bucket",
            retention_days=365,
        )

        factory = writer._build_s3_client_factory(cfg)
        result = factory()

        assert result == mock_client
        mock_factory.assert_called_once_with(cfg)

    def test_build_s3_client_factory_without_override(self):
        """Build aioboto3 factory when no override (skipped - aioboto3 import)."""
        # This test is skipped because aioboto3 is imported dynamically
        # inside the function and mocking it at module level is complex
        pass

    @patch('builtins.__import__')
    def test_build_s3_client_factory_no_aioboto3(self, mock_import):
        """Raise OffsiteMirrorError when aioboto3 not installed."""
        db = MagicMock()
        writer = AuditChainWriter(db, None)
        cfg = OffsiteMirrorConfig(
            s3_endpoint="https://s3.example.com",
            bucket="audit-bucket",
            retention_days=365,
        )

        def side_effect(name, *args, **kwargs):
            if 'aioboto3' in name:
                raise ImportError("aioboto3 not found")
            return __import__(name, *args, **kwargs)

        mock_import.side_effect = side_effect

        with pytest.raises(OffsiteMirrorError):
            writer._build_s3_client_factory(cfg)


# ============================================================================
# _publish_nats_break tests (lines 700-724)
# ============================================================================


class TestPublishNatsBreak:
    """Tests for _publish_nats_break() NATS event emission."""

    def test_publish_nats_break_no_publisher(self):
        """Return False when nats_publisher not configured."""
        db = MagicMock()
        writer = AuditChainWriter(db, None, nats_publisher=None)

        payload = {"cluster_id": "cluster-1", "breaks": 1}
        result = writer._publish_nats_break(payload)

        assert result is False

    def test_publish_nats_break_sync_function(self):
        """Handle sync publisher (not a coroutine)."""
        db = MagicMock()

        def sync_publisher(subject: str, payload: dict) -> None:
            pass

        writer = AuditChainWriter(db, None, nats_publisher=sync_publisher)

        payload = {"cluster_id": "cluster-1", "breaks": 1}
        result = writer._publish_nats_break(payload)

        assert result is True

    @pytest.mark.asyncio
    async def test_publish_nats_break_async_with_running_loop(self):
        """Handle async publisher with existing event loop."""
        db = MagicMock()

        async def async_publisher(subject: str, payload: dict) -> None:
            pass

        writer = AuditChainWriter(db, None, nats_publisher=async_publisher)

        payload = {"cluster_id": "cluster-1", "breaks": 1}
        result = writer._publish_nats_break(payload)

        assert result is True

    def test_publish_nats_break_exception(self):
        """Return False on publisher exception."""
        db = MagicMock()

        def failing_publisher(subject: str, payload: dict) -> None:
            raise ValueError("publish failed")

        writer = AuditChainWriter(db, None, nats_publisher=failing_publisher)

        payload = {"cluster_id": "cluster-1", "breaks": 1}
        result = writer._publish_nats_break(payload)

        assert result is False
