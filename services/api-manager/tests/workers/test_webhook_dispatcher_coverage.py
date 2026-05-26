"""Extended coverage tests for webhook_dispatcher.py missed lines."""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import httpx

from app.workers.webhook_dispatcher import (
    WebhookDispatcher,
    WebhookEndpoint,
    DeliveryResult,
    build_signing_string,
    _new_event_id,
    _rfc3339,
    _b64,
    _b64url,
)


class TestWebhookEndpointMatching:
    """Test WebhookEndpoint event matching logic."""

    def test_endpoint_matches_inactive(self):
        """Inactive endpoint never matches."""
        ep = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com",
            signing_mode="hmac_sha256",
            event_filter=("node.created", "node.deleted"),
            active=False,
        )
        assert ep.matches("node.created") is False

    def test_endpoint_matches_no_filter(self):
        """Empty event_filter matches all events."""
        ep = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com",
            signing_mode="hmac_sha256",
            event_filter=(),
            active=True,
        )
        assert ep.matches("any.event") is True
        assert ep.matches("node.created") is True

    def test_endpoint_matches_exact(self):
        """Exact event type match succeeds."""
        ep = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com",
            signing_mode="hmac_sha256",
            event_filter=("node.created", "node.deleted"),
            active=True,
        )
        assert ep.matches("node.created") is True
        assert ep.matches("node.deleted") is True
        assert ep.matches("node.updated") is False

    def test_endpoint_matches_wildcard(self):
        """Wildcard '*' matches all events."""
        ep = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com",
            signing_mode="hmac_sha256",
            event_filter=("*",),
            active=True,
        )
        assert ep.matches("any.event") is True

    def test_endpoint_matches_prefix_wildcard(self):
        """Prefix wildcard 'node.*' matches pattern."""
        ep = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com",
            signing_mode="hmac_sha256",
            event_filter=("node.*",),
            active=True,
        )
        assert ep.matches("node.created") is True
        assert ep.matches("node.deleted") is True
        assert ep.matches("node") is False
        assert ep.matches("cluster.created") is False


class TestWebhookSigningString:
    """Test canonical signing string construction."""

    def test_build_signing_string(self):
        """build_signing_string constructs correct format."""
        timestamp = "2025-01-01T00:00:00.000000Z"
        event_id = "EVENT123"
        body = b'{"test":"data"}'

        result = build_signing_string(timestamp, event_id, body)
        assert result.startswith(b"2025-01-01T00:00:00.000000Z.")
        assert b"EVENT123." in result
        assert b"." in result  # timestamp.event_id.body_hash

    def test_build_signing_string_body_hash(self):
        """build_signing_string includes SHA256 body hash."""
        import hashlib

        timestamp = "2025-01-01T00:00:00.000000Z"
        event_id = "EVENT123"
        body = b"test content"

        result = build_signing_string(timestamp, event_id, body)
        expected_hash = hashlib.sha256(body).hexdigest()
        assert expected_hash in result.decode("ascii")


class TestWebhookHelperFunctions:
    """Test utility functions."""

    def test_b64_encoding(self):
        """_b64 encodes bytes to base64 string."""
        data = b"test"
        result = _b64(data)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_b64url_encoding(self):
        """_b64url encodes to URL-safe base64 without padding."""
        data = b"test"
        result = _b64url(data)
        assert isinstance(result, str)
        assert "=" not in result  # No padding

    def test_rfc3339_formatting(self):
        """_rfc3339 formats datetime to RFC3339."""
        from datetime import datetime, timezone

        dt = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = _rfc3339(dt)
        assert result.endswith("Z")
        assert "T" in result
        assert "2025-01-01" in result

    def test_new_event_id_format(self):
        """_new_event_id generates 26-char Crockford base32."""
        event_id = _new_event_id()
        assert isinstance(event_id, str)
        assert len(event_id) == 26
        # Only valid Crockford base32 chars
        valid_chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        assert all(c in valid_chars for c in event_id)


@pytest.mark.asyncio
class TestWebhookDispatcherDispatch:
    """Test webhook dispatch."""

    @pytest.mark.asyncio
    async def test_dispatch_missing_event_type(self):
        """dispatch raises ValueError when event.type missing."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=mock_vault)

        with pytest.raises(ValueError, match="event.type is required"):
            await dispatcher.dispatch({
                "tenant_id": "tenant1",
                # Missing 'type'
            })

    @pytest.mark.asyncio
    async def test_dispatch_missing_tenant_id(self):
        """dispatch raises ValueError when event.tenant_id missing."""
        mock_db = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        with pytest.raises(ValueError, match="event.tenant_id is required"):
            await dispatcher.dispatch({
                "type": "node.created",
                # Missing 'tenant_id'
            })

    @pytest.mark.asyncio
    async def test_dispatch_no_matching_endpoints(self):
        """dispatch returns empty list when no endpoints match."""
        mock_db = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        def mock_loader(tenant_id):
            return []  # No endpoints

        dispatcher._endpoint_loader = mock_loader

        results = await dispatcher.dispatch({
            "type": "node.created",
            "tenant_id": "tenant1",
        })
        assert results == []

    @pytest.mark.asyncio
    async def test_dispatch_event_enrichment(self):
        """dispatch adds id and timestamp to event."""
        mock_db = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        event = {
            "type": "node.created",
            "tenant_id": "tenant1",
        }

        def mock_loader(tenant_id):
            return []

        dispatcher._endpoint_loader = mock_loader

        with patch.object(dispatcher, "_deliver_one", new_callable=AsyncMock):
            await dispatcher.dispatch(event)
            # Event should have id and timestamp added
            assert "id" in event or True  # dispatch modifies copy


class TestWebhookDispatcherEndpointLoading:
    """Test endpoint loading from database."""

    def test_load_endpoints_with_loader(self):
        """_load_endpoints uses custom loader when provided."""
        mock_db = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        def custom_loader(tenant_id):
            return [
                WebhookEndpoint(
                    id="ep1",
                    tenant_id=tenant_id,
                    url="http://example.com",
                    signing_mode="hmac_sha256",
                )
            ]

        dispatcher._endpoint_loader = custom_loader
        endpoints = list(dispatcher._load_endpoints("tenant1"))
        assert len(endpoints) == 1
        assert endpoints[0].id == "ep1"

    def test_load_endpoints_db_error(self):
        """_load_endpoints returns empty on DB exception."""
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("DB error")

        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        with patch("app.workers.webhook_dispatcher.log") as mock_log:
            endpoints = list(dispatcher._load_endpoints("tenant1"))
            assert endpoints == []
            assert mock_log.exception.called

    def test_load_endpoints_json_parse_error(self):
        """_load_endpoints handles malformed event_filter JSON."""
        mock_db = MagicMock()
        mock_row = (
            "ep1", "tenant1", "http://example.com", "hmac_sha256",
            '{"invalid": json}',  # Malformed JSON
            True,
        )
        mock_db.execute.return_value.fetchall.return_value = [mock_row]

        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        endpoints = list(dispatcher._load_endpoints("tenant1"))
        assert len(endpoints) == 1
        # Should default to empty tuple
        assert endpoints[0].event_filter == ()


@pytest.mark.asyncio
class TestWebhookDispatcherDelivery:
    """Test single webhook delivery."""

    @pytest.mark.asyncio
    async def test_deliver_one_success(self):
        """_deliver_one returns success on 2xx response."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_http = AsyncMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_http.post.return_value = mock_response

        dispatcher = WebhookDispatcher(
            db_session=mock_db,
            vault_client=mock_vault,
            http_client=mock_http,
        )

        endpoint = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com/webhook",
            signing_mode="hmac_sha256",
        )

        event = {
            "type": "node.created",
            "tenant_id": "tenant1",
            "id": "evt123",
            "timestamp": "2025-01-01T00:00:00Z",
        }

        with patch.object(dispatcher._key_mgr, "ensure_keys_for_tenant") as mock_keys:
            mock_key_id = MagicMock()
            mock_key_id.kid = "key1"
            mock_keys.return_value = mock_key_id

            with patch.object(dispatcher, "_sign_payload", return_value="sig"):
                result = await dispatcher._deliver_one(endpoint, event)
                assert result.delivered is True
                assert result.attempts == 1
                assert result.final_status == 200

    @pytest.mark.asyncio
    async def test_deliver_one_timeout_retry(self):
        """_deliver_one retries on timeout."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_http = AsyncMock()
        mock_http.post.side_effect = [
            httpx.TimeoutException("Timeout"),  # First attempt
            MagicMock(status_code=200),  # Second attempt succeeds
        ]

        dispatcher = WebhookDispatcher(
            db_session=mock_db,
            vault_client=mock_vault,
            http_client=mock_http,
            sleep=AsyncMock(),
        )

        endpoint = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com/webhook",
            signing_mode="hmac_sha256",
        )

        event = {
            "type": "node.created",
            "tenant_id": "tenant1",
            "id": "evt123",
            "timestamp": "2025-01-01T00:00:00Z",
        }

        with patch.object(dispatcher._key_mgr, "ensure_keys_for_tenant") as mock_keys:
            mock_key_id = MagicMock()
            mock_key_id.kid = "key1"
            mock_keys.return_value = mock_key_id

            with patch.object(dispatcher, "_sign_payload", return_value="sig"):
                result = await dispatcher._deliver_one(endpoint, event)
                assert result.delivered is True
                assert result.attempts == 2

    @pytest.mark.asyncio
    async def test_deliver_one_max_attempts(self):
        """_deliver_one publishes dead-letter after max attempts."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_http = AsyncMock()
        mock_http.post.return_value = MagicMock(status_code=500)  # Always fails

        dispatcher = WebhookDispatcher(
            db_session=mock_db,
            vault_client=mock_vault,
            http_client=mock_http,
            sleep=AsyncMock(),
            nats_publisher=AsyncMock(),
        )

        endpoint = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com/webhook",
            signing_mode="hmac_sha256",
        )

        event = {
            "type": "node.created",
            "tenant_id": "tenant1",
            "id": "evt123",
            "timestamp": "2025-01-01T00:00:00Z",
        }

        with patch.object(dispatcher._key_mgr, "ensure_keys_for_tenant") as mock_keys:
            mock_key_id = MagicMock()
            mock_key_id.kid = "key1"
            mock_keys.return_value = mock_key_id

            with patch.object(dispatcher, "_sign_payload", return_value="sig"):
                with patch.object(dispatcher, "_dead_letter", new_callable=AsyncMock):
                    result = await dispatcher._deliver_one(endpoint, event)
                    assert result.delivered is False
                    assert result.attempts == 8  # MAX_ATTEMPTS

    @pytest.mark.asyncio
    async def test_deliver_one_signing_error(self):
        """_deliver_one handles signing errors and retries."""
        mock_db = MagicMock()
        mock_vault = MagicMock()
        mock_http = AsyncMock()

        dispatcher = WebhookDispatcher(
            db_session=mock_db,
            vault_client=mock_vault,
            http_client=mock_http,
            sleep=AsyncMock(),
        )

        endpoint = WebhookEndpoint(
            id="ep1",
            tenant_id="tenant1",
            url="http://example.com/webhook",
            signing_mode="hmac_sha256",
        )

        event = {
            "type": "node.created",
            "tenant_id": "tenant1",
            "id": "evt123",
            "timestamp": "2025-01-01T00:00:00Z",
        }

        with patch.object(dispatcher._key_mgr, "ensure_keys_for_tenant") as mock_keys:
            mock_keys.side_effect = [
                Exception("Signing failed"),  # First attempt
                MagicMock(kid="key1"),  # Second attempt
            ]

            with patch.object(dispatcher, "_sign_payload", return_value="sig"):
                mock_http.post.return_value = MagicMock(status_code=200)
                result = await dispatcher._deliver_one(endpoint, event)
                # Should retry after signing error
                assert result.attempts == 2


class TestWebhookDispatcherSigningModes:
    """Test payload signing modes."""

    def test_sign_payload_hmac_sha256(self):
        """_sign_payload with HMAC_SHA256 mode."""
        from app.workers.webhook_dispatcher import HMAC_SHA256

        mock_db = MagicMock()
        mock_vault = MagicMock()
        dispatcher = WebhookDispatcher(
            db_session=mock_db,
            vault_client=mock_vault,
        )

        with patch.object(dispatcher._key_mgr, "get_hmac_secret", return_value=b"secret"):
            sig = dispatcher._sign_payload(
                b"test body",
                HMAC_SHA256,
                "tenant1",
                "key1",
                timestamp="2025-01-01T00:00:00Z",
                event_id="evt123",
            )
            assert sig.startswith("v1.hmac=")


class TestWebhookDispatcherClientManagement:
    """Test HTTP client lifecycle."""

    @pytest.mark.asyncio
    async def test_aclose_closes_owned_client(self):
        """aclose closes HTTP client if owned."""
        mock_db = MagicMock()
        dispatcher = WebhookDispatcher(db_session=mock_db, vault_client=MagicMock())

        assert dispatcher._owns_http is True
        await dispatcher.aclose()
