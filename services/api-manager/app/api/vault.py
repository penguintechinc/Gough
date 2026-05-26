"""Vault key management endpoints.

POST /api/v1/vault/rotate-keys — operator-triggered key rotation
"""

from datetime import datetime
from quart import Blueprint, current_app, jsonify, request, g
from sqlalchemy import text
from prometheus_client import Counter

# Prometheus metrics
vault_key_rotation_total = Counter(
    "gough_vault_key_rotation_total",
    "Key rotation events",
    ["rotation_class"],
)

vault_bp = Blueprint("vault", __name__)


@vault_bp.route("/rotate-keys", methods=["POST"])
async def rotate_keys():
    """Operator-triggered key rotation endpoint.

    Requires scope: gough.cluster.superadmin

    Request body (JSON):
    {
      "rotation_class": "joiner",  # optional, defaults to "joiner"
      "reason": "scheduled"         # optional, for audit logging
    }

    Response:
    {
      "rotated": true,
      "rotation_class": "joiner",
      "revoked_count": 5
    }
    """
    # TODO: Add scope validation once auth middleware is available
    # For now, assume the request is authenticated via middleware

    data = await request.get_json()
    if not data:
        data = {}

    rotation_class = data.get("rotation_class", "joiner").strip()
    reason = data.get("reason", "operator-triggered").strip()

    if not rotation_class:
        return jsonify({"error": "rotation_class is required"}), 400

    # Get database session from g
    try:
        db = g.db
    except (AttributeError, RuntimeError):
        return jsonify({"error": "Database not available"}), 503

    try:
        # Revoke all active joiner secrets of the given rotation class
        # Query: UPDATE joiner_secrets SET revoked=TRUE WHERE rotation_class=:class AND used_at IS NULL AND expires_at > NOW()
        stmt = text("""
            UPDATE joiner_secrets
            SET revoked = TRUE, updated_at = :now
            WHERE rotation_class = :rotation_class
              AND used_at IS NULL
              AND expires_at > :now
        """)

        result = db.engine.execute(
            stmt,
            rotation_class=rotation_class,
            now=datetime.utcnow(),
        )

        revoked_count = result.rowcount

        # Log audit event via AuditEventWriter if available
        try:
            from ..audit import get_audit_logger
            audit_logger = get_audit_logger()
            if audit_logger:
                audit_logger.log_event(
                    event_type="vault.key_rotation",
                    resource_type="vault",
                    resource_id=rotation_class,
                    action="rotate",
                    status="success",
                    details={
                        "rotation_class": rotation_class,
                        "reason": reason,
                        "revoked_count": revoked_count,
                    },
                )
        except Exception as e:
            current_app.logger.warning("Failed to log audit event: %s", e)

        # Increment Prometheus counter
        vault_key_rotation_total.labels(rotation_class=rotation_class).inc()

        return jsonify({
            "rotated": True,
            "rotation_class": rotation_class,
            "revoked_count": revoked_count,
        }), 200

    except Exception as e:
        current_app.logger.error("Key rotation failed: %s", e)
        return jsonify({"error": "rotation_failed"}), 500
