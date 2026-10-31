"""
routes/auth.py – Authentication endpoints.

Provides JWT login/refresh/logout, current-user info, and API-key CRUD.
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from sqlalchemy import text

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db():
    from app import db
    return db


def _query_one(sql: str, params: dict):
    with _db().engine.connect() as conn:
        row = conn.execute(text(sql), params).fetchone()
    return dict(row._mapping) if row else None


def _execute(sql: str, params: dict):
    with _db().engine.begin() as conn:
        result = conn.execute(text(sql), params)
    return result


def _verify_password(plain: str, hashed: str) -> bool:
    """SHA-256 password verification (production should use bcrypt)."""
    return hashlib.sha256(plain.encode()).hexdigest() == hashed


def _hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


def _generate_api_key() -> tuple[str, str]:
    """Return (raw_key, hashed_key)."""
    from config import get_config
    cfg = get_config()
    raw = cfg.API_KEY_PREFIX + secrets.token_hex(cfg.API_KEY_BYTES)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def _audit(user_id: int, action: str, detail: str | None = None):
    try:
        _execute(
            "INSERT INTO audit_log (user_id, action, detail, created_at) "
            "VALUES (:uid, :action, :detail, NOW())",
            {"uid": user_id, "action": action, "detail": detail},
        )
    except Exception as exc:
        logger.warning("Audit log insert failed: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = _query_one(
        "SELECT id, username, password_hash, role, active FROM users WHERE username = :u",
        {"u": username},
    )

    if not user or not user["active"] or not _verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid credentials"}), 401

    identity = str(user["id"])
    additional = {"username": user["username"], "role": user["role"]}
    access_token = create_access_token(identity=identity, additional_claims=additional)
    refresh_token = create_refresh_token(identity=identity, additional_claims=additional)

    _audit(user["id"], "login", f"source_ip={request.remote_addr}")

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }
    )


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    claims = get_jwt()
    access_token = create_access_token(
        identity=identity,
        additional_claims={"username": claims.get("username"), "role": claims.get("role")},
    )
    return jsonify({"access_token": access_token, "token_type": "bearer"})


@auth_bp.post("/logout")
@jwt_required()
def logout():
    """
    Stateless JWT – instruct client to discard tokens.
    For full token revocation, add jti to a Redis blocklist here.
    """
    identity = get_jwt_identity()
    _audit(int(identity), "logout", None)
    return jsonify({"message": "Logged out successfully"})


@auth_bp.get("/me")
@jwt_required()
def me():
    identity = get_jwt_identity()
    user = _query_one(
        "SELECT id, username, role, email, created_at FROM users WHERE id = :id",
        {"id": int(identity)},
    )
    if not user:
        return jsonify({"error": "User not found"}), 404
    user["created_at"] = user["created_at"].isoformat() if user.get("created_at") else None
    return jsonify(user)


# ── API Keys ─────────────────────────────────────────────────────────────


@auth_bp.post("/api-keys")
@jwt_required()
def create_api_key():
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    label = data.get("label", "unnamed")
    raw_key, hashed_key = _generate_api_key()

    with _db().engine.begin() as conn:
        result = conn.execute(
            text(
                "INSERT INTO api_keys (user_id, label, key_hash, created_at, active) "
                "VALUES (:uid, :label, :kh, NOW(), true) RETURNING id, created_at"
            ),
            {"uid": int(identity), "label": label, "kh": hashed_key},
        )
        row = result.fetchone()

    _audit(int(identity), "create_api_key", f"label={label}")

    return jsonify(
        {
            "id": row[0],
            "label": label,
            "key": raw_key,  # shown only once
            "created_at": row[1].isoformat(),
        }
    ), 201


@auth_bp.get("/api-keys")
@jwt_required()
def list_api_keys():
    identity = get_jwt_identity()
    with _db().engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, label, created_at, last_used_at, active "
                "FROM api_keys WHERE user_id = :uid ORDER BY created_at DESC"
            ),
            {"uid": int(identity)},
        ).fetchall()
    keys = [
        {
            "id": r[0],
            "label": r[1],
            "created_at": r[2].isoformat() if r[2] else None,
            "last_used_at": r[3].isoformat() if r[3] else None,
            "active": r[4],
        }
        for r in rows
    ]
    return jsonify(keys)


@auth_bp.delete("/api-keys/<int:key_id>")
@jwt_required()
def delete_api_key(key_id: int):
    identity = get_jwt_identity()
    with _db().engine.begin() as conn:
        result = conn.execute(
            text(
                "DELETE FROM api_keys WHERE id = :kid AND user_id = :uid"
            ),
            {"kid": key_id, "uid": int(identity)},
        )
    if result.rowcount == 0:
        return jsonify({"error": "API key not found"}), 404
    _audit(int(identity), "delete_api_key", f"key_id={key_id}")
    return jsonify({"message": "API key deleted"})
