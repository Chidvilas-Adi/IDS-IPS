"""
routes/threats.py – Threat intelligence, IOC search, geo rules, and IP blocking.
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
threats_bp = Blueprint("threats", __name__, url_prefix="/api/threats")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db():
    from app import db
    return db


def _fetchall(sql: str, params: dict | None = None) -> list[dict]:
    with _db().engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        cols = list(result.keys())
        return [dict(zip(cols, row)) for row in result.fetchall()]


def _fetchone(sql: str, params: dict | None = None) -> dict | None:
    with _db().engine.connect() as conn:
        row = conn.execute(text(sql), params or {}).fetchone()
    return dict(row._mapping) if row else None


def _execute(sql: str, params: dict | None = None):
    with _db().engine.begin() as conn:
        return conn.execute(text(sql), params or {})


def _s(d: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in d.items()}


# ---------------------------------------------------------------------------
# IOC search
# ---------------------------------------------------------------------------


@threats_bp.get("/ioc/search")
@jwt_required()
def ioc_search():
    q = request.args.get("q", "").strip()
    if len(q) < 2:
        return jsonify({"error": "Query must be at least 2 characters"}), 400

    ip_rows = _fetchall(
        "SELECT 'ip' AS ioc_type, id, ip_address AS value, threat_type, confidence, "
        "first_seen, last_seen, active FROM ioc_ip_addresses "
        "WHERE ip_address::text ILIKE :q OR threat_type ILIKE :q LIMIT 50",
        {"q": f"%{q}%"},
    )
    domain_rows = _fetchall(
        "SELECT 'domain' AS ioc_type, id, domain AS value, threat_type, confidence, "
        "first_seen, last_seen, active FROM ioc_domains "
        "WHERE domain ILIKE :q OR threat_type ILIKE :q LIMIT 50",
        {"q": f"%{q}%"},
    )
    hash_rows = _fetchall(
        "SELECT 'hash' AS ioc_type, id, hash_value AS value, hash_type, threat_type, "
        "confidence, first_seen, last_seen, active FROM ioc_file_hashes "
        "WHERE hash_value ILIKE :q OR threat_type ILIKE :q LIMIT 50",
        {"q": f"%{q}%"},
    )

    return jsonify({
        "query": q,
        "total": len(ip_rows) + len(domain_rows) + len(hash_rows),
        "ip": [_s(r) for r in ip_rows],
        "domain": [_s(r) for r in domain_rows],
        "hash": [_s(r) for r in hash_rows],
    })


@threats_bp.get("/ioc/ip/<string:ip>")
@jwt_required()
def ioc_ip_detail(ip: str):
    ioc = _fetchone(
        "SELECT * FROM ioc_ip_addresses WHERE ip_address = :ip", {"ip": ip}
    )
    reputation = _fetchone(
        "SELECT * FROM ip_reputation WHERE ip_address = :ip", {"ip": ip}
    )
    alerts = _fetchall(
        "SELECT id, severity, message, created_at FROM alerts WHERE src_ip = :ip "
        "ORDER BY created_at DESC LIMIT 20",
        {"ip": ip},
    )
    return jsonify({
        "ip": ip,
        "ioc": _s(ioc) if ioc else None,
        "reputation": _s(reputation) if reputation else None,
        "recent_alerts": [_s(a) for a in alerts],
    })


@threats_bp.get("/ioc/domain/<string:domain>")
@jwt_required()
def ioc_domain_detail(domain: str):
    ioc = _fetchone(
        "SELECT * FROM ioc_domains WHERE domain = :domain", {"domain": domain}
    )
    return jsonify({"domain": domain, "ioc": _s(ioc) if ioc else None})


# ---------------------------------------------------------------------------
# Threat feeds
# ---------------------------------------------------------------------------


@threats_bp.get("/feeds")
@jwt_required()
def list_feeds():
    rows = _fetchall(
        "SELECT id, name, url, feed_type, enabled, last_polled, "
        "poll_interval_minutes, record_count FROM threat_feeds ORDER BY name"
    )
    return jsonify([_s(r) for r in rows])


@threats_bp.post("/feeds")
@jwt_required()
def create_feed():
    data = request.get_json(silent=True) or {}
    for f in ["name", "feed_type"]:
        if not data.get(f):
            return jsonify({"error": f"{f} is required"}), 400
    row = _fetchone(
        "INSERT INTO threat_feeds (name, url, feed_type, enabled, poll_interval_minutes, created_at) "
        "VALUES (:name, :url, :ft, :enabled, :interval, NOW()) RETURNING id",
        {
            "name": data["name"], "url": data.get("url"),
            "ft": data["feed_type"], "enabled": data.get("enabled", True),
            "interval": data.get("poll_interval_minutes", 60),
        },
    )
    return jsonify({"id": row["id"]}), 201


@threats_bp.post("/feeds/<int:feed_id>/poll")
@jwt_required()
def poll_feed(feed_id: int):
    feed = _fetchone("SELECT id, name FROM threat_feeds WHERE id = :id", {"id": feed_id})
    if not feed:
        return jsonify({"error": "Feed not found"}), 404
    try:
        from celery_worker import poll_threat_feed_task
        task = poll_threat_feed_task.delay(feed_id)
        return jsonify({"message": "Poll queued", "feed": feed["name"], "task_id": task.id})
    except Exception as exc:
        logger.error("Feed poll trigger failed: %s", exc)
        return jsonify({"error": "Queue unavailable", "detail": str(exc)}), 500


# ---------------------------------------------------------------------------
# IP reputation
# ---------------------------------------------------------------------------


@threats_bp.get("/reputation/<string:ip>")
@jwt_required()
def ip_reputation(ip: str):
    row = _fetchone("SELECT * FROM ip_reputation WHERE ip_address = :ip", {"ip": ip})
    if not row:
        return jsonify({"ip": ip, "data": None, "message": "No reputation data available"}), 200
    return jsonify(_s(row))


# ---------------------------------------------------------------------------
# Geo rules
# ---------------------------------------------------------------------------


@threats_bp.get("/geo-rules")
@jwt_required()
def list_geo_rules():
    rows = _fetchall(
        "SELECT id, country_code, action, direction, severity, enabled, created_at "
        "FROM geo_rules ORDER BY country_code"
    )
    return jsonify([_s(r) for r in rows])


@threats_bp.post("/geo-rules")
@jwt_required()
def create_geo_rule():
    data = request.get_json(silent=True) or {}
    for f in ["country_code", "action"]:
        if not data.get(f):
            return jsonify({"error": f"{f} is required"}), 400
    row = _fetchone(
        "INSERT INTO geo_rules (country_code, action, direction, severity, enabled, created_at) "
        "VALUES (:cc, :action, :direction, :severity, :enabled, NOW()) RETURNING id",
        {
            "cc": data["country_code"].upper(), "action": data["action"],
            "direction": data.get("direction", "inbound"),
            "severity": data.get("severity", "medium"), "enabled": data.get("enabled", True),
        },
    )
    return jsonify({"id": row["id"]}), 201


@threats_bp.delete("/geo-rules/<int:rule_id>")
@jwt_required()
def delete_geo_rule(rule_id: int):
    result = _execute("DELETE FROM geo_rules WHERE id = :id", {"id": rule_id})
    if result.rowcount == 0:
        return jsonify({"error": "Geo rule not found"}), 404
    return jsonify({"message": "Geo rule deleted"})


# ---------------------------------------------------------------------------
# Blocked IPs
# ---------------------------------------------------------------------------


@threats_bp.get("/blocked-ips")
@jwt_required()
def list_blocked_ips():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(500, int(request.args.get("limit", 50)))
    offset = (page - 1) * limit
    total_row = _fetchone("SELECT COUNT(*) AS c FROM blocked_ips WHERE active = true")
    total = total_row["c"] if total_row else 0
    rows = _fetchall(
        "SELECT id, ip_address, reason, blocked_at, unblocked_at, active, blocked_by "
        "FROM blocked_ips WHERE active = true ORDER BY blocked_at DESC LIMIT :limit OFFSET :offset",
        {"limit": limit, "offset": offset},
    )
    return jsonify({"total": total, "page": page, "limit": limit, "items": [_s(r) for r in rows]})


@threats_bp.post("/blocked-ips")
@jwt_required()
def block_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "ip_address is required"}), 400
    row = _fetchone(
        "INSERT INTO blocked_ips (ip_address, reason, blocked_at, active, blocked_by) "
        "VALUES (:ip, :reason, NOW(), true, 'manual') "
        "ON CONFLICT (ip_address) DO UPDATE SET active = true, reason = :reason, blocked_at = NOW() "
        "RETURNING id, blocked_at",
        {"ip": ip, "reason": data.get("reason", "Manual block")},
    )
    return jsonify({"id": row["id"], "ip_address": ip, "blocked_at": row["blocked_at"].isoformat()}), 201


@threats_bp.delete("/blocked-ips/<int:block_id>")
@jwt_required()
def unblock_ip(block_id: int):
    result = _execute(
        "UPDATE blocked_ips SET active = false, unblocked_at = NOW() WHERE id = :id AND active = true",
        {"id": block_id},
    )
    if result.rowcount == 0:
        return jsonify({"error": "Blocked IP not found or already unblocked"}), 404
    return jsonify({"message": "IP unblocked"})
