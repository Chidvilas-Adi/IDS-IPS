"""
routes/stats.py – High-performance analytical stats for the live dashboard.
"""

import logging
from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
stats_bp = Blueprint("stats", __name__, url_prefix="/api/stats")

def _db():
    from app import db
    return db

def _fetchall(sql: str, params: dict = None) -> list:
    with _db().engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        cols = list(result.keys())
        return [dict(zip(cols, row)) for row in result.fetchall()]

def _scalar(sql: str, params: dict = None):
    with _db().engine.connect() as conn:
        return conn.execute(text(sql), params or {}).scalar() or 0

@stats_bp.route("/overview", methods=["GET"])
@jwt_required(optional=True)
def get_overview():
    total_alerts = _scalar("SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours'")
    blocked_count = _scalar("SELECT COUNT(*) FROM blocked_ips WHERE active = true")
    active_sessions = _scalar("SELECT COUNT(*) FROM sessions WHERE last_seen_at >= NOW() - INTERVAL '15 minutes'")
    avg_threat_score = _scalar("SELECT AVG(score) FROM ip_reputation WHERE score > 0")

    return jsonify({
        "alerts_today": total_alerts,
        "blocked_ips": blocked_count,
        "active_sessions": active_sessions,
        "threat_score": round(float(avg_threat_score), 1),
        "engine_health": "UP"
    })

@stats_bp.route("/alerts/timeseries", methods=["GET"])
@jwt_required(optional=True)
def get_alerts_timeseries():
    sql = """
        SELECT to_char(date_trunc('hour', created_at), 'YYYY-MM-DD HH24:00') as time_slot,
               COUNT(*) as count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY 1
        ORDER BY 1 ASC
    """
    rows = _fetchall(sql)
    return jsonify({"timeseries": rows})

@stats_bp.route("/top-attackers", methods=["GET"])
@jwt_required(optional=True)
def get_top_attackers():
    sql = """
        SELECT src_ip::text, COUNT(*) as alert_count, MAX(severity) as max_severity
        FROM alerts
        GROUP BY src_ip
        ORDER BY alert_count DESC LIMIT 5
    """
    return jsonify({"attackers": _fetchall(sql)})

@stats_bp.route("/protocol-breakdown", methods=["GET"])
@jwt_required(optional=True)
def get_protocol_breakdown():
    sql = """
        SELECT COALESCE(protocol, 'OTHER') as name, COUNT(*) as value
        FROM sessions
        GROUP BY 1
        ORDER BY value DESC LIMIT 8
    """
    return jsonify({"protocols": _fetchall(sql)})

@stats_bp.route("/severity-distribution", methods=["GET"])
@jwt_required(optional=True)
def get_severity_distribution():
    sql = """
        SELECT severity as name, COUNT(*) as value
        FROM alerts
        GROUP BY severity
    """
    return jsonify({"severities": _fetchall(sql)})
