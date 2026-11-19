"""
routes/alerts.py – Alert and Incident management endpoints.
"""

import logging
import csv
import io
import ipaddress
from datetime import datetime

from flask import Blueprint, jsonify, request, Response
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


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
    ip_types = (
        ipaddress.IPv4Address,
        ipaddress.IPv6Address,
        ipaddress.IPv4Interface,
        ipaddress.IPv6Interface,
        ipaddress.IPv4Network,
        ipaddress.IPv6Network,
    )
    return {
        k: (
            v.isoformat()
            if isinstance(v, datetime)
            else str(v.ip)
            if isinstance(v, (ipaddress.IPv4Interface, ipaddress.IPv6Interface))
            else str(v)
            if isinstance(v, ip_types)
            else v
        )
        for k, v in d.items()
    }


# ---------------------------------------------------------------------------
# Alerts CRUD
# ---------------------------------------------------------------------------


@alerts_bp.get("")
@jwt_required()
def list_alerts():
    severity = request.args.get("severity")
    status = request.args.get("status")
    rule_type = request.args.get("rule_type")
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip") or request.args.get("ip")
    date_from = request.args.get("date_from") or request.args.get("startDate")
    date_to = request.args.get("date_to") or request.args.get("endDate")
    page = max(1, int(request.args.get("page", 1)))
    limit = min(500, int(request.args.get("limit", request.args.get("page_size", 50))))
    offset = (page - 1) * limit

    conditions, params = [], {}
    if severity:
        conditions.append("a.severity = :severity")
        params["severity"] = severity
    if status:
        conditions.append("a.status = :status")
        params["status"] = status
    if rule_type:
        conditions.append("a.rule_type = :rule_type")
        params["rule_type"] = rule_type
    if src_ip:
        conditions.append("(a.src_ip = :src_ip OR a.dst_ip = :src_ip)")
        params["src_ip"] = src_ip
    if protocol:
        conditions.append("a.protocol = :protocol")
        params["protocol"] = protocol
    if date_from:
        conditions.append("a.created_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        conditions.append("a.created_at < CAST(:date_to AS date) + INTERVAL '1 day'")
        params["date_to"] = date_to

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    count_row = _fetchone(
        "SELECT COUNT(*) AS total, "
        "COUNT(*) FILTER (WHERE a.status = 'open') AS open_count, "
        "COUNT(*) FILTER (WHERE a.status = 'acknowledged') AS acknowledged_count, "
        "COUNT(*) FILTER (WHERE UPPER(a.severity) = 'CRITICAL') AS critical_count, "
        "COUNT(*) FILTER (WHERE UPPER(a.severity) = 'HIGH') AS high_count "
        f"FROM alerts a LEFT JOIN rules r ON r.id = a.rule_id {where}",
        params,
    )
    total = count_row["total"] if count_row else 0

    params.update({"limit": limit, "offset": offset})
    rows = _fetchall(
        f"SELECT a.id, a.rule_id, "
        f"COALESCE(r.name, a.packet_summary->>'rule_name', a.rule_type) AS rule_name, "
        f"a.rule_type, a.severity, a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.protocol, "
        f"COALESCE(a.packet_summary->>'description', a.packet_summary->>'signature_name', "
        f"a.packet_summary->>'rule_name', a.rule_type) AS description, "
        f"a.status, a.assigned_to, a.created_at AS timestamp, a.acknowledged_at "
        f"FROM alerts a LEFT JOIN rules r ON r.id = a.rule_id "
        f"{where} ORDER BY a.created_at DESC LIMIT :limit OFFSET :offset",
        params,
    )
    return jsonify({
        "total": total,
        "open": count_row["open_count"] if count_row else 0,
        "acknowledged": count_row["acknowledged_count"] if count_row else 0,
        "critical": count_row["critical_count"] if count_row else 0,
        "high": count_row["high_count"] if count_row else 0,
        "page": page,
        "limit": limit,
        "items": [_s(r) for r in rows],
    })


@alerts_bp.get("/export/csv")
@jwt_required()
def export_alerts_csv():
    conditions, params = [], {}
    for field in ("severity", "status", "rule_type", "protocol"):
        value = request.args.get(field)
        if value:
            conditions.append(f"a.{field} = :{field}")
            params[field] = value
    src_ip = request.args.get("src_ip") or request.args.get("ip")
    if src_ip:
        conditions.append("(a.src_ip = :src_ip OR a.dst_ip = :src_ip)")
        params["src_ip"] = src_ip
    date_from = request.args.get("date_from") or request.args.get("startDate")
    date_to = request.args.get("date_to") or request.args.get("endDate")
    if date_from:
        conditions.append("a.created_at >= :date_from")
        params["date_from"] = date_from
    if date_to:
        conditions.append("a.created_at < CAST(:date_to AS date) + INTERVAL '1 day'")
        params["date_to"] = date_to
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = _fetchall(
        "SELECT id, created_at, severity, status, rule_type, src_ip::text AS src_ip, "
        "dst_ip::text AS dst_ip, src_port, dst_port, protocol "
        f"FROM alerts a {where} ORDER BY created_at DESC LIMIT 10000",
        params,
    )
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]) if rows else [
        "id", "created_at", "severity", "status", "rule_type",
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    ])
    writer.writeheader()
    for row in rows:
        writer.writerow(_s(row))
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@alerts_bp.get("/stats")
@jwt_required()
def alert_stats():
    severity_sql = """
        SELECT severity, COUNT(*) AS count
        FROM alerts
        WHERE created_at >= CURRENT_DATE
        GROUP BY severity
    """
    hourly_sql = """
        SELECT date_trunc('hour', created_at) AS hour, COUNT(*) AS count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY 1 ORDER BY 1
    """
    daily_sql = """
        SELECT DATE(created_at) AS day, COUNT(*) AS count
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY 1 ORDER BY 1
    """
    try:
        severity = _fetchall(severity_sql)
        hourly = _fetchall(hourly_sql)
        daily = _fetchall(daily_sql)
    except Exception as exc:
        logger.error("Alert stats query failed: %s", exc)
        return jsonify({"error": "Stats query failed"}), 500

    return jsonify({
        "by_severity": [_s(r) for r in severity],
        "by_hour": [_s(r) for r in hourly],
        "by_day": [_s(r) for r in daily],
    })


@alerts_bp.get("/<int:alert_id>")
@jwt_required()
def get_alert(alert_id: int):
    row = _fetchone(
        "SELECT a.*, "
        "COALESCE(r.name, a.packet_summary->>'rule_name', a.rule_type) AS rule_name, "
        "COALESCE(a.packet_summary->>'description', a.packet_summary->>'signature_name', "
        "a.packet_summary->>'rule_name', a.rule_type) AS description, "
        "a.created_at AS timestamp FROM alerts a "
        "LEFT JOIN rules r ON r.id = a.rule_id WHERE a.id = :id",
        {"id": alert_id},
    )
    if not row:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(_s(row))


@alerts_bp.patch("/<int:alert_id>/status")
@jwt_required()
def update_alert_status(alert_id: int):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    valid = {"open", "acknowledged", "investigating", "resolved", "false_positive"}
    if new_status not in valid:
        return jsonify({"error": f"status must be one of {valid}"}), 400

    extra_sets, params = [], {"id": alert_id, "status": new_status}
    if new_status == "acknowledged":
        extra_sets.append("acknowledged_at = NOW()")
    if new_status == "resolved":
        extra_sets.append("resolved_at = NOW()")

    sets = ["status = :status"] + extra_sets
    result = _execute(f"UPDATE alerts SET {', '.join(sets)} WHERE id = :id", params)
    if result.rowcount == 0:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"message": "Status updated", "status": new_status})


@alerts_bp.post("/<int:alert_id>/assign")
@jwt_required()
def assign_alert(alert_id: int):
    data = request.get_json(silent=True) or {}
    assignee = data.get("assigned_to")
    if not assignee:
        return jsonify({"error": "assigned_to is required"}), 400
    result = _execute(
        "UPDATE alerts SET assigned_to = :at, status = 'investigating' WHERE id = :id",
        {"at": assignee, "id": alert_id},
    )
    if result.rowcount == 0:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify({"message": f"Alert assigned to {assignee}"})


@alerts_bp.post("/<int:alert_id>/feedback")
@jwt_required()
def feedback(alert_id: int):
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    is_fp = data.get("is_false_positive", False)
    notes = data.get("notes", "")

    _execute(
        "INSERT INTO alert_feedback (alert_id, user_id, is_false_positive, notes, created_at) "
        "VALUES (:aid, :uid, :fp, :notes, NOW()) "
        "ON CONFLICT (alert_id, user_id) DO UPDATE SET is_false_positive = :fp, notes = :notes",
        {"aid": alert_id, "uid": int(identity), "fp": is_fp, "notes": notes},
    )
    if is_fp:
        _execute(
            "UPDATE alerts SET status = 'false_positive' WHERE id = :id",
            {"id": alert_id},
        )
    return jsonify({"message": "Feedback recorded", "is_false_positive": is_fp})


# ---------------------------------------------------------------------------
# Enrichments
# ---------------------------------------------------------------------------


@alerts_bp.get("/<int:alert_id>/enrichments")
@jwt_required()
def get_enrichments(alert_id: int):
    rows = _fetchall(
        "SELECT id, enrichment_type, data, created_at FROM alert_enrichments "
        "WHERE alert_id = :id ORDER BY created_at DESC",
        {"id": alert_id},
    )
    return jsonify([_s(r) for r in rows])


@alerts_bp.post("/<int:alert_id>/enrich")
@jwt_required()
def trigger_enrichment(alert_id: int):
    alert = _fetchone("SELECT id, src_ip FROM alerts WHERE id = :id", {"id": alert_id})
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    try:
        from celery_worker import enrich_alert_task
        task = enrich_alert_task.delay(alert_id, alert.get("src_ip"))
        return jsonify({"message": "Enrichment queued", "task_id": task.id})
    except Exception as exc:
        logger.error("Enrichment trigger failed: %s", exc)
        return jsonify({"error": "Enrichment queue unavailable", "detail": str(exc)}), 500


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

incidents_bp = Blueprint("incidents", __name__, url_prefix="/api/incidents")


@incidents_bp.get("")
@jwt_required()
def list_incidents():
    status = request.args.get("status")
    severity = request.args.get("severity")
    page = max(1, int(request.args.get("page", 1)))
    limit = min(200, int(request.args.get("limit", 25)))
    offset = (page - 1) * limit

    conditions, params = [], {"limit": limit, "offset": offset}
    if status:
        conditions.append("status = :status"); params["status"] = status
    if severity:
        conditions.append("severity = :severity"); params["severity"] = severity

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    count_row = _fetchone(f"SELECT COUNT(*) AS c FROM incidents {where}", {k: v for k, v in params.items() if k not in ("limit", "offset")})
    total = count_row["c"] if count_row else 0

    rows = _fetchall(
        f"SELECT id, title, description, severity, status, assigned_to, created_at, updated_at, resolved_at "
        f"FROM incidents {where} ORDER BY created_at DESC LIMIT :limit OFFSET :offset",
        params,
    )
    return jsonify({"total": total, "page": page, "limit": limit, "items": [_s(r) for r in rows]})


@incidents_bp.post("")
@jwt_required()
def create_incident():
    data = request.get_json(silent=True) or {}
    if not data.get("title"):
        return jsonify({"error": "title is required"}), 400
    row = _fetchone(
        "INSERT INTO incidents (title, description, severity, status, assigned_to, created_at, updated_at) "
        "VALUES (:title, :desc, :severity, 'open', :assigned_to, NOW(), NOW()) RETURNING id, created_at",
        {
            "title": data["title"], "desc": data.get("description"),
            "severity": data.get("severity", "medium"), "assigned_to": data.get("assigned_to"),
        },
    )
    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201


@incidents_bp.get("/<int:incident_id>")
@jwt_required()
def get_incident(incident_id: int):
    row = _fetchone("SELECT * FROM incidents WHERE id = :id", {"id": incident_id})
    if not row:
        return jsonify({"error": "Incident not found"}), 404
    timeline = _fetchall(
        "SELECT id, event_type, detail, created_at, created_by FROM incident_timeline "
        "WHERE incident_id = :id ORDER BY created_at ASC",
        {"id": incident_id},
    )
    result = _s(row)
    result["timeline"] = [_s(t) for t in timeline]
    return jsonify(result)


@incidents_bp.post("/<int:incident_id>/timeline")
@jwt_required()
def add_timeline_event(incident_id: int):
    identity = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    if not data.get("event_type"):
        return jsonify({"error": "event_type is required"}), 400

    incident = _fetchone("SELECT id FROM incidents WHERE id = :id", {"id": incident_id})
    if not incident:
        return jsonify({"error": "Incident not found"}), 404

    row = _fetchone(
        "INSERT INTO incident_timeline (incident_id, event_type, detail, created_at, created_by) "
        "VALUES (:iid, :et, :detail, NOW(), :uid) RETURNING id, created_at",
        {
            "iid": incident_id, "et": data["event_type"],
            "detail": data.get("detail"), "uid": int(identity),
        },
    )
    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201
