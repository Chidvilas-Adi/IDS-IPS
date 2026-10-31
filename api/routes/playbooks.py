"""
routes/playbooks.py – SOAR playbook management and execution endpoints.
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
playbooks_bp = Blueprint("playbooks", __name__, url_prefix="/api/playbooks")


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
# Playbook CRUD
# ---------------------------------------------------------------------------


@playbooks_bp.get("")
@jwt_required()
def list_playbooks():
    rows = _fetchall(
        "SELECT id, name, description, trigger_severity, trigger_rule_type, enabled, created_at, updated_at "
        "FROM playbooks ORDER BY name"
    )
    return jsonify([_s(r) for r in rows])


@playbooks_bp.post("")
@jwt_required()
def create_playbook():
    data = request.get_json(silent=True) or {}
    if not data.get("name"):
        return jsonify({"error": "name is required"}), 400
    row = _fetchone(
        "INSERT INTO playbooks (name, description, trigger_severity, trigger_rule_type, enabled, created_at, updated_at) "
        "VALUES (:name, :desc, :tsev, :trt, :enabled, NOW(), NOW()) RETURNING id, created_at",
        {
            "name": data["name"], "desc": data.get("description"),
            "tsev": data.get("trigger_severity"), "trt": data.get("trigger_rule_type"),
            "enabled": data.get("enabled", True),
        },
    )
    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201


@playbooks_bp.get("/<int:playbook_id>")
@jwt_required()
def get_playbook(playbook_id: int):
    row = _fetchone("SELECT * FROM playbooks WHERE id = :id", {"id": playbook_id})
    if not row:
        return jsonify({"error": "Playbook not found"}), 404
    steps = _fetchall(
        "SELECT id, step_order, action_type, action_params, condition, on_success, on_failure "
        "FROM playbook_steps WHERE playbook_id = :id ORDER BY step_order",
        {"id": playbook_id},
    )
    result = _s(row)
    result["steps"] = [_s(s) for s in steps]
    return jsonify(result)


@playbooks_bp.put("/<int:playbook_id>")
@jwt_required()
def update_playbook(playbook_id: int):
    data = request.get_json(silent=True) or {}
    sets, params = ["updated_at = NOW()"], {"id": playbook_id}
    for field in ["name", "description", "trigger_severity", "trigger_rule_type", "enabled"]:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]
    result = _execute(f"UPDATE playbooks SET {', '.join(sets)} WHERE id = :id", params)
    if result.rowcount == 0:
        return jsonify({"error": "Playbook not found"}), 404
    return jsonify({"message": "Playbook updated"})


@playbooks_bp.delete("/<int:playbook_id>")
@jwt_required()
def delete_playbook(playbook_id: int):
    _execute("DELETE FROM playbook_steps WHERE playbook_id = :id", {"id": playbook_id})
    result = _execute("DELETE FROM playbooks WHERE id = :id", {"id": playbook_id})
    if result.rowcount == 0:
        return jsonify({"error": "Playbook not found"}), 404
    return jsonify({"message": "Playbook deleted"})


# ---------------------------------------------------------------------------
# Playbook steps
# ---------------------------------------------------------------------------


@playbooks_bp.get("/<int:playbook_id>/steps")
@jwt_required()
def list_steps(playbook_id: int):
    rows = _fetchall(
        "SELECT id, playbook_id, step_order, action_type, action_params, "
        "condition, on_success, on_failure FROM playbook_steps "
        "WHERE playbook_id = :id ORDER BY step_order",
        {"id": playbook_id},
    )
    return jsonify([_s(r) for r in rows])


@playbooks_bp.post("/<int:playbook_id>/steps")
@jwt_required()
def add_step(playbook_id: int):
    pb = _fetchone("SELECT id FROM playbooks WHERE id = :id", {"id": playbook_id})
    if not pb:
        return jsonify({"error": "Playbook not found"}), 404

    data = request.get_json(silent=True) or {}
    if not data.get("action_type"):
        return jsonify({"error": "action_type is required"}), 400

    import json as _json
    params_json = (
        _json.dumps(data["action_params"])
        if isinstance(data.get("action_params"), dict)
        else data.get("action_params", "{}")
    )

    # Auto-assign step_order
    max_row = _fetchone(
        "SELECT COALESCE(MAX(step_order), 0) AS m FROM playbook_steps WHERE playbook_id = :id",
        {"id": playbook_id},
    )
    next_order = (max_row["m"] if max_row else 0) + 1

    row = _fetchone(
        "INSERT INTO playbook_steps (playbook_id, step_order, action_type, action_params, "
        "condition, on_success, on_failure) "
        "VALUES (:pid, :order, :at, :params::jsonb, :cond, :ons, :onf) RETURNING id",
        {
            "pid": playbook_id, "order": data.get("step_order", next_order),
            "at": data["action_type"], "params": params_json,
            "cond": data.get("condition"), "ons": data.get("on_success", "continue"),
            "onf": data.get("on_failure", "stop"),
        },
    )
    return jsonify({"id": row["id"]}), 201


@playbooks_bp.put("/<int:playbook_id>/steps/<int:step_id>")
@jwt_required()
def update_step(playbook_id: int, step_id: int):
    data = request.get_json(silent=True) or {}
    import json as _json
    sets, params = [], {"id": step_id, "pid": playbook_id}
    for field in ["step_order", "action_type", "condition", "on_success", "on_failure"]:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]
    if "action_params" in data:
        sets.append("action_params = :action_params::jsonb")
        params["action_params"] = (
            _json.dumps(data["action_params"])
            if isinstance(data["action_params"], dict)
            else data["action_params"]
        )
    if not sets:
        return jsonify({"error": "No fields to update"}), 400
    result = _execute(
        f"UPDATE playbook_steps SET {', '.join(sets)} WHERE id = :id AND playbook_id = :pid",
        params,
    )
    if result.rowcount == 0:
        return jsonify({"error": "Step not found"}), 404
    return jsonify({"message": "Step updated"})


@playbooks_bp.delete("/<int:playbook_id>/steps/<int:step_id>")
@jwt_required()
def delete_step(playbook_id: int, step_id: int):
    result = _execute(
        "DELETE FROM playbook_steps WHERE id = :id AND playbook_id = :pid",
        {"id": step_id, "pid": playbook_id},
    )
    if result.rowcount == 0:
        return jsonify({"error": "Step not found"}), 404
    return jsonify({"message": "Step deleted"})


# ---------------------------------------------------------------------------
# Playbook execution
# ---------------------------------------------------------------------------


@playbooks_bp.post("/<int:playbook_id>/execute")
@jwt_required()
def execute_playbook(playbook_id: int):
    data = request.get_json(silent=True) or {}
    alert_id = data.get("alert_id")
    if not alert_id:
        return jsonify({"error": "alert_id is required"}), 400

    pb = _fetchone("SELECT id, name, enabled FROM playbooks WHERE id = :id", {"id": playbook_id})
    if not pb:
        return jsonify({"error": "Playbook not found"}), 404
    if not pb["enabled"]:
        return jsonify({"error": "Playbook is disabled"}), 400

    try:
        from celery_worker import execute_playbook_task
        task = execute_playbook_task.delay(playbook_id, alert_id)
        return jsonify({
            "message": "Playbook execution queued",
            "playbook": pb["name"],
            "alert_id": alert_id,
            "task_id": task.id,
        })
    except Exception as exc:
        logger.error("Playbook execution queue failed: %s", exc)
        return jsonify({"error": "Queue unavailable", "detail": str(exc)}), 500


# ---------------------------------------------------------------------------
# Executions log
# ---------------------------------------------------------------------------


@playbooks_bp.get("/executions")
@jwt_required()
def list_executions():
    page = max(1, int(request.args.get("page", 1)))
    limit = min(200, int(request.args.get("limit", 25)))
    offset = (page - 1) * limit
    rows = _fetchall(
        "SELECT pe.id, pe.playbook_id, p.name AS playbook_name, pe.alert_id, pe.status, "
        "pe.started_at, pe.finished_at, pe.error_message "
        "FROM playbook_executions pe JOIN playbooks p ON p.id = pe.playbook_id "
        "ORDER BY pe.started_at DESC LIMIT :limit OFFSET :offset",
        {"limit": limit, "offset": offset},
    )
    count_row = _fetchone("SELECT COUNT(*) AS c FROM playbook_executions")
    return jsonify({
        "total": count_row["c"] if count_row else 0,
        "page": page,
        "limit": limit,
        "items": [_s(r) for r in rows],
    })


@playbooks_bp.get("/executions/<int:exec_id>")
@jwt_required()
def get_execution(exec_id: int):
    row = _fetchone(
        "SELECT pe.*, p.name AS playbook_name FROM playbook_executions pe "
        "JOIN playbooks p ON p.id = pe.playbook_id WHERE pe.id = :id",
        {"id": exec_id},
    )
    if not row:
        return jsonify({"error": "Execution not found"}), 404
    step_logs = _fetchall(
        "SELECT id, step_id, status, output, error, started_at, finished_at "
        "FROM playbook_step_logs WHERE execution_id = :id ORDER BY started_at",
        {"id": exec_id},
    )
    result = _s(row)
    result["step_logs"] = [_s(s) for s in step_logs]
    return jsonify(result)


# ---------------------------------------------------------------------------
# Action templates
# ---------------------------------------------------------------------------

_ACTION_TEMPLATES = [
    {
        "type": "block_ip",
        "label": "Block IP Address",
        "params_schema": {
            "ip_field": {"type": "string", "description": "Alert field to extract IP from (src_ip/dst_ip)", "default": "src_ip"},
            "duration_hours": {"type": "integer", "description": "Block duration in hours (0 = permanent)", "default": 24},
        },
    },
    {
        "type": "send_notification",
        "label": "Send Notification",
        "params_schema": {
            "channel": {"type": "string", "enum": ["email", "slack", "pagerduty", "webhook"], "default": "email"},
            "recipients": {"type": "array", "items": {"type": "string"}},
            "template": {"type": "string", "description": "Message template name"},
        },
    },
    {
        "type": "create_ticket",
        "label": "Create SIEM Ticket",
        "params_schema": {
            "system": {"type": "string", "enum": ["jira", "servicenow", "github"], "default": "jira"},
            "project": {"type": "string"},
            "priority": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        },
    },
    {
        "type": "enrich_ip",
        "label": "Enrich IP Reputation",
        "params_schema": {
            "ip_field": {"type": "string", "default": "src_ip"},
            "sources": {"type": "array", "items": {"type": "string"}, "default": ["abuseipdb", "virustotal"]},
        },
    },
    {
        "type": "capture_packets",
        "label": "Capture Packets",
        "params_schema": {
            "duration_seconds": {"type": "integer", "default": 30},
            "filter": {"type": "string", "description": "BPF filter expression"},
        },
    },
    {
        "type": "kill_session",
        "label": "Kill TCP Session (RST)",
        "params_schema": {
            "session_id_field": {"type": "string", "default": "session_id"},
        },
    },
    {
        "type": "run_script",
        "label": "Run Custom Script",
        "params_schema": {
            "script": {"type": "string", "description": "Script path on the sensor"},
            "args": {"type": "array", "items": {"type": "string"}},
            "timeout_seconds": {"type": "integer", "default": 60},
        },
    },
]


@playbooks_bp.get("/action-templates")
@jwt_required()
def action_templates():
    return jsonify(_ACTION_TEMPLATES)
