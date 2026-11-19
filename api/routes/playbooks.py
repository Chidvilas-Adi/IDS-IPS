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
        "SELECT id, name, description, trigger_severity, trigger_rule_type, auto_execute, enabled, created_at "
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
        "INSERT INTO playbooks (name, description, trigger_severity, trigger_rule_type, auto_execute, enabled, created_at) "
        "VALUES (:name, :desc, :tsev, :trt, :auto_execute, :enabled, NOW()) RETURNING id, created_at",
        {
            "name": data["name"], "desc": data.get("description"),
            "tsev": data.get("trigger_severity"), "trt": data.get("trigger_rule_type"),
            "auto_execute": data.get("auto_execute", False),
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
        "SELECT ps.id, ps.step_order, ps.action_template_id, at.name AS action_type, "
        "ps.parameters AS action_params, ps.wait_seconds_after, ps.continue_on_failure "
        "FROM playbook_steps ps "
        "LEFT JOIN action_templates at ON at.id = ps.action_template_id "
        "WHERE ps.playbook_id = :id ORDER BY ps.step_order",
        {"id": playbook_id},
    )
    result = _s(row)
    result["steps"] = [_s(s) for s in steps]
    return jsonify(result)


@playbooks_bp.put("/<int:playbook_id>")
@jwt_required()
def update_playbook(playbook_id: int):
    data = request.get_json(silent=True) or {}
    sets, params = [], {"id": playbook_id}
    for field in ["name", "description", "trigger_severity", "trigger_rule_type", "auto_execute", "enabled"]:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]
    if not sets:
        return jsonify({"error": "No fields to update"}), 400
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
        "SELECT ps.id, ps.playbook_id, ps.step_order, ps.action_template_id, "
        "at.name AS action_type, ps.parameters AS action_params, "
        "ps.wait_seconds_after, ps.continue_on_failure "
        "FROM playbook_steps ps "
        "LEFT JOIN action_templates at ON at.id = ps.action_template_id "
        "WHERE ps.playbook_id = :id ORDER BY ps.step_order",
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
    action_template_id = data.get("action_template_id")
    if action_template_id is None and data.get("action_type"):
        action_template = _fetchone(
            "SELECT id FROM action_templates WHERE enabled IS TRUE AND "
            "(UPPER(name) = UPPER(:type) OR UPPER(action_type) = UPPER(:type)) "
            ") LIMIT 1",
            {"type": data["action_type"]},
        )
        action_template_id = action_template["id"] if action_template else None
    elif action_template_id is not None:
        action_template = _fetchone(
            "SELECT id FROM action_templates WHERE id = :id AND enabled IS TRUE",
            {"id": action_template_id},
        )
        if not action_template:
            return jsonify({"error": "Action template not found or disabled"}), 400
    if action_template_id is None:
        return jsonify({"error": "A valid action_template_id or action_type is required"}), 400

    import json as _json
    params_json = (
        _json.dumps(data["parameters"])
        if isinstance(data.get("parameters"), dict)
        else data.get("parameters", "{}")
    )

    # Auto-assign step_order
    max_row = _fetchone(
        "SELECT COALESCE(MAX(step_order), 0) AS m FROM playbook_steps WHERE playbook_id = :id",
        {"id": playbook_id},
    )
    next_order = (max_row["m"] if max_row else 0) + 1

    row = _fetchone(
        "INSERT INTO playbook_steps (playbook_id, step_order, action_template_id, parameters, "
        "wait_seconds_after, continue_on_failure) "
        "VALUES (:pid, :order, :template_id, CAST(:params AS jsonb), :wait, :continue) RETURNING id",
        {
            "pid": playbook_id, "order": data.get("step_order", next_order),
            "template_id": action_template_id, "params": params_json,
            "wait": data.get("wait_seconds_after", 0),
            "continue": data.get("continue_on_failure", False),
        },
    )
    return jsonify({"id": row["id"]}), 201


@playbooks_bp.put("/<int:playbook_id>/steps/<int:step_id>")
@jwt_required()
def update_step(playbook_id: int, step_id: int):
    data = request.get_json(silent=True) or {}
    import json as _json
    sets, params = [], {"id": step_id, "pid": playbook_id}
    for field in ["step_order", "action_template_id", "wait_seconds_after", "continue_on_failure"]:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]
    if "parameters" in data:
        sets.append("parameters = CAST(:parameters AS jsonb)")
        params["parameters"] = (
            _json.dumps(data["parameters"])
            if isinstance(data["parameters"], dict)
            else data["parameters"]
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
        "pe.started_at, pe.completed_at, pe.step_results, pe.error_message "
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
    result = _s(row)
    return jsonify(result)


@playbooks_bp.get("/action-templates")
@jwt_required()
def action_templates():
    rows = _fetchall(
        "SELECT id, name, action_type, description, parameters "
        "FROM action_templates WHERE enabled IS TRUE ORDER BY name"
    )
    return jsonify([_s(row) for row in rows])
