"""
routes/compliance.py – Automated PCI-DSS/HIPAA verification, compliance checks, and audit trails.
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
compliance_bp = Blueprint("compliance", __name__, url_prefix="/api/compliance")

def _db():
    from app import db
    return db

def _fetchall(sql: str, params: dict = None) -> list:
    with _db().engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        cols = list(result.keys())
        return [dict(zip(cols, row)) for row in result.fetchall()]

@compliance_bp.route("/checks", methods=["GET"])
@jwt_required(optional=True)
def list_checks():
    framework = request.args.get("framework")
    sql = "SELECT id, framework, check_name, description, severity, last_run_at, last_status, last_result FROM compliance_checks"
    params = {}
    if framework:
        sql += " WHERE UPPER(framework) = UPPER(:fw)"
        params["fw"] = framework
    rows = _fetchall(sql, params)
    for r in rows:
        if r.get("last_run_at"):
            r["last_run_at"] = r["last_run_at"].isoformat()
    return jsonify({"checks": rows})

@compliance_bp.route("/checks/run", methods=["POST"])
@jwt_required()
def run_all_checks():
    sql = "SELECT id, check_name, check_query, expected_result FROM compliance_checks"
    checks = _fetchall(sql)
    results = []

    with _db().engine.begin() as conn:
        for c in checks:
            status = "PASS"
            result_val = None
            try:
                res = conn.execute(text(c["check_query"])).scalar()
                result_val = res
                min_cnt = c.get("expected_result", {}).get("min_count", 0)
                if res < min_cnt:
                    status = "FAIL"
            except Exception as e:
                status = "ERROR"
                result_val = str(e)

            conn.execute(
                text("UPDATE compliance_checks SET last_run_at = NOW(), last_status = :st, last_result = :res WHERE id = :id"),
                {"st": status, "res": f'{{"value": "{result_val}"}}', "id": c["id"]}
            )
            results.append({"id": c["id"], "name": c["check_name"], "status": status, "value": result_val})

    return jsonify({"results": results, "timestamp": datetime.utcnow().isoformat()})

@compliance_bp.route("/audit-log", methods=["GET"])
@jwt_required(optional=True)
def list_audit_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    sql = """
        SELECT id, actor, actor_type, action, table_name, record_id, ip_address::text, created_at
        FROM audit_log ORDER BY created_at DESC LIMIT :limit
    """
    rows = _fetchall(sql, {"limit": limit})
    for r in rows:
        if r.get("created_at"):
            r["created_at"] = r["created_at"].isoformat()
    return jsonify({"audit_logs": rows, "count": len(rows)})
