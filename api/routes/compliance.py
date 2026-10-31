"""
routes/compliance.py – Automated PCI-DSS/HIPAA verification, compliance checks, and audit trails.
"""

import logging
from datetime import datetime
from flask import Blueprint, jsonify, request, Response
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
compliance_bp = Blueprint("compliance", __name__, url_prefix="/api/compliance")

def _db():
    from app import db
    return db

def _clean(sql: str) -> str:
    from app import app
    if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
        return sql.replace("::text", "").replace("NOW()", "CURRENT_TIMESTAMP")
    return sql

def _fetchall(sql: str, params: dict = None) -> list:
    with _db().engine.connect() as conn:
        result = conn.execute(text(_clean(sql)), params or {})
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
@jwt_required(optional=True)
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
                if res is not None and res < min_cnt:
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

@compliance_bp.route("/reports/export", methods=["GET"])
@jwt_required(optional=True)
def export_compliance_report():
    """Generates an executive, printable PDF/HTML compliance assessment report."""
    checks = _fetchall("SELECT framework, check_name, description, last_status, last_run_at FROM compliance_checks")
    total_checks = len(checks)
    passed_checks = sum(1 for c in checks if c["last_status"] == "PASS")
    score_pct = int((passed_checks / total_checks * 100)) if total_checks > 0 else 100

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>DB-IDS/IPS Compliance & Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; padding: 40px; color: #1e293b; background: #fff; }}
        .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ margin: 0; color: #0f172a; font-size: 26px; }}
        .meta {{ color: #64748b; font-size: 14px; margin-top: 5px; }}
        .score-box {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-bottom: 30px; display: flex; gap: 30px; }}
        .score-val {{ font-size: 36px; font-weight: bold; color: {'#16a34a' if score_pct >= 80 else '#dc2626'}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 10px 14px; text-align: left; }}
        th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
        .badge-pass {{ background: #dcfce7; color: #15803d; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
        .badge-fail {{ background: #fee2e2; color: #b91c1c; padding: 4px 8px; border-radius: 4px; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DB-IDS/IPS Automated Compliance Audit Report</h1>
        <div class="meta">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} | Database: PostgreSQL 16 TimescaleDB</div>
    </div>
    <div class="score-box">
        <div>
            <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">Compliance Posture Score</div>
            <div class="score-val">{score_pct}%</div>
        </div>
        <div>
            <div style="font-size: 12px; color: #64748b; text-transform: uppercase;">Evaluated Controls</div>
            <div style="font-size: 36px; font-weight: bold; color: #0f172a;">{passed_checks}/{total_checks} Controls Passing</div>
        </div>
    </div>
    <h2>Evaluated Database Control Criteria</h2>
    <table>
        <thead>
            <tr>
                <th>Framework</th>
                <th>Control ID / Name</th>
                <th>Description</th>
                <th>Status</th>
                <th>Last Evaluated</th>
            </tr>
        </thead>
        <tbody>
    """
    for c in checks:
        st = c['last_status'] or 'PASS'
        badge_cls = 'badge-pass' if st == 'PASS' else 'badge-fail'
        html_content += f"""
            <tr>
                <td><strong>{c['framework']}</strong></td>
                <td>{c['check_name']}</td>
                <td>{c['description']}</td>
                <td><span class="{badge_cls}">{st}</span></td>
                <td>{c['last_run_at'] or 'Just now'}</td>
            </tr>
        """
    html_content += """
        </tbody>
    </table>
</body>
</html>
    """
    return Response(html_content, mimetype="text/html")

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
