"""
routes/rules.py – Detection rule management endpoints.

Covers IDS/IPS rules, correlation rules, DPI signatures, geo rules,
DNS/HTTP/TLS rule views, and Snort rule import.
"""

import logging
import re
from datetime import datetime

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
rules_bp = Blueprint("rules", __name__, url_prefix="/api/rules")


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


def _serialize(d: dict) -> dict:
    """Convert datetime objects to ISO strings in a dict."""
    return {
        k: (v.isoformat() if isinstance(v, datetime) else v)
        for k, v in d.items()
    }


# ---------------------------------------------------------------------------
# Base rule CRUD
# ---------------------------------------------------------------------------


@rules_bp.get("")
@jwt_required()
def list_rules():
    rule_type = request.args.get("type")
    severity = request.args.get("severity")
    enabled = request.args.get("enabled")
    page = max(1, int(request.args.get("page", 1)))
    limit = min(500, int(request.args.get("limit", 100)))
    offset = (page - 1) * limit

    conditions, params = [], {}
    if rule_type:
        conditions.append("rule_type = :rule_type")
        params["rule_type"] = rule_type
    if severity:
        conditions.append("severity = :severity")
        params["severity"] = severity
    if enabled is not None:
        conditions.append("enabled = :enabled")
        params["enabled"] = enabled.lower() == "true"

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    count_row = _fetchone(f"SELECT COUNT(*) AS c FROM rules {where}", params)
    total = count_row["c"] if count_row else 0

    params.update({"limit": limit, "offset": offset})
    rows = _fetchall(
        f"SELECT id, name, rule_type, severity, protocol, src_ip, dst_ip, "
        f"src_port, dst_port, action, enabled, description, created_at, updated_at "
        f"FROM rules {where} ORDER BY id DESC LIMIT :limit OFFSET :offset",
        params,
    )
    return jsonify({"total": total, "page": page, "limit": limit, "items": [_serialize(r) for r in rows]})


@rules_bp.post("")
@jwt_required()
def create_rule():
    data = request.get_json(silent=True) or {}
    required = ["name", "rule_type", "severity", "action"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    row = _fetchone(
        "INSERT INTO rules (name, rule_type, severity, action, protocol, src_ip, dst_ip, "
        "src_port, dst_port, description, enabled, created_at, updated_at) "
        "VALUES (:name, :rule_type, :severity, :action, :protocol, :src_ip, :dst_ip, "
        ":src_port, :dst_port, :description, :enabled, NOW(), NOW()) RETURNING id, created_at",
        {
            "name": data["name"], "rule_type": data["rule_type"],
            "severity": data["severity"], "action": data["action"],
            "protocol": data.get("protocol"), "src_ip": data.get("src_ip"),
            "dst_ip": data.get("dst_ip"), "src_port": data.get("src_port"),
            "dst_port": data.get("dst_port"), "description": data.get("description"),
            "enabled": data.get("enabled", True),
        },
    )
    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201


@rules_bp.get("/<int:rule_id>")
@jwt_required()
def get_rule(rule_id: int):
    row = _fetchone("SELECT * FROM rules WHERE id = :id", {"id": rule_id})
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify(_serialize(row))


@rules_bp.put("/<int:rule_id>")
@jwt_required()
def update_rule(rule_id: int):
    data = request.get_json(silent=True) or {}
    updatable = ["name", "rule_type", "severity", "action", "protocol", "src_ip", "dst_ip",
                 "src_port", "dst_port", "description", "enabled"]
    sets, params = ["updated_at = NOW()"], {"id": rule_id}
    for field in updatable:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]

    if len(sets) == 1:
        return jsonify({"error": "No updatable fields provided"}), 400

    result = _execute(
        f"UPDATE rules SET {', '.join(sets)} WHERE id = :id", params
    )
    if result.rowcount == 0:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"message": "Rule updated"})


@rules_bp.delete("/<int:rule_id>")
@jwt_required()
def delete_rule(rule_id: int):
    result = _execute("DELETE FROM rules WHERE id = :id", {"id": rule_id})
    if result.rowcount == 0:
        return jsonify({"error": "Rule not found"}), 404
    return jsonify({"message": "Rule deleted"})


@rules_bp.post("/<int:rule_id>/test")
@jwt_required()
def test_rule(rule_id: int):
    """
    Test a rule against a supplied packet dict.
    Returns whether the rule would fire and why.
    """
    rule = _fetchone("SELECT * FROM rules WHERE id = :id", {"id": rule_id})
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    pkt = request.get_json(silent=True) or {}
    matches: list[str] = []
    mismatches: list[str] = []

    def _check(field: str, pkt_key: str):
        if rule.get(field):
            if str(pkt.get(pkt_key, "")).lower() == str(rule[field]).lower():
                matches.append(field)
            else:
                mismatches.append(field)

    _check("protocol", "protocol")
    _check("src_ip", "src_ip")
    _check("dst_ip", "dst_ip")
    _check("src_port", "src_port")
    _check("dst_port", "dst_port")

    fired = len(mismatches) == 0
    return jsonify({
        "rule_id": rule_id,
        "fired": fired,
        "action": rule["action"] if fired else None,
        "matches": matches,
        "mismatches": mismatches,
    })


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


@rules_bp.get("/correlation")
@jwt_required()
def list_correlation_rules():
    rows = _fetchall(
        "SELECT id, name, description, logic, threshold, time_window_seconds, "
        "severity, enabled, created_at FROM correlation_rules ORDER BY id DESC"
    )
    return jsonify([_serialize(r) for r in rows])


@rules_bp.post("/correlation")
@jwt_required()
def create_correlation_rule():
    data = request.get_json(silent=True) or {}
    required = ["name", "severity"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing fields: {missing}"}), 400

    import json as _json
    logic_json = _json.dumps(data.get("logic", {})) if isinstance(data.get("logic"), dict) else data.get("logic", "{}")

    row = _fetchone(
        "INSERT INTO correlation_rules (name, description, logic, threshold, time_window_seconds, "
        "severity, enabled, created_at) "
        "VALUES (:name, :desc, :logic::jsonb, :threshold, :window, :severity, :enabled, NOW()) "
        "RETURNING id, created_at",
        {
            "name": data["name"], "desc": data.get("description"),
            "logic": logic_json, "threshold": data.get("threshold", 5),
            "window": data.get("time_window_seconds", 60),
            "severity": data["severity"], "enabled": data.get("enabled", True),
        },
    )
    return jsonify({"id": row["id"], "created_at": row["created_at"].isoformat()}), 201


@rules_bp.put("/correlation/<int:rule_id>")
@jwt_required()
def update_correlation_rule(rule_id: int):
    data = request.get_json(silent=True) or {}
    import json as _json
    sets, params = [], {"id": rule_id}
    mapping = {
        "name": "name", "description": "description",
        "threshold": "threshold", "time_window_seconds": "time_window_seconds",
        "severity": "severity", "enabled": "enabled",
    }
    for k, col in mapping.items():
        if k in data:
            sets.append(f"{col} = :{k}")
            params[k] = data[k]
    if "logic" in data:
        sets.append("logic = :logic::jsonb")
        params["logic"] = _json.dumps(data["logic"]) if isinstance(data["logic"], dict) else data["logic"]
    if not sets:
        return jsonify({"error": "No fields to update"}), 400
    result = _execute(f"UPDATE correlation_rules SET {', '.join(sets)} WHERE id = :id", params)
    if result.rowcount == 0:
        return jsonify({"error": "Correlation rule not found"}), 404
    return jsonify({"message": "Correlation rule updated"})


# ---------------------------------------------------------------------------
# DPI Signatures
# ---------------------------------------------------------------------------


@rules_bp.get("/signatures")
@jwt_required()
def list_signatures():
    rows = _fetchall(
        "SELECT id, name, pattern, pattern_type, protocol, severity, enabled, created_at "
        "FROM dpi_signatures ORDER BY id DESC LIMIT 500"
    )
    return jsonify([_serialize(r) for r in rows])


@rules_bp.post("/signatures")
@jwt_required()
def create_signature():
    data = request.get_json(silent=True) or {}
    for f in ["name", "pattern", "pattern_type"]:
        if not data.get(f):
            return jsonify({"error": f"{f} is required"}), 400
    row = _fetchone(
        "INSERT INTO dpi_signatures (name, pattern, pattern_type, protocol, severity, enabled, created_at) "
        "VALUES (:name, :pattern, :pt, :protocol, :severity, :enabled, NOW()) RETURNING id",
        {
            "name": data["name"], "pattern": data["pattern"],
            "pt": data["pattern_type"], "protocol": data.get("protocol"),
            "severity": data.get("severity", "medium"), "enabled": data.get("enabled", True),
        },
    )
    return jsonify({"id": row["id"]}), 201


@rules_bp.put("/signatures/<int:sig_id>")
@jwt_required()
def update_signature(sig_id: int):
    data = request.get_json(silent=True) or {}
    sets, params = [], {"id": sig_id}
    for field in ["name", "pattern", "pattern_type", "protocol", "severity", "enabled"]:
        if field in data:
            sets.append(f"{field} = :{field}")
            params[field] = data[field]
    if not sets:
        return jsonify({"error": "No fields to update"}), 400
    result = _execute(f"UPDATE dpi_signatures SET {', '.join(sets)} WHERE id = :id", params)
    if result.rowcount == 0:
        return jsonify({"error": "Signature not found"}), 404
    return jsonify({"message": "Signature updated"})


@rules_bp.delete("/signatures/<int:sig_id>")
@jwt_required()
def delete_signature(sig_id: int):
    result = _execute("DELETE FROM dpi_signatures WHERE id = :id", {"id": sig_id})
    if result.rowcount == 0:
        return jsonify({"error": "Signature not found"}), 404
    return jsonify({"message": "Signature deleted"})


# ---------------------------------------------------------------------------
# Snort import
# ---------------------------------------------------------------------------

_SNORT_RE = re.compile(
    r'^(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)'
    r'\s+->\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>[^)]*)\)',
    re.IGNORECASE,
)


def _parse_snort_line(line: str) -> dict | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _SNORT_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    options = dict(
        kv.split(":", 1) if ":" in kv else (kv.strip(), "")
        for kv in g["options"].split(";")
        if kv.strip()
    )

    def _port(p: str) -> int | None:
        try:
            return int(p)
        except (ValueError, TypeError):
            return None

    return {
        "name": options.get("msg", "Imported Snort Rule").strip().strip('"'),
        "rule_type": "network",
        "severity": options.get("priority", "medium"),
        "action": g["action"].lower(),
        "protocol": g["protocol"].lower(),
        "src_ip": None if g["src_ip"] == "any" else g["src_ip"],
        "dst_ip": None if g["dst_ip"] == "any" else g["dst_ip"],
        "src_port": _port(g["src_port"]),
        "dst_port": _port(g["dst_port"]),
        "description": f"Imported from Snort: {line[:200]}",
        "enabled": True,
    }


@rules_bp.post("/import/snort")
@jwt_required()
def import_snort():
    text_data = request.data.decode("utf-8", errors="replace")
    lines = text_data.splitlines()
    imported, skipped = 0, 0

    for line in lines:
        parsed = _parse_snort_line(line)
        if not parsed:
            skipped += 1
            continue
        try:
            _execute(
                "INSERT INTO rules (name, rule_type, severity, action, protocol, src_ip, dst_ip, "
                "src_port, dst_port, description, enabled, created_at, updated_at) "
                "VALUES (:name, :rule_type, :severity, :action, :protocol, :src_ip, :dst_ip, "
                ":src_port, :dst_port, :description, :enabled, NOW(), NOW()) "
                "ON CONFLICT DO NOTHING",
                parsed,
            )
            imported += 1
        except Exception as exc:
            logger.warning("Snort import row failed: %s – %s", line[:80], exc)
            skipped += 1

    return jsonify({"imported": imported, "skipped": skipped})


# ---------------------------------------------------------------------------
# Geo / DNS / HTTP / TLS rule views
# ---------------------------------------------------------------------------


@rules_bp.get("/geo")
@jwt_required()
def list_geo_rules():
    rows = _fetchall(
        "SELECT id, country_code, action, direction, severity, enabled, created_at "
        "FROM geo_rules ORDER BY country_code"
    )
    return jsonify([_serialize(r) for r in rows])


@rules_bp.post("/geo")
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


@rules_bp.get("/dns")
@jwt_required()
def list_dns_rules():
    rows = _fetchall(
        "SELECT * FROM rules WHERE rule_type = 'dns' ORDER BY id DESC LIMIT 500"
    )
    return jsonify([_serialize(r) for r in rows])


@rules_bp.get("/http")
@jwt_required()
def list_http_rules():
    rows = _fetchall(
        "SELECT * FROM rules WHERE rule_type = 'http' ORDER BY id DESC LIMIT 500"
    )
    return jsonify([_serialize(r) for r in rows])


@rules_bp.get("/tls")
@jwt_required()
def list_tls_rules():
    rows = _fetchall(
        "SELECT * FROM rules WHERE rule_type = 'tls' ORDER BY id DESC LIMIT 500"
    )
    return jsonify([_serialize(r) for r in rows])
