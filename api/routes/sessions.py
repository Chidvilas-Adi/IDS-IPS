"""
routes/sessions.py – Active network sessions, connection topologies, and flow logs.
"""

import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from sqlalchemy import text

logger = logging.getLogger(__name__)
sessions_bp = Blueprint("sessions", __name__, url_prefix="/api/sessions")

def _db():
    from app import db
    return db

def _fetchall(sql: str, params: dict = None) -> list:
    with _db().engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        cols = list(result.keys())
        return [dict(zip(cols, row)) for row in result.fetchall()]

def _fetchone(sql: str, params: dict = None) -> dict:
    with _db().engine.connect() as conn:
        row = conn.execute(text(sql), params or {}).fetchone()
        return dict(row._mapping) if row else None

@sessions_bp.route("", methods=["GET"])
@jwt_required(optional=True)
def list_sessions():
    limit = int(request.args.get("limit", 100))
    proto = request.args.get("protocol")
    sql = """
        SELECT id, src_ip::text, dst_ip::text, src_port, dst_port, protocol,
               state, bytes_sent, bytes_recv, packets_sent, packets_recv,
               started_at, last_seen_at
        FROM sessions
    """
    params = {"limit": limit}
    if proto:
        sql += " WHERE UPPER(protocol) = UPPER(:proto)"
        params["proto"] = proto
    sql += " ORDER BY last_seen_at DESC LIMIT :limit"

    rows = _fetchall(sql, params)
    for r in rows:
        for k in ["started_at", "last_seen_at"]:
            if r.get(k):
                r[k] = r[k].isoformat()
    return jsonify({"sessions": rows, "count": len(rows)})

@sessions_bp.route("/<int:session_id>", methods=["GET"])
@jwt_required(optional=True)
def get_session(session_id: int):
    sql = "SELECT id, src_ip::text, dst_ip::text, src_port, dst_port, protocol, state, bytes_sent, bytes_recv, started_at, last_seen_at FROM sessions WHERE id = :id"
    row = _fetchone(sql, {"id": session_id})
    if not row:
        return jsonify({"error": "Session not found"}), 404
    for k in ["started_at", "last_seen_at"]:
        if row.get(k):
            row[k] = row[k].isoformat()
    return jsonify(row)

@sessions_bp.route("/<int:session_id>", methods=["DELETE"])
@jwt_required()
def kill_session(session_id: int):
    sql = "DELETE FROM sessions WHERE id = :id"
    with _db().engine.begin() as conn:
        conn.execute(text(sql), {"id": session_id})
    return jsonify({"message": f"Session {session_id} terminated."})

@sessions_bp.route("/flows", methods=["GET"])
@jwt_required(optional=True)
def list_flows():
    limit = int(request.args.get("limit", 100))
    sql = """
        SELECT id, src_ip::text, dst_ip::text, src_port, dst_port, protocol,
               bytes, packets, duration_ms, flow_start, flow_end
        FROM flow_records ORDER BY flow_end DESC LIMIT :limit
    """
    rows = _fetchall(sql, {"limit": limit})
    for r in rows:
        for k in ["flow_start", "flow_end"]:
            if r.get(k):
                r[k] = r[k].isoformat()
    return jsonify({"flows": rows, "count": len(rows)})

@sessions_bp.route("/topology", methods=["GET"])
@jwt_required(optional=True)
def get_topology():
    sql = """
        SELECT src_ip::text, dst_ip::text, connection_count, total_bytes, first_seen, last_seen
        FROM connection_graph_edges
        ORDER BY last_seen DESC LIMIT 200
    """
    edges = _fetchall(sql)
    nodes = set()
    edge_list = []
    for e in edges:
        nodes.add(e["src_ip"])
        nodes.add(e["dst_ip"])
        edge_list.append({
            "source": e["src_ip"],
            "target": e["dst_ip"],
            "count": e["connection_count"],
            "bytes": e["total_bytes"]
        })
    node_list = [{"id": ip, "label": ip} for ip in nodes]
    return jsonify({"nodes": node_list, "edges": edge_list})

@sessions_bp.route("/fingerprints", methods=["GET"])
@jwt_required(optional=True)
def list_fingerprints():
    sql = """
        SELECT id, session_id, os_guess, ttl, window_size, ja3_hash, hassh_hash, confidence, created_at
        FROM session_fingerprints ORDER BY created_at DESC LIMIT 100
    """
    rows = _fetchall(sql)
    for r in rows:
        if r.get("created_at"):
            r["created_at"] = r["created_at"].isoformat()
    return jsonify({"fingerprints": rows})
