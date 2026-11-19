"""
routes/forensics.py – MongoDB-driven deep packet forensics, DNS & HTTP logs, and anomaly vectors.
"""

import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from bson import ObjectId
from sqlalchemy import text

logger = logging.getLogger(__name__)
forensics_bp = Blueprint("forensics", __name__, url_prefix="/api/forensics")

def _mongo():
    from app import mongo_db
    return mongo_db

def _db():
    from app import db
    return db

def _clean_doc(doc):
    if not doc:
        return doc
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    for k, v in doc.items():
        if hasattr(v, "isoformat"):
            doc[k] = v.isoformat()
    return doc

@forensics_bp.route("/packets", methods=["GET"])
@jwt_required()
def list_raw_packets():
    limit = max(1, min(int(request.args.get("limit", 100)), 200))
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")
    proto = request.args.get("protocol", "").upper()

    conditions, params = [], {"limit": limit}
    if src_ip:
        conditions.append("host(src_ip) = :src_ip")
        params["src_ip"] = src_ip
    if dst_ip:
        conditions.append("host(dst_ip) = :dst_ip")
        params["dst_ip"] = dst_ip
    if proto:
        conditions.append("UPPER(protocol) = :protocol")
        params["protocol"] = proto
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with _db().engine.connect() as conn:
        total = conn.execute(
            text(f"SELECT COUNT(*) FROM ingress_packets {where}"),
            {key: value for key, value in params.items() if key != "limit"},
        ).scalar_one()
        rows = conn.execute(
            text(
                "SELECT id, created_at, host(src_ip) AS src_ip, host(dst_ip) AS dst_ip, "
                "src_port, dst_port, protocol, tcp_flags, packet_length, "
                "capture_source, octet_length(payload_bytes) AS payload_size, "
                "encode(substring(payload_bytes FROM 1 FOR 96), 'hex') AS payload_hex "
                f"FROM ingress_packets {where} ORDER BY id DESC LIMIT :limit"
            ),
            params,
        ).mappings().all()
        protocol_rows = conn.execute(
            text("SELECT protocol, COUNT(*) AS count FROM ingress_packets GROUP BY protocol")
        ).mappings().all()
        source_rows = conn.execute(
            text("SELECT capture_source, COUNT(*) AS count FROM ingress_packets GROUP BY capture_source")
        ).mappings().all()
        last_captured_at = conn.execute(
            text("SELECT MAX(created_at) FROM ingress_packets WHERE capture_source = 'capture'")
        ).scalar_one()

    packets = []
    for row in rows:
        packet = dict(row)
        packet["timestamp"] = packet["created_at"].isoformat()
        del packet["created_at"]
        packets.append(packet)

    return jsonify({
        "packets": packets,
        "count": len(packets),
        "total": total,
        "protocol_counts": {row["protocol"]: row["count"] for row in protocol_rows},
        "source_counts": {row["capture_source"]: row["count"] for row in source_rows},
        "last_captured_at": last_captured_at.isoformat() if last_captured_at else None,
    })

@forensics_bp.route("/packets/<packet_id>", methods=["GET"])
@jwt_required(optional=True)
def get_packet(packet_id: str):
    try:
        doc = _mongo().raw_packets.find_one({"_id": ObjectId(packet_id)})
        if not doc:
            return jsonify({"error": "Packet not found"}), 404
        return jsonify(_clean_doc(doc))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@forensics_bp.route("/dns", methods=["GET"])
@jwt_required(optional=True)
def list_dns_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    cursor = _mongo().dns_query_log.find().sort("timestamp", -1).limit(limit)
    return jsonify({"dns_logs": [_clean_doc(d) for d in cursor]})

@forensics_bp.route("/http", methods=["GET"])
@jwt_required(optional=True)
def list_http_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    cursor = _mongo().http_transaction_log.find().sort("timestamp", -1).limit(limit)
    return jsonify({"http_logs": [_clean_doc(h) for h in cursor]})

@forensics_bp.route("/tls", methods=["GET"])
@jwt_required(optional=True)
def list_tls_logs():
    limit = min(int(request.args.get("limit", 50)), 200)
    cursor = _mongo().tls_handshake_log.find().sort("timestamp", -1).limit(limit)
    return jsonify({"tls_logs": [_clean_doc(t) for t in cursor]})

@forensics_bp.route("/anomaly-scores/<ip>", methods=["GET"])
@jwt_required(optional=True)
def get_ip_anomalies(ip: str):
    cursor = _mongo().anomaly_vectors.find({"ip": ip}).sort("timestamp", -1).limit(20)
    return jsonify({"anomalies": [_clean_doc(a) for a in cursor]})
