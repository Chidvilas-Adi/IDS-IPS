"""
routes/forensics.py – MongoDB-driven deep packet forensics, DNS & HTTP logs, and anomaly vectors.
"""

import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from bson import ObjectId

logger = logging.getLogger(__name__)
forensics_bp = Blueprint("forensics", __name__, url_prefix="/api/forensics")

def _mongo():
    from app import mongo_db
    return mongo_db

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
@jwt_required(optional=True)
def list_raw_packets():
    limit = min(int(request.args.get("limit", 50)), 200)
    src_ip = request.args.get("src_ip")
    proto = request.args.get("protocol")

    query = {}
    if src_ip:
        query["src_ip"] = src_ip
    if proto:
        query["protocol"] = proto.upper()

    cursor = _mongo().raw_packets.find(query).sort("timestamp", -1).limit(limit)
    packets = [_clean_doc(p) for p in cursor]
    return jsonify({"packets": packets, "count": len(packets)})

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
