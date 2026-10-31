"""
routes/nosql.py – MongoDB collection explorer and NoSQL introspection interface.
"""

import logging
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

logger = logging.getLogger(__name__)
nosql_bp = Blueprint("nosql", __name__, url_prefix="/api/nosql")

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

@nosql_bp.route("/collections", methods=["GET"])
@jwt_required(optional=True)
def list_collections():
    cols = _mongo().list_collection_names()
    stats = []
    for c in cols:
        count = _mongo()[c].estimated_document_count()
        stats.append({"name": c, "count": count})
    return jsonify({"collections": stats})

@nosql_bp.route("/raw-packets", methods=["GET"])
@jwt_required(optional=True)
def browse_raw_packets():
    limit = min(int(request.args.get("limit", 25)), 100)
    cursor = _mongo().raw_packets.find().sort("timestamp", -1).limit(limit)
    return jsonify({"documents": [_clean_doc(d) for d in cursor]})

@nosql_bp.route("/threat-intel", methods=["GET"])
@jwt_required(optional=True)
def browse_threat_intel():
    cursor = _mongo().threat_intel_raw.find().sort("ingested_at", -1).limit(20)
    return jsonify({"threat_intel": [_clean_doc(d) for d in cursor]})

@nosql_bp.route("/canary-log", methods=["GET"])
@jwt_required(optional=True)
def browse_canary_log():
    cursor = _mongo().canary_access_log.find().sort("accessed_at", -1).limit(50)
    return jsonify({"canary_logs": [_clean_doc(d) for d in cursor]})
