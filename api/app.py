"""
app.py — Core Flask REST API, GraphQL & WebSocket Gateway for DB-IDS/IPS.
"""

import os
import eventlet
eventlet.monkey_patch()

import logging
from datetime import datetime
from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient
import redis

from config import Config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [API] %(message)s")
logger = logging.getLogger("API")

# -----------------------------------------------------------------------------
# Extensions & Connections
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# MongoDB
mongo_client = MongoClient(app.config.get("MONGO_URI", "mongodb://localhost:27017"))
mongo_db = mongo_client[app.config.get("MONGO_DB", "ids_ips")]

# Redis
redis_client = redis.Redis.from_url(app.config.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

# -----------------------------------------------------------------------------
# Register Route Blueprints
# -----------------------------------------------------------------------------
from routes.auth import auth_bp
from routes.rules import rules_bp
from routes.alerts import alerts_bp, incidents_bp
from routes.playbooks import playbooks_bp
from routes.threats import threats_bp
from routes.sessions import sessions_bp
from routes.forensics import forensics_bp
from routes.compliance import compliance_bp
from routes.stats import stats_bp
from routes.nosql import nosql_bp

app.register_blueprint(auth_bp)
app.register_blueprint(rules_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(playbooks_bp)
app.register_blueprint(threats_bp)
app.register_blueprint(sessions_bp)
app.register_blueprint(forensics_bp)
app.register_blueprint(compliance_bp)
app.register_blueprint(stats_bp)
app.register_blueprint(nosql_bp)

# -----------------------------------------------------------------------------
# WebSocket Events & Real-Time Alert Broadcasts
# -----------------------------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    logger.info("WebSocket client connected to live alert stream")

@socketio.on("disconnect")
def handle_disconnect():
    logger.info("WebSocket client disconnected")

def background_alert_emitter():
    """Polls database for fresh alerts and pushes to connected UI clients."""
    from sqlalchemy import text
    last_id = 0
    while True:
        try:
            with app.app_context():
                with db.engine.connect() as conn:
                    res = conn.execute(
                        text("SELECT id, rule_type, severity, src_ip::text, dst_ip::text, src_port, dst_port, protocol, created_at FROM alerts WHERE id > :lid ORDER BY id ASC LIMIT 10"),
                        {"lid": last_id}
                    ).fetchall()
                    for r in res:
                        alert_dict = {
                            "id": r[0], "rule_type": r[1], "severity": r[2],
                            "src_ip": r[3], "dst_ip": r[4], "src_port": r[5],
                            "dst_port": r[6], "protocol": r[7], "created_at": r[8].isoformat()
                        }
                        last_id = max(last_id, r[0])
                        socketio.emit("new_alert", alert_dict)
        except Exception as e:
            pass
        socketio.sleep(2)

eventlet.spawn(background_alert_emitter)

# -----------------------------------------------------------------------------
# Health Check Endpoint
# -----------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "UP",
        "service": "DB-IDS/IPS API",
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
