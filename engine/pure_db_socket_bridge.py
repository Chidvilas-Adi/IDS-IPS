"""
pure_db_socket_bridge.py — Pure Socket-to-Database Gateway (Zero In-Memory Logic)

THIS SCRIPT PERFORMS ZERO ANALYSIS OR CALCULATION IN PYTHON.
Every single operation:
- Deep packet inspection regex matching
- Threshold calculation & sliding windows (SSH brute force, port scan)
- Stateful session tracking
- Threat intelligence matching
- Alert generation
- Automated playbook execution & IP blocking

IS PERFORMED 100% BY PostgreSQL PL/pgSQL TRIGGERS ON INSERT!

This bridge simply:
1. Receives raw socket packet bytes.
2. Runs: INSERT INTO ingress_packets (...) VALUES (...);
3. Listens to PostgreSQL via LISTEN db_firewall_action to execute the DB's commands.
"""

import os
import sys
import json
import logging
import platform
import subprocess
import threading
from datetime import datetime

try:
    import psycopg2
    import psycopg2.extensions
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, Raw
    from pymongo import MongoClient
except ImportError as e:
    print(f"Missing dependency: {e}. Run pip install scapy psycopg2-binary pymongo")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PureDBSocketBridge] %(message)s")
logger = logging.getLogger("PureDBSocketBridge")

PG_HOST = os.environ.get("POSTGRES_HOST", "localhost")
PG_PORT = int(os.environ.get("POSTGRES_PORT", 5432))
PG_DB = os.environ.get("POSTGRES_DB", "idsips")
PG_USER = os.environ.get("POSTGRES_USER", "idsips")
PG_PASS = os.environ.get("POSTGRES_PASSWORD", "idsips_secret")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
IS_WINDOWS = platform.system().lower() == "windows"

# MongoDB connection for raw NoSQL dumps
mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
mongo_db = mongo_client["idsips"]

def get_pg_conn():
    return psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )

# -----------------------------------------------------------------------------
# 1. DATABASE NOTIFICATION LISTENER (PostgreSQL LISTEN / NOTIFY)
# -----------------------------------------------------------------------------
def postgres_action_listener():
    """Listens for commands issued BY THE DATABASE TRIGGERS via pg_notify."""
    logger.info("Connecting to PostgreSQL notification channel 'db_firewall_action'...")
    try:
        conn = get_pg_conn()
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        cursor.execute("LISTEN db_firewall_action;")
        logger.info("Successfully subscribed to database-driven firewall commands!")

        while True:
            conn.poll()
            while conn.notifies:
                notify = conn.notifies.pop(0)
                try:
                    payload = json.loads(notify.payload)
                    action = payload.get("action")
                    ip = payload.get("ip")
                    reason = payload.get("reason", "In-Database Trigger")

                    logger.warning(f"DATABASE COMMAND RECEIVED -> {action} IP: {ip} (Reason: {reason})")

                    # Execute OS firewall block as commanded by SQL trigger
                    if action == "BLOCK" and ip:
                        if IS_WINDOWS:
                            rule_name = f"DBIDS_{ip.replace(':', '_')}"
                            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        else:
                            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        logger.info(f"Firewall successfully updated for {ip} per DATABASE command.")
                except Exception as ex:
                    logger.error(f"Error handling DB notification: {ex}")
    except Exception as e:
        logger.error(f"PostgreSQL notification listener disconnected: {e}")

# -----------------------------------------------------------------------------
# 2. DUMB RAW SOCKET TO DATABASE PIPE
# -----------------------------------------------------------------------------
class PureDBSocketBridge:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.conn = get_pg_conn()
        self.cursor = self.conn.cursor()

    def handle_packet(self, pkt):
        """Dumps raw packet into PostgreSQL. The DB triggers handle 100% of the logic!"""
        if not (IP in pkt or IPv6 in pkt):
            return

        ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto if IP in pkt else ip_layer.nh
        pkt_len = len(pkt)

        src_port, dst_port, tcp_flags = None, None, ""
        protocol = "OTHER"

        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            protocol = "ICMP"

        payload_text = ""
        if Raw in pkt:
            payload_text = pkt[Raw].load.decode("utf-8", errors="ignore")

        # 1. Sole SQL Action: Direct INSERT into database
        # This single SQL statement automatically triggers all PL/pgSQL correlation,
        # regex DPI matching, alert generation, and firewall notifications!
        try:
            self.cursor.execute("""
                INSERT INTO ingress_packets 
                    (src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, packet_length, payload_text)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, pkt_len, payload_text))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()

        # 2. Asynchronous copy to MongoDB for NoSQL document forensics
        try:
            mongo_db.raw_packets.insert_one({
                "timestamp": datetime.utcnow(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": pkt_len,
                "payload_hex": pkt[Raw].load.hex() if Raw in pkt else ""
            })
        except Exception:
            pass

    def start(self):
        logger.info("=========================================================")
        logger.info("   100% IN-DATABASE SOCKET BRIDGE STARTED               ")
        logger.info("   ALL INTELLIGENCE & LOGIC IS EXECUTED BY PostgreSQL    ")
        logger.info("=========================================================")

        # Start PostgreSQL NOTIFY listener thread
        t = threading.Thread(target=postgres_action_listener, daemon=True)
        t.start()

        # Sniff packets directly into SQL
        sniff(iface=self.interface, prn=self.handle_packet, store=False)

if __name__ == "__main__":
    bridge = PureDBSocketBridge()
    bridge.start()
