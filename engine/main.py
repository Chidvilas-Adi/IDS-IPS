"""
main.py — Master Daemon for the DB-IDS/IPS Engine

Orchestrates all concurrent security processing pipelines:
- Packet Sniffing & Ingestion (packet_capture.py)
- Correlation & Threat Analysis (correlation_engine.py)
- Deep Packet Inspection (dpi_engine.py)
- ML & Behavioral Anomaly Detection (ml_engine.py)
- IP Reputation & Auto-Escalation (reputation_engine.py)
- Retention & Housekeeping (data_retention.py)
- Integrated Health Check HTTP listener
"""

import os
import sys
import time
import signal
import threading
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

from packet_capture import PacketCaptureEngine
from correlation_engine import CorrelationEngine
from dpi_engine import DPIEngine
from ml_engine import AnomalyEngine
from reputation_engine import ReputationEngine
from data_retention import RetentionManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [EngineMaster] %(message)s")
logger = logging.getLogger("EngineMaster")

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "UP", "engine": "DB-IDS/IPS", "mode": "DATABASE_DRIVEN"}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress noisy health check access logs

def run_health_server(port: int = 8080):
    server = HTTPServer(("0.0.0.0", port), HealthHandler)
    logger.info(f"Health check HTTP endpoint listening on port {port}")
    server.serve_forever()

def main():
    logger.info("=========================================================")
    logger.info("   DB-IDS/IPS ULTRA — DATABASE-DRIVEN SECURITY ENGINE   ")
    logger.info("=========================================================")

    # 1. Start Health Check Server in daemon thread
    health_thread = threading.Thread(target=run_health_server, daemon=True)
    health_thread.start()

    # 2. Instantiate and run ML Anomaly Engine thread
    anomaly_engine = AnomalyEngine(check_interval_seconds=60)
    ml_thread = threading.Thread(target=anomaly_engine.run_forever, daemon=True)
    ml_thread.start()

    # 3. Instantiate and run Reputation Engine thread
    rep_engine = ReputationEngine()
    rep_thread = threading.Thread(target=lambda: rep_engine.run_forever(interval_seconds=300), daemon=True)
    rep_thread.start()

    # 4. Instantiate and run Retention Manager thread
    retention_mgr = RetentionManager()
    retention_thread = threading.Thread(target=lambda: retention_mgr.run_forever(interval_seconds=3600), daemon=True)
    retention_thread.start()

    # 5. Correlation & DPI Engine pipeline
    correlation_engine = CorrelationEngine()
    dpi_engine = DPIEngine()

    def on_packet_received(packet_data):
        # 1. Run through DPI signatures
        dpi_engine.inspect_packet(packet_data)
        # 2. Run through database-driven correlation rules
        correlation_engine.evaluate_packet(packet_data)

    # 6. Packet Capture Engine (Primary loop on main thread or dedicated thread)
    interface = os.environ.get("NETWORK_INTERFACE", None)
    sniff_engine = PacketCaptureEngine(interface=interface, packet_callback=on_packet_received)

    def signal_handler(sig, frame):
        logger.info("Shutdown signal received. Stopping packet capture...")
        sniff_engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Starting real-time packet sniffer...")
    sniff_engine.start()

if __name__ == "__main__":
    main()
