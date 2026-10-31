"""
ml_engine.py — Machine Learning & Statistical Anomaly Detection Engine

Evaluates per-IP network feature metrics against baseline distributions.
Stores anomaly vectors in MongoDB (anomaly_vectors collection) and updates
PostgreSQL ip_reputation table based on behavioral deviations.
"""

import time
import math
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from models import get_db_session, get_mongo_db, Session, IpReputation, Alert
from action_engine import ActionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [MLEngine] %(message)s")
logger = logging.getLogger("MLEngine")

class AnomalyEngine:
    def __init__(self, check_interval_seconds: int = 60):
        self.interval = check_interval_seconds
        self.action_engine = ActionEngine()
        self.mongo_db = get_mongo_db()

    def run_cycle(self):
        """Analyze recent active traffic patterns in PostgreSQL sessions and detect outliers."""
        session = get_db_session()
        try:
            cutoff = datetime.utcnow() - timedelta(minutes=15)
            active_sessions = session.query(Session).filter(Session.last_seen_at >= cutoff).all()
            if not active_sessions:
                return

            ip_metrics: Dict[str, Dict[str, Any]] = {}
            for s in active_sessions:
                ip = str(s.src_ip)
                if ip not in ip_metrics:
                    ip_metrics[ip] = {
                        "total_bytes": 0,
                        "session_count": 0,
                        "dst_ports": set(),
                        "protocols": set()
                    }
                ip_metrics[ip]["total_bytes"] += (s.bytes_sent or 0) + (s.bytes_recv or 0)
                ip_metrics[ip]["session_count"] += 1
                ip_metrics[ip]["dst_ports"].add(s.dst_port)
                ip_metrics[ip]["protocols"].add(s.protocol)

            if len(ip_metrics) < 2:
                return

            # Compute population baseline averages
            counts = [m["session_count"] for m in ip_metrics.values()]
            mean_sessions = sum(counts) / len(counts)
            variance = sum((c - mean_sessions) ** 2 for c in counts) / len(counts)
            std_dev = math.sqrt(variance) if variance > 0 else 1.0

            for ip, m in ip_metrics.items():
                z_score = (m["session_count"] - mean_sessions) / std_dev
                unique_ports = len(m["dst_ports"])

                anomaly_score = 0.0
                if z_score > 3.0:
                    anomaly_score += 45.0
                elif z_score > 2.0:
                    anomaly_score += 25.0

                if unique_ports > 20:
                    anomaly_score += 35.0

                if anomaly_score > 50.0:
                    logger.warning(f"⚠️ ML Anomaly detected for {ip}: Score={anomaly_score:.1f}, Z={z_score:.2f}, Ports={unique_ports}")
                    self._record_anomaly(ip, anomaly_score, m, z_score, unique_ports)

        except Exception as e:
            logger.error(f"Error executing ML anomaly cycle: {e}")
        finally:
            session.close()

    def _record_anomaly(self, ip: str, score: float, metrics: Dict[str, Any], z_score: float, unique_ports: int):
        """Save vector to MongoDB and adjust reputation in PostgreSQL."""
        # 1. MongoDB anomaly_vectors collection
        try:
            self.mongo_db.anomaly_vectors.insert_one({
                "ip": ip,
                "timestamp": datetime.utcnow(),
                "anomaly_score": score,
                "features": {
                    "z_score": z_score,
                    "session_count": metrics["session_count"],
                    "total_bytes": metrics["total_bytes"],
                    "unique_dst_ports": unique_ports
                },
                "flagged": True
            })
        except Exception as ex:
            logger.error(f"MongoDB anomaly insert error: {ex}")

        # 2. Update PostgreSQL IP Reputation
        self.action_engine.update_reputation(ip, int(score / 2))

    def run_forever(self):
        """Continuous background execution loop."""
        logger.info("ML Anomaly Engine starting monitoring loop...")
        while True:
            try:
                self.run_cycle()
            except Exception as e:
                logger.error(f"Unhandled exception in ML monitor: {e}")
            time.sleep(self.interval)

if __name__ == "__main__":
    engine = AnomalyEngine(check_interval_seconds=10)
    engine.run_cycle()
    print("ML Anomaly cycle completed.")
