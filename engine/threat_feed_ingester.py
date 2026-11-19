"""Ingest public, no-API-key threat feeds into PostgreSQL and MongoDB."""

import time
import logging
import requests
from datetime import datetime

from models import get_db_session, get_mongo_db, IocIPv4

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ThreatFeedIngester] %(message)s")
logger = logging.getLogger("ThreatFeedIngester")

class ThreatFeedIngester:
    def __init__(self):
        self.mongo_db = get_mongo_db()

    def poll_all_feeds(self):
        """Poll public feeds that do not require provider API credentials."""
        session = get_db_session()
        try:
            logger.info("Starting ingestion of public no-key threat feeds...")
            self.ingest_feodo_tracker(session)
            self.ingest_emerging_threats(session)
        except Exception as e:
            logger.error(f"Error in threat feed cycle: {e}")
        finally:
            session.close()

    def _archive_raw_mongo(self, source: str, raw_payload: str, count: int):
        """Archives full raw feed JSON/CSV to MongoDB NoSQL for forensics and compliance."""
        try:
            self.mongo_db.threat_intel_raw.insert_one({
                "source": source,
                "ingested_at": datetime.utcnow(),
                "iocs_extracted": count,
                "payload_snippet": raw_payload[:2500],
                "processed": True
            })
        except Exception as e:
            logger.warning(f"MongoDB threat archive error: {e}")

    def _insert_ioc(self, session, ip: str, source: str, confidence: int = 90, severity: str = "HIGH"):
        """Inserts normalized IP into PostgreSQL ioc_ipv4."""
        try:
            existing = session.query(IocIPv4).filter(IocIPv4.ip == ip).first()
            if not existing:
                ioc = IocIPv4(
                    ip=ip,
                    confidence=confidence,
                    severity=severity,
                    source=source,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                session.add(ioc)
            else:
                existing.last_seen = datetime.utcnow()
                existing.confidence = max(existing.confidence, confidence)
        except Exception:
            session.rollback()

    def ingest_feodo_tracker(self, session):
        """Feed 1: Feodo Tracker Botnet C2 JSON."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        try:
            resp = requests.get(url, timeout=12)
            if resp.status_code == 200:
                data = resp.json()
                cnt = 0
                for item in data[:300]:
                    ip = item.get("ip_address")
                    if ip:
                        self._insert_ioc(session, ip, "FeodoTracker", confidence=95, severity="CRITICAL")
                        cnt += 1
                session.commit()
                self._archive_raw_mongo("FeodoTracker", resp.text, cnt)
                logger.info("FeodoTracker ingested %s botnet C2 IOCs", cnt)
        except Exception as e:
            logger.error(f"FeodoTracker error: {e}")

    def ingest_emerging_threats(self, session):
        """Feed 2: Emerging Threats Compromised IP List."""
        url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        try:
            resp = requests.get(url, timeout=12)
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                cnt = 0
                for line in lines[:300]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._insert_ioc(session, line, "EmergingThreats", confidence=90, severity="HIGH")
                        cnt += 1
                session.commit()
                self._archive_raw_mongo("EmergingThreats", resp.text, cnt)
                logger.info("EmergingThreats ingested %s compromised host IPs", cnt)
        except Exception as e:
            logger.error(f"EmergingThreats error: {e}")

    def run_scheduler(self, interval_seconds: int = 1800):
        while True:
            self.poll_all_feeds()
            time.sleep(interval_seconds)

if __name__ == "__main__":
    worker = ThreatFeedIngester()
    worker.poll_all_feeds()
