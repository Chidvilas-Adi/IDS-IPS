"""
threat_feed_ingester.py — Threat Intelligence Feed Ingestion Worker

Automatically polls external OSINT threat feeds configured in PostgreSQL (threat_feeds table).
Saves raw feeds to MongoDB (threat_intel_raw collection) and populates PostgreSQL
indicators of compromise (ioc_ipv4 and ioc_domains tables).
"""

import time
import json
import logging
import requests
from datetime import datetime
from typing import List, Dict, Any

from models import get_db_session, get_mongo_db, ThreatFeed, IocIPv4, IocDomain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ThreatFeed] %(message)s")
logger = logging.getLogger("ThreatFeed")

class ThreatFeedIngester:
    def __init__(self):
        self.mongo_db = get_mongo_db()

    def poll_all_feeds(self):
        """Query active threat feeds from PostgreSQL and fetch latest IOCs."""
        session = get_db_session()
        try:
            feeds = session.query(ThreatFeed).filter(ThreatFeed.enabled == True).all()
            logger.info(f"Checking {len(feeds)} enabled threat feeds...")

            for feed in feeds:
                try:
                    self.ingest_feed(feed, session)
                except Exception as ex:
                    logger.error(f"Failed to ingest feed '{feed.name}': {ex}")

        except Exception as e:
            logger.error(f"Database query error in threat feed ingester: {e}")
        finally:
            session.close()

    def ingest_feed(self, feed: ThreatFeed, session):
        """Fetch feed data, store raw in MongoDB, and extract IOCs into PostgreSQL."""
        logger.info(f"Polling feed: {feed.name} ({feed.url})")
        resp = requests.get(feed.url, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"Feed {feed.name} returned HTTP {resp.status_code}")
            return

        content = resp.text

        # 1. Store raw snapshot in MongoDB
        try:
            self.mongo_db.threat_intel_raw.insert_one({
                "source": feed.name,
                "url": feed.url,
                "ingested_at": datetime.utcnow(),
                "content_preview": content[:2000],
                "processed": True
            })
        except Exception as e:
            logger.warning(f"Could not store raw threat intel in MongoDB: {e}")

        # 2. Parse IOCs depending on format
        new_iocs = 0
        if feed.feed_type == "JSON":
            try:
                data = resp.json()
                if isinstance(data, list):
                    for item in data[:500]:  # batch limit
                        ip = item.get("ip_address") or item.get("dst_ip") or item.get("ip")
                        if ip:
                            self._insert_ioc_ip(session, ip, source=feed.name)
                            new_iocs += 1
            except Exception as e:
                logger.error(f"JSON parsing error for feed {feed.name}: {e}")

        elif feed.feed_type == "PLAIN_IP":
            lines = content.splitlines()
            for line in lines[:500]:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    ip = parts[0] if parts else None
                    if ip and len(ip) >= 7 and "." in ip:
                        self._insert_ioc_ip(session, ip, source=feed.name)
                        new_iocs += 1

        feed.last_polled_at = datetime.utcnow()
        feed.ioc_count = (feed.ioc_count or 0) + new_iocs
        session.commit()
        logger.info(f"Feed '{feed.name}' ingestion finished. Added/Refreshed {new_iocs} IOCs.")

    def _insert_ioc_ip(self, session, ip: str, source: str):
        """Insert or refresh IPv4 indicator in PostgreSQL."""
        try:
            existing = session.query(IocIPv4).filter(IocIPv4.ip == ip).first()
            if not existing:
                ioc = IocIPv4(
                    ip=ip,
                    confidence=90,
                    severity="HIGH",
                    source=source,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow()
                )
                session.add(ioc)
            else:
                existing.last_seen = datetime.utcnow()
        except Exception:
            session.rollback()

    def run_scheduler(self, interval_seconds: int = 1800):
        """Periodic background polling loop."""
        logger.info(f"Threat Feed Ingester loop active (Interval: {interval_seconds}s)")
        while True:
            self.poll_all_feeds()
            time.sleep(interval_seconds)

if __name__ == "__main__":
    worker = ThreatFeedIngester()
    worker.poll_all_feeds()
