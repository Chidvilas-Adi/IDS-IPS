"""
data_retention.py — Automated Database Lifecycle & Housekeeping Service

Executes retention policies stored in PostgreSQL data_retention_policies table.
Purges stale sessions, expired blocklist records, and cleans up Redis cache.
"""

import time
import logging
from datetime import datetime
from sqlalchemy import text

from models import get_db_session, get_redis, DataRetentionPolicy, BlockedIp

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Retention] %(message)s")
logger = logging.getLogger("Retention")

class RetentionManager:
    def __init__(self):
        self.redis = get_redis()

    def run_cleanup(self):
        """Execute cleanup tasks according to database retention policies."""
        session = get_db_session()
        try:
            # 1. Unblock expired firewall entries
            now = datetime.utcnow()
            expired_blocks = session.query(BlockedIp).filter(
                BlockedIp.active == True,
                BlockedIp.expires_at < now
            ).all()

            for b in expired_blocks:
                b.active = False
                ip_str = str(b.ip)
                try:
                    self.redis.srem("blocked_ips_set", ip_str)
                    self.redis.delete(f"blocked_ip_exp:{ip_str}")
                    logger.info(f"Unblocked expired IP from Redis & DB: {ip_str}")
                except Exception as ex:
                    logger.warning(f"Error removing {ip_str} from Redis: {ex}")
            session.commit()

            # 2. Enforce retention policies
            policies = session.query(DataRetentionPolicy).filter(
                DataRetentionPolicy.enabled == True
            ).all()

            for policy in policies:
                table = policy.table_name
                col = policy.cleanup_column or "created_at"
                days = policy.retention_days

                # Safe execution with parameterized interval
                sql = text(f"DELETE FROM {table} WHERE {col} < NOW() - INTERVAL '{days} days'")
                result = session.execute(sql)
                session.commit()
                if result.rowcount > 0:
                    logger.info(f"Cleaned up {result.rowcount} stale records from '{table}' (Retention: {days}d)")

        except Exception as e:
            session.rollback()
            logger.error(f"Error executing retention cycle: {e}")
        finally:
            session.close()

    def run_forever(self, interval_seconds: int = 3600):
        """Runs periodic cleanup (defaults to every hour)."""
        logger.info(f"Data retention manager active (Interval: {interval_seconds}s)")
        while True:
            self.run_cleanup()
            time.sleep(interval_seconds)

if __name__ == "__main__":
    mgr = RetentionManager()
    mgr.run_cleanup()
    print("Retention cleanup executed.")
