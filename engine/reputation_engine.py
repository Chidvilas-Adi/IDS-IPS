"""
reputation_engine.py — IP Threat Reputation & Automated Tier Promotion

Maintains PostgreSQL ip_reputation table, caches hot reputation scores in Redis,
decays scores for inactive benign IPs, and automatically escalates critical-score
IPs directly to the firewall blocklist.
"""

import time
import logging
from datetime import datetime, timedelta

from models import get_db_session, get_redis, IpReputation, BlockedIp
from action_engine import ActionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Reputation] %(message)s")
logger = logging.getLogger("Reputation")

class ReputationEngine:
    def __init__(self):
        self.redis = get_redis()
        self.action_engine = ActionEngine()

    def get_reputation(self, ip: str) -> int:
        """Fetch reputation score with Redis caching for sub-millisecond retrieval."""
        cache_key = f"rep_score:{ip}"
        cached = self.redis.get(cache_key)
        if cached is not None:
            return int(cached)

        session = get_db_session()
        try:
            entry = session.query(IpReputation).filter(IpReputation.ip == ip).first()
            score = entry.score if entry else 0
            self.redis.set(cache_key, score, ex=120)
            return score
        except Exception as e:
            logger.error(f"Error reading reputation for {ip}: {e}")
            return 0
        finally:
            session.close()

    def decay_and_escalate(self):
        """Decay idle scores and escalate high-threat IPs to the active blocklist."""
        session = get_db_session()
        try:
            # 1. Escalate IPs with score >= 85 to Blocked list
            high_threats = session.query(IpReputation).filter(
                IpReputation.score >= 85
            ).all()

            for rep in high_threats:
                ip_str = str(rep.ip)
                already_blocked = session.query(BlockedIp).filter(
                    BlockedIp.ip == rep.ip, BlockedIp.active == True
                ).first()
                if not already_blocked:
                    logger.warning(f"Escalating IP {ip_str} to Blocklist (Reputation Score: {rep.score})")
                    self.action_engine.block_ip(
                        ip=ip_str,
                        duration_minutes=240,
                        reason=f"Reputation score exceeded threshold ({rep.score})"
                    )

            # 2. Decay inactive IPs (inactive for > 48 hours)
            idle_cutoff = datetime.utcnow() - timedelta(days=2)
            idlers = session.query(IpReputation).filter(
                IpReputation.last_seen < idle_cutoff,
                IpReputation.score > 0
            ).all()

            for rep in idlers:
                rep.score = max(0, rep.score - 5)
            session.commit()

        except Exception as e:
            session.rollback()
            logger.error(f"Error in reputation decay cycle: {e}")
        finally:
            session.close()

    def run_forever(self, interval_seconds: int = 300):
        """Continuous background reputation maintenance loop."""
        logger.info(f"Reputation engine maintenance loop started (Interval: {interval_seconds}s)")
        while True:
            try:
                self.decay_and_escalate()
            except Exception as e:
                logger.error(f"Reputation cycle error: {e}")
            time.sleep(interval_seconds)

if __name__ == "__main__":
    engine = ReputationEngine()
    engine.decay_and_escalate()
    print("Reputation maintenance cycle completed.")
