#!/usr/bin/env python3
"""
verify_db_live.py — Real-Time Health & Database Interception Verifier

Connects to PostgreSQL, MongoDB, and Redis to verify that:
1. All tables and collections are healthy.
2. Ingress packets are being parsed into sessions and raw_packets.
3. Fired alerts are stored in PostgreSQL.
4. Auto-blocked IPs are active in both PostgreSQL and Redis.
"""

import os
import sys

# Add parent and engine directories to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "engine")))

try:
    from models import get_db_session, get_redis, get_mongo_db, Alert, Session, BlockedIp, CorrelationRule, DpiSignature
    from sqlalchemy import text
except ImportError as e:
    print(f"Error importing engine models: {e}")
    sys.exit(1)

def main():
    print("=================================================================")
    print("   DB-IDS/IPS REAL-TIME DATABASE HEALTH & VERIFICATION CHECK   ")
    print("=================================================================\n")

    # 1. PostgreSQL Check
    print("[1/3] Checking PostgreSQL Relational Rules & Alert Store...")
    try:
        session = get_db_session()
        rule_count = session.query(CorrelationRule).count()
        dpi_count = session.query(DpiSignature).count()
        session_count = session.query(Session).count()
        alert_count = session.query(Alert).count()
        blocked_count = session.query(BlockedIp).filter(BlockedIp.active == True).count()

        print(f"  [+] PostgreSQL Connection:  OK")
        print(f"  [+] Active Correlation Rules: {rule_count}")
        print(f"  [+] DPI Signatures:           {dpi_count}")
        print(f"  [+] Sessions Recorded:        {session_count}")
        print(f"  [+] Total Alerts Logged:      {alert_count}")
        print(f"  [+] Active Blocked IPs:       {blocked_count}")

        if alert_count > 0:
            print("\n  --- Latest 3 Fired Alerts in Database ---")
            latest_alerts = session.query(Alert).order_by(Alert.id.desc()).limit(3).all()
            for a in latest_alerts:
                print(f"  - Alert #{a.id} [{a.severity}] from {a.src_ip} -> {a.dst_ip}:{a.dst_port} ({a.rule_type})")
        session.close()
    except Exception as e:
        print(f"  [!] PostgreSQL Check Failed: {e}")

    # 2. Redis Check
    print("\n[2/3] Checking Redis Hot-Path & O(1) Blocklist Cache...")
    try:
        r = get_redis()
        r.ping()
        blocked_set = r.smembers("blocked_ips_set")
        print(f"  [+] Redis Connection:         OK")
        print(f"  [+] Cached Blocked IPs:       {len(blocked_set)}: {list(blocked_set)}")
    except Exception as e:
        print(f"  [!] Redis Check Failed: {e}")

    # 3. MongoDB Check
    print("\n[3/3] Checking MongoDB NoSQL Raw Packet Store...")
    try:
        mdb = get_mongo_db()
        raw_pkt_count = mdb.raw_packets.count_documents({})
        dns_count = mdb.dns_query_log.count_documents({})
        threat_count = mdb.threat_intel_raw.count_documents({})
        print(f"  [+] MongoDB Connection:       OK")
        print(f"  [+] Stored Raw Packets:       {raw_pkt_count}")
        print(f"  [+] DNS Transaction Logs:     {dns_count}")
        print(f"  [+] Raw Threat Intel Feeds:   {threat_count}")
    except Exception as e:
        print(f"  [!] MongoDB Check Failed: {e}")

    print("\n=================================================================")
    print("   VERIFICATION SUMMARY COMPLETE                                ")
    print("=================================================================\n")

if __name__ == "__main__":
    main()
