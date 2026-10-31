"""
correlation_engine.py — Event correlation engine for the DB-Driven IDS/IPS.

Rule types supported:
  THRESHOLD        — count events in sliding window, alert if >= threshold_count
  SEQUENCE         — detect ordered event sequence within time window
  RATIO            — ratio of two event counts exceeds threshold
  GEO_FENCE        — src country not in / in allowed list
  IOC_MATCH        — src/dst ip present in ioc_ipv4/ioc_ipv6
  BEHAVIORAL       — metric deviates >3σ from user_behavior_profiles baseline
  LATERAL_MOVEMENT — IP connects to N new hosts in T seconds
  PROTOCOL_ANOMALY — packet fields deviate from expected protocol norms
  TLS_DOWNGRADE    — TLS version below acceptable minimum
  DNS_TUNNEL       — high query rate + long subdomains + many unique domains
  CANARY_ACCESS    — read from canary_tokens triggers immediate alert
"""

import os
import json
import time
import logging
import hashlib
import datetime
import threading
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text

from models import (
    get_db_session, get_redis, get_mongo_db,
    CorrelationRule, Alert, GeoRule, IocIPv4,
    UserBehaviorProfile, CanaryToken,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [correlation] %(levelname)s %(message)s",
)
log = logging.getLogger("correlation_engine")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TENANT_ID = os.environ.get("TENANT_ID", "00000000-0000-0000-0000-000000000001")
RULE_RELOAD_INTERVAL = int(os.environ.get("CORR_RULE_RELOAD_INTERVAL", "60"))
POLL_INTERVAL = float(os.environ.get("CORR_POLL_INTERVAL", "0.1"))
DEDUP_TTL = int(os.environ.get("ALERT_DEDUP_TTL", "60"))
REDIS_KEY_PREFIX = "corr:"

# ---------------------------------------------------------------------------
# In-memory rule cache
# ---------------------------------------------------------------------------

_rules: List[Dict] = []
_rules_lock = threading.RLock()


def _load_rules() -> List[Dict]:
    """Load all enabled CorrelationRules from PostgreSQL."""
    db = get_db_session()
    try:
        rows = db.query(CorrelationRule).filter(
            CorrelationRule.tenant_id == TENANT_ID,
            CorrelationRule.is_enabled == True,
        ).all()
        rules = []
        for r in rows:
            rules.append({
                "id": r.id,
                "name": r.name,
                "rule_type": r.rule_type,
                "severity": r.severity,
                "event_filter": r.event_filter or {},
                "window_seconds": r.window_seconds or 300,
                "threshold_count": r.threshold_count,
                "threshold_ratio": r.threshold_ratio,
                "sequence_events": r.sequence_events or [],
                "geo_config": r.geo_config or {},
                "behavioral_config": r.behavioral_config or {},
                "action": r.action,
                "playbook_id": r.playbook_id,
                "suppress_seconds": r.suppress_seconds or 60,
            })
        log.info("Loaded %d correlation rules.", len(rules))
        return rules
    except Exception as exc:
        log.error("Failed to load correlation rules: %s", exc)
        return []
    finally:
        db.close()


def reload_rules_periodically():
    """Background thread: reload rules every RULE_RELOAD_INTERVAL seconds."""
    global _rules
    while True:
        time.sleep(RULE_RELOAD_INTERVAL)
        new_rules = _load_rules()
        with _rules_lock:
            _rules = new_rules


# ---------------------------------------------------------------------------
# Alert deduplication via Redis
# ---------------------------------------------------------------------------

def _dedup_key(rule_id: int, src_ip: str) -> str:
    raw = f"{rule_id}:{src_ip}"
    return "alert_dedup:" + hashlib.sha256(raw.encode()).hexdigest()


def is_duplicate(rule_id: int, src_ip: str, suppress_seconds: int) -> bool:
    r = get_redis()
    key = _dedup_key(rule_id, src_ip)
    try:
        if r.get(key):
            return True
        r.setex(key, suppress_seconds, "1")
        return False
    except Exception as exc:
        log.warning("Redis dedup error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Alert insertion
# ---------------------------------------------------------------------------

_INSERT_ALERT_SQL = text("""
    INSERT INTO alerts
        (tenant_id, correlation_rule_id, title, description, severity, status,
         src_ip, dst_ip, src_port, dst_port, protocol, alert_ts, raw_event, tags)
    VALUES
        (:tenant_id, :rule_id, :title, :description, :severity, 'open',
         :src_ip, :dst_ip, :src_port, :dst_port, :protocol, NOW(), :raw_event::jsonb, :tags)
    RETURNING id
""")


def insert_alert(
    rule: Dict,
    event: Dict,
    description: str,
    db,
) -> Optional[int]:
    """Insert an alert row and return its id."""
    try:
        result = db.execute(
            _INSERT_ALERT_SQL,
            {
                "tenant_id": TENANT_ID,
                "rule_id": rule["id"],
                "title": f"[{rule['rule_type']}] {rule['name']}",
                "description": description,
                "severity": rule["severity"],
                "src_ip": event.get("src_ip"),
                "dst_ip": event.get("dst_ip"),
                "src_port": event.get("src_port"),
                "dst_port": event.get("dst_port"),
                "protocol": event.get("protocol"),
                "raw_event": json.dumps(event),
                "tags": [rule["rule_type"], rule["name"]],
            },
        )
        db.commit()
        row = result.fetchone()
        alert_id = row[0] if row else None
        log.info("Alert %s created for rule '%s'", alert_id, rule["name"])
        return alert_id
    except Exception as exc:
        log.error("Alert insert error: %s", exc)
        db.rollback()
        return None


# ---------------------------------------------------------------------------
# Playbook trigger
# ---------------------------------------------------------------------------

def trigger_playbook(playbook_id: int, alert_id: int):
    """Signal the action engine via Redis pub/sub."""
    r = get_redis()
    payload = json.dumps({"playbook_id": playbook_id, "alert_id": alert_id, "tenant_id": TENANT_ID})
    try:
        r.publish("playbook_trigger", payload)
    except Exception as exc:
        log.warning("Failed to publish playbook trigger: %s", exc)


# ---------------------------------------------------------------------------
# Redis sliding-window counter (ZADD + ZCOUNT)
# ---------------------------------------------------------------------------

def _sliding_count(redis_client, key: str, window_seconds: int, now_ts: float) -> int:
    """Increment and return count of events in sliding window using sorted set."""
    pipe = redis_client.pipeline()
    min_ts = now_ts - window_seconds
    member = f"{now_ts:.6f}"
    pipe.zadd(key, {member: now_ts})
    pipe.zremrangebyscore(key, "-inf", min_ts)
    pipe.zcard(key)
    pipe.expire(key, window_seconds + 10)
    results = pipe.execute()
    return results[2]  # zcard result


# ---------------------------------------------------------------------------
# Rule type handlers
# ---------------------------------------------------------------------------

def handle_threshold(rule: Dict, event: Dict, db) -> bool:
    """THRESHOLD: count events matching event_filter in window, fire if >= threshold_count."""
    src_ip = event.get("src_ip", "unknown")
    ef = rule["event_filter"]

    # Check that event matches filter
    for key, expected in ef.items():
        if event.get(key) != expected:
            return False

    redis_client = get_redis()
    key = f"{REDIS_KEY_PREFIX}threshold:{rule['id']}:{src_ip}"
    now_ts = time.time()
    count = _sliding_count(redis_client, key, rule["window_seconds"], now_ts)

    if count >= (rule["threshold_count"] or 10):
        if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
            return False
        desc = (
            f"Source IP {src_ip} triggered {count} events matching filter "
            f"{json.dumps(ef)} within {rule['window_seconds']}s "
            f"(threshold={rule['threshold_count']})."
        )
        alert_id = insert_alert(rule, event, desc, db)
        if alert_id and rule.get("playbook_id"):
            trigger_playbook(rule["playbook_id"], alert_id)
        return True
    return False


def handle_sequence(rule: Dict, event: Dict, db) -> bool:
    """SEQUENCE: detect ordered event sequence within time window."""
    src_ip = event.get("src_ip", "unknown")
    sequence = rule.get("sequence_events", [])
    if not sequence:
        return False

    redis_client = get_redis()
    state_key = f"{REDIS_KEY_PREFIX}seq:{rule['id']}:{src_ip}"
    now_ts = time.time()

    # Load current sequence progress
    try:
        raw = redis_client.get(state_key)
        state = json.loads(raw) if raw else {"step": 0, "ts": now_ts}
    except Exception:
        state = {"step": 0, "ts": now_ts}

    # Timeout — reset if window exceeded
    if now_ts - state["ts"] > rule["window_seconds"]:
        state = {"step": 0, "ts": now_ts}

    step = state["step"]
    if step >= len(sequence):
        state = {"step": 0, "ts": now_ts}
        step = 0

    # Check if current event matches current sequence step
    step_filter = sequence[step] if isinstance(sequence[step], dict) else {}
    match = all(event.get(k) == v for k, v in step_filter.items())
    if match:
        state["step"] = step + 1
        state["ts"] = now_ts
        redis_client.setex(state_key, rule["window_seconds"] + 10, json.dumps(state))

        if state["step"] >= len(sequence):
            # Full sequence matched
            if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
                return False
            desc = (
                f"Source IP {src_ip} completed threat sequence '{rule['name']}' "
                f"({len(sequence)} steps) within {rule['window_seconds']}s."
            )
            alert_id = insert_alert(rule, event, desc, db)
            redis_client.delete(state_key)
            if alert_id and rule.get("playbook_id"):
                trigger_playbook(rule["playbook_id"], alert_id)
            return True
    else:
        redis_client.setex(state_key, rule["window_seconds"] + 10, json.dumps(state))

    return False


def handle_ratio(rule: Dict, event: Dict, db) -> bool:
    """RATIO: calculate ratio between two event counts, alert if exceeds threshold."""
    src_ip = event.get("src_ip", "unknown")
    ef = rule["event_filter"]
    numerator_filter = ef.get("numerator", {})
    denominator_filter = ef.get("denominator", {})

    redis_client = get_redis()
    now_ts = time.time()

    # Match numerator
    num_match = all(event.get(k) == v for k, v in numerator_filter.items())
    if num_match:
        num_key = f"{REDIS_KEY_PREFIX}ratio_num:{rule['id']}:{src_ip}"
        _sliding_count(redis_client, num_key, rule["window_seconds"], now_ts)

    # Match denominator
    den_match = all(event.get(k) == v for k, v in denominator_filter.items())
    if den_match:
        den_key = f"{REDIS_KEY_PREFIX}ratio_den:{rule['id']}:{src_ip}"
        _sliding_count(redis_client, den_key, rule["window_seconds"], now_ts)

    # Evaluate ratio
    try:
        num_key = f"{REDIS_KEY_PREFIX}ratio_num:{rule['id']}:{src_ip}"
        den_key = f"{REDIS_KEY_PREFIX}ratio_den:{rule['id']}:{src_ip}"
        numerator = int(redis_client.zcard(num_key) or 0)
        denominator = int(redis_client.zcard(den_key) or 1)
        if denominator == 0:
            return False
        ratio = numerator / denominator
        threshold = rule.get("threshold_ratio") or 0.5
        if ratio >= threshold and numerator >= 5:  # min sample
            if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
                return False
            desc = (
                f"Source IP {src_ip} ratio {ratio:.2f} >= threshold {threshold:.2f} "
                f"(num={numerator}, den={denominator}) for rule '{rule['name']}'."
            )
            alert_id = insert_alert(rule, event, desc, db)
            if alert_id and rule.get("playbook_id"):
                trigger_playbook(rule["playbook_id"], alert_id)
            return True
    except Exception as exc:
        log.warning("Ratio evaluation error: %s", exc)
    return False


def handle_geo_fence(rule: Dict, event: Dict, db) -> bool:
    """GEO_FENCE: check src country against geo_rules table."""
    src_ip = event.get("src_ip")
    if not src_ip:
        return False

    geo_config = rule.get("geo_config", {})
    blocked_countries = geo_config.get("blocked_countries", [])
    allowed_countries = geo_config.get("allowed_countries", [])

    # Look up session country from DB
    db_session = get_db_session()
    try:
        row = db_session.execute(
            text("SELECT country_src FROM sessions WHERE src_ip=:ip ORDER BY last_seen DESC LIMIT 1"),
            {"ip": src_ip},
        ).fetchone()
        if not row:
            return False
        country = row[0]
    except Exception:
        return False
    finally:
        db_session.close()

    fired = False
    if blocked_countries and country in blocked_countries:
        fired = True
    if allowed_countries and country not in allowed_countries:
        fired = True

    if fired:
        if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
            return False
        desc = (
            f"Source IP {src_ip} (country={country}) triggered geo-fence rule '{rule['name']}'. "
            f"blocked_countries={blocked_countries}, allowed_countries={allowed_countries}."
        )
        alert_id = insert_alert(rule, event, desc, db)
        if alert_id and rule.get("playbook_id"):
            trigger_playbook(rule["playbook_id"], alert_id)
        return True
    return False


def handle_ioc_match(rule: Dict, event: Dict, db) -> bool:
    """IOC_MATCH: check src_ip/dst_ip against ioc_ipv4 (index lookup)."""
    for field in ("src_ip", "dst_ip"):
        ip = event.get(field)
        if not ip:
            continue
        try:
            row = db.execute(
                text("""
                    SELECT id, confidence, threat_type FROM ioc_ipv4
                    WHERE ip = :ip
                    AND (expires_at IS NULL OR expires_at > NOW())
                    LIMIT 1
                """),
                {"ip": ip},
            ).fetchone()
            if row:
                if is_duplicate(rule["id"], ip, rule["suppress_seconds"]):
                    return False
                desc = (
                    f"{field}={ip} matched IOC entry "
                    f"(confidence={row[1]:.1f}%, threat_type={row[2]}) "
                    f"for rule '{rule['name']}'."
                )
                alert_id = insert_alert(rule, event, desc, db)
                if alert_id and rule.get("playbook_id"):
                    trigger_playbook(rule["playbook_id"], alert_id)
                return True
        except Exception as exc:
            log.warning("IOC match DB error: %s", exc)
    return False


def handle_behavioral(rule: Dict, event: Dict, db) -> bool:
    """BEHAVIORAL: compare metric to user_behavior_profiles baseline (3-sigma)."""
    src_ip = event.get("src_ip")
    if not src_ip:
        return False

    bconfig = rule.get("behavioral_config", {})
    feature_name = bconfig.get("feature_name", "packets_per_second_from_ip")
    metric_value = event.get(feature_name)
    if metric_value is None:
        return False

    try:
        row = db.execute(
            text("""
                SELECT mean, std_dev FROM user_behavior_profiles
                WHERE entity_type='IP' AND entity_id=:ip AND feature_name=:fname
                LIMIT 1
            """),
            {"ip": src_ip, "fname": feature_name},
        ).fetchone()
        if not row:
            return False
        mean, std_dev = row[0], row[1]
        if std_dev == 0:
            return False
        z_score = abs(metric_value - mean) / std_dev
        sigma_threshold = bconfig.get("sigma_threshold", 3.0)
        if z_score >= sigma_threshold:
            if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
                return False
            desc = (
                f"Behavioral anomaly: IP {src_ip} feature '{feature_name}'={metric_value:.3f} "
                f"deviates {z_score:.1f}σ from baseline (mean={mean:.3f}, std={std_dev:.3f})."
            )
            alert_id = insert_alert(rule, event, desc, db)
            if alert_id and rule.get("playbook_id"):
                trigger_playbook(rule["playbook_id"], alert_id)
            return True
    except Exception as exc:
        log.warning("Behavioral rule error: %s", exc)
    return False


def handle_lateral_movement(rule: Dict, event: Dict, db) -> bool:
    """LATERAL_MOVEMENT: detect IP connecting to N new hosts in T seconds."""
    src_ip = event.get("src_ip")
    dst_ip = event.get("dst_ip")
    if not src_ip or not dst_ip:
        return False

    bconfig = rule.get("behavioral_config", {})
    new_host_threshold = bconfig.get("new_host_threshold", 10)

    redis_client = get_redis()
    now_ts = time.time()
    key = f"{REDIS_KEY_PREFIX}lateral:{rule['id']}:{src_ip}"

    try:
        pipe = redis_client.pipeline()
        pipe.zadd(key, {dst_ip: now_ts})
        pipe.zremrangebyscore(key, "-inf", now_ts - rule["window_seconds"])
        pipe.zcard(key)
        pipe.expire(key, rule["window_seconds"] + 10)
        results = pipe.execute()
        unique_hosts = results[2]

        if unique_hosts >= new_host_threshold:
            if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
                return False
            desc = (
                f"Lateral movement detected: IP {src_ip} connected to "
                f"{unique_hosts} unique hosts in {rule['window_seconds']}s "
                f"(threshold={new_host_threshold})."
            )
            alert_id = insert_alert(rule, event, desc, db)
            if alert_id and rule.get("playbook_id"):
                trigger_playbook(rule["playbook_id"], alert_id)
            return True
    except Exception as exc:
        log.warning("Lateral movement rule error: %s", exc)
    return False


def handle_protocol_anomaly(rule: Dict, event: Dict, db) -> bool:
    """PROTOCOL_ANOMALY: check against protocol_anomalies table."""
    protocol = event.get("protocol")
    src_port = event.get("src_port")
    dst_port = event.get("dst_port")
    if not protocol:
        return False

    ef = rule.get("event_filter", {})
    expected_protocol = ef.get("protocol")
    expected_ports = ef.get("expected_ports", [])

    anomaly_found = False
    reason = ""

    if expected_protocol and protocol != expected_protocol:
        anomaly_found = True
        reason = f"Unexpected protocol {protocol} (expected {expected_protocol})"

    if expected_ports and dst_port not in expected_ports:
        anomaly_found = True
        reason = f"Unexpected dst_port {dst_port} for protocol {protocol} (expected {expected_ports})"

    if anomaly_found:
        src_ip = event.get("src_ip", "unknown")
        if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
            return False
        desc = f"Protocol anomaly detected: {reason}. Rule: '{rule['name']}'."
        alert_id = insert_alert(rule, event, desc, db)
        if alert_id and rule.get("playbook_id"):
            trigger_playbook(rule["playbook_id"], alert_id)
        return True
    return False


def handle_tls_downgrade(rule: Dict, event: Dict, db) -> bool:
    """TLS_DOWNGRADE: check TLS version from session fingerprint / raw event."""
    protocol = event.get("protocol")
    dst_port = event.get("dst_port")
    if protocol != "TCP" or dst_port not in (443, 8443):
        return False

    tls_version = event.get("tls_version")
    if tls_version is None:
        return False

    ef = rule.get("event_filter", {})
    min_version = ef.get("min_tls_version", 0x0303)  # TLS 1.2 default

    if tls_version < min_version:
        src_ip = event.get("src_ip", "unknown")
        if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
            return False
        version_str = {0x0300: "SSL3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
                       0x0303: "TLS1.2", 0x0304: "TLS1.3"}.get(tls_version, hex(tls_version))
        desc = (
            f"TLS downgrade detected from {src_ip}: version={version_str} "
            f"is below minimum {hex(min_version)}."
        )
        alert_id = insert_alert(rule, event, desc, db)
        if alert_id and rule.get("playbook_id"):
            trigger_playbook(rule["playbook_id"], alert_id)
        return True
    return False


def handle_dns_tunnel(rule: Dict, event: Dict, db) -> bool:
    """DNS_TUNNEL: high query rate + long subdomain names + many unique queries."""
    if event.get("protocol") not in ("UDP", "TCP") or event.get("dst_port") != 53:
        if "DNS" not in event.get("layers", []):
            return False

    src_ip = event.get("src_ip", "unknown")
    dns_queries = event.get("dns_queries", [])
    if not dns_queries:
        return False

    redis_client = get_redis()
    now_ts = time.time()
    window = rule["window_seconds"]

    ef = rule.get("event_filter", {})
    max_label_len = ef.get("max_label_len", 40)
    unique_threshold = ef.get("unique_query_threshold", 50)
    rate_threshold = ef.get("rate_per_window", 100)

    # Count queries
    rate_key = f"{REDIS_KEY_PREFIX}dns_rate:{rule['id']}:{src_ip}"
    for qname in dns_queries:
        _sliding_count(redis_client, rate_key, window, now_ts)

    # Count unique queries
    uniq_key = f"{REDIS_KEY_PREFIX}dns_uniq:{rule['id']}:{src_ip}"
    for qname in dns_queries:
        redis_client.sadd(uniq_key, qname)
    redis_client.expire(uniq_key, window + 10)

    total_queries = int(redis_client.zcard(rate_key) or 0)
    unique_queries = int(redis_client.scard(uniq_key) or 0)
    max_label = max((len(q.split(".")[0]) for q in dns_queries), default=0)

    suspicious = (
        total_queries >= rate_threshold
        or unique_queries >= unique_threshold
        or max_label >= max_label_len
    )
    if suspicious:
        if is_duplicate(rule["id"], src_ip, rule["suppress_seconds"]):
            return False
        desc = (
            f"Possible DNS tunnel from {src_ip}: "
            f"total_queries={total_queries}, unique={unique_queries}, "
            f"max_label_len={max_label} in {window}s."
        )
        alert_id = insert_alert(rule, event, desc, db)
        if alert_id and rule.get("playbook_id"):
            trigger_playbook(rule["playbook_id"], alert_id)
        return True
    return False


def handle_canary_access(rule: Dict, event: Dict, db) -> bool:
    """CANARY_ACCESS: any access to canary_tokens triggers an alert."""
    canary_token = event.get("canary_token")
    if not canary_token:
        return False

    src_ip = event.get("src_ip", "unknown")
    try:
        row = db.execute(
            text("SELECT id, description FROM canary_tokens WHERE token=:tok AND is_active=true LIMIT 1"),
            {"tok": canary_token},
        ).fetchone()
        if row:
            # Update trigger count
            db.execute(
                text("""
                    UPDATE canary_tokens
                    SET trigger_count = trigger_count + 1, last_triggered_at = NOW()
                    WHERE id = :id
                """),
                {"id": row[0]},
            )
            db.commit()
            desc = (
                f"Canary token accessed by {src_ip}! "
                f"Token description: {row[1]}. "
                f"This indicates unauthorized access."
            )
            alert_id = insert_alert(rule, event, desc, db)
            if alert_id and rule.get("playbook_id"):
                trigger_playbook(rule["playbook_id"], alert_id)
            return True
    except Exception as exc:
        log.warning("Canary access check error: %s", exc)
    return False


# ---------------------------------------------------------------------------
# Rule dispatcher
# ---------------------------------------------------------------------------

RULE_HANDLERS = {
    "THRESHOLD": handle_threshold,
    "SEQUENCE": handle_sequence,
    "RATIO": handle_ratio,
    "GEO_FENCE": handle_geo_fence,
    "IOC_MATCH": handle_ioc_match,
    "BEHAVIORAL": handle_behavioral,
    "LATERAL_MOVEMENT": handle_lateral_movement,
    "PROTOCOL_ANOMALY": handle_protocol_anomaly,
    "TLS_DOWNGRADE": handle_tls_downgrade,
    "DNS_TUNNEL": handle_dns_tunnel,
    "CANARY_ACCESS": handle_canary_access,
}


def process_event(event: Dict, db):
    """Evaluate an event against all loaded correlation rules."""
    with _rules_lock:
        rules_snapshot = list(_rules)

    for rule in rules_snapshot:
        handler = RULE_HANDLERS.get(rule["rule_type"])
        if handler is None:
            continue
        try:
            handler(rule, event, db)
        except Exception as exc:
            log.error("Rule '%s' (type=%s) raised error: %s", rule["name"], rule["rule_type"], exc)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run(event_queue):
    """
    Consume events from event_queue and evaluate correlation rules.
    event_queue: multiprocessing.Queue fed by packet_capture.
    """
    global _rules

    log.info("Correlation engine starting.")
    _rules = _load_rules()

    # Start reload thread
    t_reload = threading.Thread(target=reload_rules_periodically, daemon=True)
    t_reload.start()

    db = get_db_session()
    log.info("Correlation engine ready. Polling for events...")

    while True:
        try:
            try:
                event = event_queue.get(timeout=1.0)
            except Exception:
                continue  # queue empty timeout

            process_event(event, db)

        except KeyboardInterrupt:
            log.info("Correlation engine shutting down.")
            break
        except Exception as exc:
            log.exception("Unexpected error in correlation loop: %s", exc)
            time.sleep(1)

    db.close()
