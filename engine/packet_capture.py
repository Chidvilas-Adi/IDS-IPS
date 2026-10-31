"""
packet_capture.py — High-performance packet capture engine for the DB-Driven IDS/IPS.

Responsibilities:
  - Sniff packets on the configured interface using Scapy
  - Check Redis blocked_ips_set (O(1)) and drop blocked packets immediately
  - Parse Ethernet, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, HTTP, Raw layers
  - Extract JA3 fingerprints from TLS ClientHello (manual TLS record parser)
  - Extract HASSH fingerprints from SSH handshake KEX_INIT packets
  - Upsert session records in PostgreSQL
  - Write raw packets to MongoDB with TTL
  - Put parsed events onto a multiprocessing Queue for DPI + Correlation engines
  - Periodically flush packet metrics to TimescaleDB flow_records
  - Graceful shutdown on SIGINT/SIGTERM
"""

import os
import sys
import time
import signal
import struct
import hashlib
import logging
import datetime
import multiprocessing
from collections import defaultdict
from typing import Optional, Dict, Any

from dotenv import load_dotenv
load_dotenv()

from scapy.all import (
    sniff, Ether, ARP, IP, IPv6, TCP, UDP, ICMP, Raw, Packet,
    DNS, DNSQR,
)

# Scapy HTTP layer — imported separately so failure is non-fatal
try:
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False

from models import get_db_session, get_redis, get_mongo_db
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [packet_capture] %(levelname)s %(message)s",
)
log = logging.getLogger("packet_capture")

# ---------------------------------------------------------------------------
# Configuration (from environment)
# ---------------------------------------------------------------------------

IFACE = os.environ.get("CAPTURE_INTERFACE", "eth0")
TENANT_ID = os.environ.get("TENANT_ID", "00000000-0000-0000-0000-000000000001")
MONGO_RAW_TTL_HOURS = int(os.environ.get("MONGO_RAW_TTL_HOURS", "72"))
FLUSH_INTERVAL_SEC = int(os.environ.get("PACKET_FLUSH_INTERVAL", "10"))
BLOCKED_IPS_REDIS_KEY = "blocked_ips_set"
RULE_CACHE_PREFIX = "rule_cache:"

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

_shutdown = multiprocessing.Event()

# Per-worker stats counters
_stats: Dict[str, int] = defaultdict(int)
_stats_lock = None  # set in worker process

# ---------------------------------------------------------------------------
# JA3 / TLS ClientHello parser
# ---------------------------------------------------------------------------

_TLS_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def _parse_tls_extensions(data: bytes, offset: int, length: int):
    """Parse TLS extensions from a ClientHello, return (SNI, supported_groups, ec_point_formats, sig_algs)."""
    end = offset + length
    sni_list: list = []
    supported_groups: list = []
    ec_point_fmts: list = []
    sig_algs: list = []

    while offset + 4 <= end:
        ext_type = struct.unpack("!H", data[offset:offset + 2])[0]
        ext_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        offset += 4
        ext_data = data[offset:offset + ext_len]
        offset += ext_len

        if ext_type == 0x0000 and len(ext_data) >= 5:  # SNI
            sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
            pos = 2
            while pos < 2 + sni_list_len:
                name_type = ext_data[pos]
                name_len = struct.unpack("!H", ext_data[pos + 1:pos + 3])[0]
                if name_type == 0:
                    sni_list.append(ext_data[pos + 3:pos + 3 + name_len].decode(errors="ignore"))
                pos += 3 + name_len

        elif ext_type == 0x000a and len(ext_data) >= 2:  # supported_groups
            gl = struct.unpack("!H", ext_data[0:2])[0]
            for i in range(2, 2 + gl, 2):
                if i + 2 <= len(ext_data):
                    g = struct.unpack("!H", ext_data[i:i + 2])[0]
                    if g not in _TLS_GREASE:
                        supported_groups.append(g)

        elif ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
            fmts_len = ext_data[0]
            ec_point_fmts.extend(list(ext_data[1:1 + fmts_len]))

        elif ext_type == 0x000d and len(ext_data) >= 2:  # signature_algorithms
            sa_len = struct.unpack("!H", ext_data[0:2])[0]
            for i in range(2, 2 + sa_len, 2):
                if i + 2 <= len(ext_data):
                    sig_algs.append(struct.unpack("!H", ext_data[i:i + 2])[0])

    return sni_list, supported_groups, ec_point_fmts, sig_algs


def extract_ja3(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello from raw bytes and compute the JA3 fingerprint.
    Returns None if the payload is not a valid TLS ClientHello.
    """
    try:
        if len(payload) < 5:
            return None
        # TLS record layer: content_type=0x16, version >= 0x0300, length
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None

        record_len = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + record_len:
            return None

        handshake = payload[5:5 + record_len]
        if len(handshake) < 4 or handshake[0] != 0x01:  # ClientHello type
            return None

        # Handshake message length (3 bytes)
        hs_len = struct.unpack("!I", b"\x00" + handshake[1:4])[0]
        data = handshake[4:4 + hs_len]
        if len(data) < 34:
            return None

        tls_version = struct.unpack("!H", data[0:2])[0]
        # skip 32-byte random
        offset = 34
        # session id
        sid_len = data[offset]
        offset += 1 + sid_len

        if offset + 2 > len(data):
            return None

        # cipher suites
        cs_len = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            cs = struct.unpack("!H", data[offset + i:offset + i + 2])[0]
            if cs not in _TLS_GREASE and cs != 0x00ff:
                cipher_suites.append(cs)
        offset += cs_len

        # compression methods
        cm_len = data[offset]
        offset += 1 + cm_len

        # extensions
        extensions_types = []
        supported_groups: list = []
        ec_point_fmts: list = []
        sig_algs: list = []

        if offset + 2 <= len(data):
            ext_total_len = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len
            ext_pos = offset

            while ext_pos + 4 <= ext_end:
                et = struct.unpack("!H", data[ext_pos:ext_pos + 2])[0]
                el = struct.unpack("!H", data[ext_pos + 2:ext_pos + 4])[0]
                if et not in _TLS_GREASE:
                    extensions_types.append(et)
                ext_pos += 4 + el

            _, supported_groups, ec_point_fmts, _ = _parse_tls_extensions(data, offset, ext_total_len)

        ja3_str = (
            f"{tls_version}"
            f"-{','.join(str(c) for c in cipher_suites)}"
            f"-{','.join(str(e) for e in extensions_types)}"
            f"-{','.join(str(g) for g in supported_groups)}"
            f"-{','.join(str(f) for f in ec_point_fmts)}"
        )
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HASSH fingerprint extraction from SSH KEX_INIT
# ---------------------------------------------------------------------------

def extract_hassh(payload: bytes) -> Optional[str]:
    """
    Parse SSH handshake from raw bytes, extract HASSH fingerprint.
    HASSH = md5(kex_algorithms;enc_c2s;mac_c2s;compression_c2s)
    """
    try:
        # SSH banner check
        if payload[:4] == b"SSH-":
            return None  # this is the banner, not KEX_INIT

        # SSH binary packet: uint32 packet_length, byte padding_length, payload...
        if len(payload) < 6:
            return None

        pkt_len = struct.unpack("!I", payload[0:4])[0]
        padding_len = payload[4]
        msg_type = payload[5]

        # MSG_KEXINIT = 20
        if msg_type != 20:
            return None

        if len(payload) < 6 + 16:
            return None

        # Skip 16-byte cookie
        pos = 6 + 16

        def read_name_list(data: bytes, offset: int):
            if offset + 4 > len(data):
                return [], offset
            length = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4
            if offset + length > len(data):
                return [], offset + length
            names = data[offset:offset + length].decode(errors="ignore").split(",")
            return names, offset + length

        kex_algs, pos = read_name_list(payload, pos)
        _server_host_key_algs, pos = read_name_list(payload, pos)
        enc_c2s, pos = read_name_list(payload, pos)
        _enc_s2c, pos = read_name_list(payload, pos)
        mac_c2s, pos = read_name_list(payload, pos)
        _mac_s2c, pos = read_name_list(payload, pos)
        comp_c2s, pos = read_name_list(payload, pos)

        hassh_str = (
            f"{','.join(kex_algs)};{','.join(enc_c2s)};"
            f"{','.join(mac_c2s)};{','.join(comp_c2s)}"
        )
        return hashlib.md5(hassh_str.encode()).hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Packet parser
# ---------------------------------------------------------------------------

def parse_packet(pkt: Packet) -> Optional[Dict[str, Any]]:
    """
    Dissect a Scapy packet and return a structured dict.
    Returns None for non-IP/ARP frames.
    """
    parsed: Dict[str, Any] = {
        "ts": datetime.datetime.utcnow().isoformat(),
        "packet_length": len(pkt),
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "ttl": None,
        "window_size": None,
        "tcp_flags": None,
        "payload_hex": None,
        "raw_bytes_len": 0,
        "layers": [],
        "is_arp": False,
        "arp_op": None,
        "arp_hwsrc": None,
        "arp_hwdst": None,
        "dns_queries": [],
        "http_method": None,
        "http_uri": None,
        "http_headers": {},
        "http_body_hex": None,
        "is_ipv6": False,
        "ja3": None,
        "hassh": None,
    }

    # ARP
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        parsed["is_arp"] = True
        parsed["protocol"] = "ARP"
        parsed["src_ip"] = arp.psrc
        parsed["dst_ip"] = arp.pdst
        parsed["arp_op"] = arp.op
        parsed["arp_hwsrc"] = arp.hwsrc
        parsed["arp_hwdst"] = arp.hwdst
        parsed["layers"].append("ARP")
        return parsed

    # IPv6
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        parsed["is_ipv6"] = True
        parsed["src_ip"] = ip6.src
        parsed["dst_ip"] = ip6.dst
        parsed["ttl"] = ip6.hlim
        parsed["layers"].append("IPv6")
        next_hdr = ip6.nh
        if next_hdr == 6:
            parsed["protocol"] = "TCP"
        elif next_hdr == 17:
            parsed["protocol"] = "UDP"
        elif next_hdr == 58:
            parsed["protocol"] = "ICMPv6"
        else:
            parsed["protocol"] = f"IPv6-{next_hdr}"

    # IP
    elif pkt.haslayer(IP):
        ip = pkt[IP]
        parsed["src_ip"] = ip.src
        parsed["dst_ip"] = ip.dst
        parsed["ttl"] = ip.ttl
        parsed["layers"].append("IP")
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 41: "IPv6"}
        parsed["protocol"] = proto_map.get(ip.proto, str(ip.proto))
    else:
        return None  # skip non-IP/ARP

    # TCP
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        parsed["src_port"] = tcp.sport
        parsed["dst_port"] = tcp.dport
        parsed["window_size"] = tcp.window
        flags = []
        flag_map = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
                    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
        for f, name in flag_map.items():
            if tcp.flags & getattr(tcp.flags, f, 0):
                flags.append(name)
        parsed["tcp_flags"] = "|".join(flags) if flags else str(tcp.flags)
        parsed["layers"].append("TCP")

    # UDP
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        parsed["src_port"] = udp.sport
        parsed["dst_port"] = udp.dport
        parsed["layers"].append("UDP")

    # ICMP
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        parsed["protocol"] = "ICMP"
        parsed["layers"].append("ICMP")

    # DNS
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        parsed["layers"].append("DNS")
        if dns.qr == 0 and dns.qdcount > 0:  # query
            for i in range(dns.qdcount):
                try:
                    qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                    parsed["dns_queries"].append(qname)
                except Exception:
                    pass

    # HTTP (scapy-http)
    if _HTTP_AVAILABLE and pkt.haslayer(HTTPRequest):
        req = pkt[HTTPRequest]
        parsed["layers"].append("HTTP")
        parsed["http_method"] = req.Method.decode(errors="ignore") if req.Method else None
        parsed["http_uri"] = req.Path.decode(errors="ignore") if req.Path else None
        headers = {}
        for field in req.fields:
            val = getattr(req, field, None)
            if isinstance(val, bytes):
                val = val.decode(errors="ignore")
            headers[field] = val
        parsed["http_headers"] = headers

    # Raw payload
    if pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw].load)
        parsed["payload_hex"] = raw_data.hex()
        parsed["raw_bytes_len"] = len(raw_data)
        parsed["layers"].append("Raw")

        # JA3 from TLS ClientHello
        if parsed.get("dst_port") == 443 or parsed.get("src_port") == 443:
            ja3 = extract_ja3(raw_data)
            if ja3:
                parsed["ja3"] = ja3

        # HASSH from SSH
        if parsed.get("dst_port") == 22 or parsed.get("src_port") == 22:
            hassh = extract_hassh(raw_data)
            if hassh:
                parsed["hassh"] = hassh

    return parsed


# ---------------------------------------------------------------------------
# Redis fast-path check
# ---------------------------------------------------------------------------

def is_blocked(ip: str, redis_client) -> bool:
    """O(1) check whether an IP is in the Redis blocked set."""
    try:
        return bool(redis_client.sismember(BLOCKED_IPS_REDIS_KEY, ip))
    except Exception as exc:
        log.warning("Redis SISMEMBER error: %s", exc)
        return False


def get_cached_rule_action(src_ip: str, dst_ip: str, protocol: str, redis_client) -> Optional[str]:
    """Check Redis rule_cache for a quick-match action."""
    try:
        key = f"{RULE_CACHE_PREFIX}{protocol}:{src_ip}:{dst_ip}"
        return redis_client.get(key)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PostgreSQL session upsert
# ---------------------------------------------------------------------------

_SESSION_UPSERT_SQL = text("""
    INSERT INTO sessions
        (tenant_id, src_ip, dst_ip, src_port, dst_port, protocol, state,
         bytes_out, packets_out, first_seen, last_seen, tcp_flags, metadata)
    VALUES
        (:tenant_id, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, 'NEW',
         :pkt_len, 1, NOW(), NOW(), :tcp_flags, :meta::jsonb)
    ON CONFLICT (src_ip, dst_ip, src_port, dst_port, protocol, first_seen)
    DO UPDATE SET
        bytes_out   = sessions.bytes_out + :pkt_len,
        packets_out = sessions.packets_out + 1,
        last_seen   = NOW(),
        tcp_flags   = EXCLUDED.tcp_flags
    RETURNING id
""")


def upsert_session(parsed: Dict[str, Any], db) -> Optional[int]:
    """Upsert a session row in PostgreSQL. Returns the session id."""
    import json
    try:
        meta = json.dumps({
            "layers": parsed.get("layers", []),
            "window_size": parsed.get("window_size"),
            "ttl": parsed.get("ttl"),
        })
        result = db.execute(
            _SESSION_UPSERT_SQL,
            {
                "tenant_id": TENANT_ID,
                "src_ip": parsed["src_ip"],
                "dst_ip": parsed["dst_ip"],
                "src_port": parsed.get("src_port"),
                "dst_port": parsed.get("dst_port"),
                "protocol": parsed.get("protocol", "UNKNOWN"),
                "pkt_len": parsed["packet_length"],
                "tcp_flags": parsed.get("tcp_flags"),
                "meta": meta,
            },
        )
        db.commit()
        row = result.fetchone()
        return row[0] if row else None
    except Exception as exc:
        log.error("session upsert error: %s", exc)
        db.rollback()
        return None


# ---------------------------------------------------------------------------
# MongoDB raw packet writer
# ---------------------------------------------------------------------------

def write_raw_packet(parsed: Dict[str, Any], session_id: Optional[int], mongo_db):
    """Write full parsed packet document to MongoDB raw_packets collection."""
    try:
        doc = dict(parsed)
        doc["session_id"] = session_id
        doc["tenant_id"] = TENANT_ID
        doc["expire_at"] = datetime.datetime.utcnow() + datetime.timedelta(hours=MONGO_RAW_TTL_HOURS)
        mongo_db["raw_packets"].insert_one(doc)
    except Exception as exc:
        log.warning("MongoDB write error: %s", exc)


# ---------------------------------------------------------------------------
# Session fingerprint insert
# ---------------------------------------------------------------------------

_FINGERPRINT_SQL = text("""
    INSERT INTO session_fingerprints (session_id, fingerprint_type, fingerprint_hash, raw_value)
    VALUES (:sid, :ftype, :fhash, :raw)
    ON CONFLICT DO NOTHING
""")


def insert_fingerprint(session_id: int, ftype: str, fhash: str, raw: str, db):
    try:
        db.execute(_FINGERPRINT_SQL, {"sid": session_id, "ftype": ftype, "fhash": fhash, "raw": raw})
        db.commit()
    except Exception as exc:
        log.warning("fingerprint insert error: %s", exc)
        db.rollback()


# ---------------------------------------------------------------------------
# Metrics accumulator
# ---------------------------------------------------------------------------

class MetricsAccumulator:
    """Thread-safe accumulator for packet/byte counts; flushes to PostgreSQL."""

    def __init__(self):
        self._packets = 0
        self._bytes = 0
        self._dropped = 0
        self._last_flush = time.monotonic()

    def record(self, pkt_len: int, dropped: bool = False):
        self._packets += 1
        self._bytes += pkt_len
        if dropped:
            self._dropped += 1

    def maybe_flush(self, db):
        now = time.monotonic()
        elapsed = now - self._last_flush
        if elapsed < FLUSH_INTERVAL_SEC:
            return
        pps = self._packets / elapsed
        bps = self._bytes / elapsed
        log.info(
            "STATS packets/sec=%.1f bytes/sec=%.1f dropped=%d",
            pps, bps, self._dropped,
        )
        try:
            db.execute(
                text("""
                    INSERT INTO flow_records
                        (tenant_id, ts, src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes)
                    VALUES
                        (:tid, NOW(), '0.0.0.0', '0.0.0.0', 0, 0, 'AGGREGATE', :pkts, :byts)
                """),
                {"tid": TENANT_ID, "pkts": self._packets, "byts": self._bytes},
            )
            db.commit()
        except Exception as exc:
            log.warning("metrics flush error: %s", exc)
            db.rollback()
        finally:
            self._packets = 0
            self._bytes = 0
            self._dropped = 0
            self._last_flush = now


# ---------------------------------------------------------------------------
# Core packet handler
# ---------------------------------------------------------------------------

def make_packet_handler(event_queue: multiprocessing.Queue, metrics: MetricsAccumulator):
    """Factory: returns a Scapy packet callback that uses shared resources."""

    redis_client = get_redis()
    db = get_db_session()
    mongo_db = get_mongo_db()

    def handler(pkt: Packet):
        if _shutdown.is_set():
            return

        pkt_len = len(pkt)
        metrics.record(pkt_len)

        # ── Fast path: parse src_ip for Redis block check ──────────────────
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc

        # ── Redis block check (O(1)) ────────────────────────────────────────
        if src_ip and is_blocked(src_ip, redis_client):
            metrics.record(pkt_len, dropped=True)
            log.debug("BLOCKED packet from %s", src_ip)
            return

        # ── Full parse ──────────────────────────────────────────────────────
        parsed = parse_packet(pkt)
        if parsed is None:
            return

        # ── Redis rule_cache quick-action check ─────────────────────────────
        if src_ip and dst_ip:
            cached_action = get_cached_rule_action(
                src_ip, dst_ip, parsed.get("protocol", ""), redis_client
            )
            if cached_action == "DROP":
                metrics.record(pkt_len, dropped=True)
                return
            if cached_action == "ALERT":
                parsed["cached_rule_hit"] = True

        # ── PostgreSQL session upsert ───────────────────────────────────────
        session_id = None
        if parsed["src_ip"] and parsed["dst_ip"]:
            session_id = upsert_session(parsed, db)

        # ── Fingerprints ────────────────────────────────────────────────────
        if session_id:
            if parsed.get("ja3"):
                insert_fingerprint(session_id, "JA3", parsed["ja3"], parsed["ja3"], db)
            if parsed.get("hassh"):
                insert_fingerprint(session_id, "HASSH", parsed["hassh"], parsed["hassh"], db)

        # ── MongoDB raw storage ─────────────────────────────────────────────
        write_raw_packet(parsed, session_id, mongo_db)

        # ── Put on event queue for DPI + Correlation engines ────────────────
        try:
            event_queue.put_nowait(parsed)
        except Exception:
            pass  # queue full — non-fatal

        # ── Periodic metric flush ────────────────────────────────────────────
        metrics.maybe_flush(db)

    return handler


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _handle_signal(signum, frame):
    log.info("Received signal %d — initiating shutdown.", signum)
    _shutdown.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Main capture loop
# ---------------------------------------------------------------------------

def run_capture(event_queue: multiprocessing.Queue):
    """
    Start Scapy sniff() on IFACE.
    Runs until _shutdown event is set.
    """
    log.info("Starting packet capture on interface '%s'", IFACE)
    metrics = MetricsAccumulator()
    handler = make_packet_handler(event_queue, metrics)

    # Ensure MongoDB TTL index exists
    try:
        mongo_db = get_mongo_db()
        mongo_db["raw_packets"].create_index(
            "expire_at", expireAfterSeconds=0, background=True
        )
        log.info("MongoDB TTL index ensured on raw_packets.expire_at")
    except Exception as exc:
        log.warning("MongoDB index creation warning: %s", exc)

    while not _shutdown.is_set():
        try:
            sniff(
                iface=IFACE,
                prn=handler,
                store=False,
                timeout=5,  # return periodically so we can check _shutdown
                stop_filter=lambda _: _shutdown.is_set(),
            )
        except PermissionError:
            log.error(
                "Permission denied on interface '%s'. "
                "Run as root or with CAP_NET_RAW capability.",
                IFACE,
            )
            time.sleep(5)
        except OSError as exc:
            log.error("OSError sniffing on '%s': %s — retrying in 5s", IFACE, exc)
            time.sleep(5)
        except Exception as exc:
            log.exception("Unexpected capture error: %s", exc)
            time.sleep(2)

    log.info("Packet capture stopped.")


# ---------------------------------------------------------------------------
# Entry point (invoked by main.py via subprocess)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    q: multiprocessing.Queue = multiprocessing.Queue(maxsize=50_000)
    run_capture(q)
