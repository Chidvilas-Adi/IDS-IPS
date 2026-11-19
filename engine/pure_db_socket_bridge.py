"""Capture IP packets and submit them to PostgreSQL for SQL-side processing."""

import ipaddress
import json
import logging
import os
import platform
import select
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import psycopg2
from dotenv import load_dotenv
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env", override=False)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DBSocketBridge] %(levelname)s %(message)s")
logger = logging.getLogger("DBSocketBridge")

IS_WINDOWS = platform.system().lower() == "windows"
NETWORK_INTERFACE = os.environ.get("NETWORK_INTERFACE", "eth0")


def get_db_conn():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ.get("POSTGRES_DB", "idsips"),
        user=os.environ.get("POSTGRES_USER", "idsips"),
        password=os.environ.get("POSTGRES_PASSWORD", "idsips_secret"),
        connect_timeout=5,
    )


def process_packet_in_db(conn, packet):
    src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, payload, payload_bytes, packet_length = packet
    payload_text = payload.replace("\x00", "")
    for attempt in range(3):
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO ingress_packets
                        (src_ip, dst_ip, src_port, dst_port, protocol,
                         tcp_flags, packet_length, payload_text, payload_bytes, capture_source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'capture')
                    """,
                    (
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        tcp_flags, packet_length, payload_text, payload_bytes,
                    ),
                )
            conn.commit()
            return True
        except psycopg2.Error as exc:
            conn.rollback()
            if exc.pgcode == "40P01":
                if attempt < 2:
                    logger.warning(
                        "Packet transaction deadlocked; retrying (%s/3)",
                        attempt + 1,
                    )
                    time.sleep(0.1 * (attempt + 1))
                    continue
                logger.error(
                    "Dropping captured packet after repeated database deadlocks "
                    "(SQLSTATE %s)",
                    exc.pgcode,
                )
                return False
            logger.exception("PostgreSQL rejected a captured packet")
            raise
    return False


def _run_firewall_command(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "firewall command failed")


def execute_firewall_action(action, local_ip=None):
    operation = str(action.get("action", "")).upper()
    if operation not in {"BLOCK", "UNBLOCK"}:
        if operation == "ALERT":
            logger.warning("Database alert: %s", action.get("reason", "unspecified"))
        else:
            logger.warning("Ignoring unsupported database firewall action: %s", operation)
        return

    try:
        address = ipaddress.ip_interface(str(action["ip"]))
    except (KeyError, ValueError) as exc:
        logger.error("Ignoring database firewall action with invalid IP: %s", exc)
        return

    if address.network.prefixlen != address.max_prefixlen:
        logger.error(
            "Ignoring firewall action for non-host network: %s",
            address.with_prefixlen,
        )
        return
    ip = address.ip

    if operation == "BLOCK" and local_ip and ip == ipaddress.ip_address(local_ip):
        logger.error("Ignoring firewall block for the adapter's own host address: %s", ip)
        return

    try:
        if IS_WINDOWS:
            rule_name = f"DBIDS_{str(ip).replace(':', '_')}"
            if operation == "BLOCK":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                _run_firewall_command(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", "action=block",
                        f"remoteip={ip}", "profile=any",
                    ]
                )
            else:
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if result.returncode:
                    logger.info("No active firewall rule found for %s", ip)
        else:
            binary = "ip6tables" if ip.version == 6 else "iptables"
            rule = [binary, "-s", str(ip), "-j", "DROP"]
            if operation == "BLOCK":
                exists = subprocess.run(
                    [binary, "-C", "INPUT", *rule[1:]],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if exists.returncode:
                    _run_firewall_command([binary, "-I", "INPUT", *rule[1:]])
            else:
                result = subprocess.run(
                    [binary, "-D", "INPUT", *rule[1:]],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if result.returncode:
                    logger.info("No active firewall rule found for %s", ip)
                    return

        logger.info("%s firewall rule for %s", operation, ip)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        logger.exception("Failed to apply %s firewall action for %s", operation, ip)


def purge_expired_blocks():
    with get_db_conn() as conn, conn.cursor() as cursor:
        cursor.execute("CALL sp_purge_expired_records()")


def listen_for_firewall_actions(local_ip):
    while True:
        conn = None
        try:
            conn = get_db_conn()
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            with conn.cursor() as cursor:
                cursor.execute("LISTEN db_firewall_action")
            logger.info("Listening for PostgreSQL firewall actions")
            next_purge = 0

            while True:
                select.select([conn], [], [], 1)
                conn.poll()
                while conn.notifies:
                    notification = conn.notifies.pop(0)
                    try:
                        execute_firewall_action(json.loads(notification.payload), local_ip)
                    except json.JSONDecodeError:
                        logger.error("Ignoring malformed database firewall notification")
                if time.monotonic() >= next_purge:
                    try:
                        purge_expired_blocks()
                    except psycopg2.Error:
                        logger.exception("PostgreSQL expired-block cleanup failed")
                    next_purge = time.monotonic() + 15
        except (OSError, psycopg2.Error):
            logger.exception("Database notification listener disconnected; retrying")
            time.sleep(3)
        finally:
            if conn is not None:
                conn.close()


def parse_raw_ip_packet(data):
    if len(data) < 20:
        return None

    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(data) < ip_header_length:
        return None

    protocol_number = data[9]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    src_port = dst_port = None
    protocol = "OTHER"
    tcp_flags = ""
    payload_offset = ip_header_length

    if protocol_number == socket.IPPROTO_TCP:
        if len(data) < ip_header_length + 20:
            return None
        src_port, dst_port = struct.unpack("!HH", data[ip_header_length : ip_header_length + 4])
        tcp_offset = (data[ip_header_length + 12] >> 4) * 4
        if tcp_offset < 20 or len(data) < ip_header_length + tcp_offset:
            return None
        flags = data[ip_header_length + 13]
        tcp_flags = ",".join(
            name for bit, name in (
                (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
            ) if flags & bit
        )
        protocol = "TCP"
        payload_offset += tcp_offset
    elif protocol_number == socket.IPPROTO_UDP:
        if len(data) < ip_header_length + 8:
            return None
        src_port, dst_port = struct.unpack("!HH", data[ip_header_length : ip_header_length + 4])
        protocol = "UDP"
        payload_offset += 8
    elif protocol_number == socket.IPPROTO_ICMP:
        protocol = "ICMP"

    payload_bytes = data[payload_offset:]
    payload = payload_bytes.decode("utf-8", errors="ignore")
    return src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, payload, payload_bytes, len(data)


def _parse_ethernet_frame(data):
    if len(data) < 14:
        return None
    ether_type = struct.unpack("!H", data[12:14])[0]
    offset = 14
    if ether_type in (0x8100, 0x88A8):
        if len(data) < 18:
            return None
        ether_type = struct.unpack("!H", data[16:18])[0]
        offset = 18
    if ether_type != 0x0800:
        return None
    return parse_raw_ip_packet(data[offset:])


class PureDBSocketBridge:
    def __init__(self):
        self.stop_event = threading.Event()

    @staticmethod
    def get_host_ip():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return probe.getsockname()[0]

    def _start_udp_listener(self, local_ip):
        try:
            with get_db_conn() as conn, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("0.0.0.0", 9999))
                logger.info("Test packet input listening on UDP port 9999")
                while not self.stop_event.is_set():
                    data, address = sock.recvfrom(65535)
                    packet = (
                        address[0], local_ip, address[1], 9999, "UDP", "",
                        data.decode("utf-8", errors="ignore"), data, len(data),
                    )
                    process_packet_in_db(conn, packet)
        except OSError as exc:
            logger.warning(
                "Optional UDP test listener on port 9999 is unavailable; "
                "raw packet capture and firewall monitoring will continue: %s",
                exc,
            )
        except psycopg2.Error:
            logger.exception(
                "Optional UDP test listener could not connect to PostgreSQL; "
                "raw packet capture and firewall monitoring will continue"
            )

    def start(self):
        local_ip = self.get_host_ip()
        conn = get_db_conn()
        conn.close()
        threading.Thread(
            target=listen_for_firewall_actions,
            args=(local_ip,),
            daemon=True,
        ).start()
        threading.Thread(target=self._start_udp_listener, args=(local_ip,), daemon=True).start()
        logger.info("Capture host address: %s", local_ip)

        if IS_WINDOWS:
            capture_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            capture_socket.bind((local_ip, 0))
            capture_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            logger.info("Windows raw packet capture enabled on %s", local_ip)
            parse_frame = parse_raw_ip_packet
        else:
            capture_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            capture_socket.bind((NETWORK_INTERFACE, 0))
            logger.info("Linux packet capture enabled on %s", NETWORK_INTERFACE)
            parse_frame = _parse_ethernet_frame

        with capture_socket, get_db_conn() as conn:
            while True:
                data, _ = capture_socket.recvfrom(65535)
                packet = parse_frame(data)
                if packet is not None:
                    process_packet_in_db(conn, packet)


if __name__ == "__main__":
    try:
        PureDBSocketBridge().start()
    except (OSError, psycopg2.Error) as exc:
        logger.exception("Packet bridge could not start: %s", exc)
        raise SystemExit(1) from exc
