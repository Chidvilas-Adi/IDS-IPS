"""
dpi_engine.py — Deep Packet Inspection (DPI) Engine

Loads deep packet inspection signatures directly from PostgreSQL (dpi_signatures table),
compiles regex/byte patterns, and inspects raw application payloads (HTTP, SMB, TLS, DNS).
Directly triggers the ActionEngine upon signature match.
"""

import re
import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from models import get_db_session, DpiSignature, Alert
from action_engine import ActionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [DPIEngine] %(message)s")
logger = logging.getLogger("DPIEngine")

class DPIEngine:
    def __init__(self, action_engine: Optional[ActionEngine] = None):
        self.action_engine = action_engine or ActionEngine()
        self.signatures: List[Dict[str, Any]] = []
        self.last_reload = 0
        self.reload_interval = 60  # seconds
        self.reload_signatures()

    def reload_signatures(self):
        """Reload and compile DPI signatures from PostgreSQL."""
        session = get_db_session()
        try:
            db_sigs = session.query(DpiSignature).filter(DpiSignature.enabled == True).all()
            compiled = []
            for sig in db_sigs:
                entry = {
                    "id": sig.id,
                    "name": sig.name,
                    "protocol": sig.protocol.upper() if sig.protocol else "ANY",
                    "pattern_type": sig.pattern_type.upper(),
                    "pattern_raw": sig.pattern,
                    "severity": sig.severity,
                    "cve": sig.cve,
                    "action": sig.action.upper() if sig.action else "BLOCK",
                    "compiled_regex": None,
                    "hex_bytes": None
                }
                try:
                    if entry["pattern_type"] == "REGEX":
                        entry["compiled_regex"] = re.compile(sig.pattern, re.IGNORECASE)
                    elif entry["pattern_type"] == "HEX_BYTES":
                        # Convert hex string (e.g. 'ff534d42') into raw bytes
                        clean_hex = sig.pattern.replace(" ", "").replace("0x", "")
                        entry["hex_bytes"] = bytes.fromhex(clean_hex)
                    compiled.append(entry)
                except Exception as ex:
                    logger.error(f"Failed to compile signature ID {sig.id} '{sig.name}': {ex}")

            self.signatures = compiled
            self.last_reload = time.time()
            logger.info(f"Loaded {len(self.signatures)} active DPI signatures from PostgreSQL")
        except Exception as e:
            logger.error(f"Error reading DPI signatures from database: {e}")
        finally:
            session.close()

    def inspect_packet(self, packet_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Inspect a single parsed packet against all active compiled signatures."""
        if time.time() - self.last_reload > self.reload_interval:
            self.reload_signatures()

        matches = []
        payload_raw = packet_data.get("payload_raw", b"")
        payload_hex = packet_data.get("payload_hex", "")
        proto = packet_data.get("protocol", "ANY").upper()

        if not payload_raw and payload_hex:
            try:
                payload_raw = bytes.fromhex(payload_hex)
            except Exception:
                payload_raw = b""

        if not payload_raw:
            return matches

        payload_str = payload_raw.decode("utf-8", errors="ignore")

        for sig in self.signatures:
            if sig["protocol"] != "ANY" and sig["protocol"] != proto:
                continue

            matched = False
            if sig["pattern_type"] == "REGEX" and sig["compiled_regex"]:
                if sig["compiled_regex"].search(payload_str):
                    matched = True
            elif sig["pattern_type"] == "HEX_BYTES" and sig["hex_bytes"]:
                if sig["hex_bytes"] in payload_raw:
                    matched = True
            elif sig["pattern_type"] == "EXACT":
                if sig["pattern_raw"] in payload_str:
                    matched = True

            if matched:
                logger.warning(f"🚨 DPI MATCH: {sig['name']} (Severity: {sig['severity']}, CVE: {sig['cve']}) on {packet_data.get('src_ip')}:{packet_data.get('src_port')}")
                matches.append(sig)
                self._handle_dpi_match(sig, packet_data)

        return matches

    def _handle_dpi_match(self, sig: Dict[str, Any], packet_data: Dict[str, Any]):
        """Persist alert and execute firewall block action."""
        session = get_db_session()
        try:
            alert = Alert(
                tenant_id=1,
                rule_id=sig["id"],
                rule_type="DPI_SIGNATURE",
                severity=sig["severity"],
                src_ip=packet_data.get("src_ip", "0.0.0.0"),
                dst_ip=packet_data.get("dst_ip", "0.0.0.0"),
                src_port=packet_data.get("src_port"),
                dst_port=packet_data.get("dst_port"),
                protocol=packet_data.get("protocol"),
                packet_summary={
                    "signature": sig["name"],
                    "cve": sig["cve"],
                    "pattern": sig["pattern_raw"][:100],
                    "length": packet_data.get("packet_length", 0)
                },
                status="open"
            )
            session.add(alert)
            session.commit()

            if sig["action"] == "BLOCK":
                self.action_engine.block_ip(
                    ip=packet_data.get("src_ip"),
                    duration_minutes=120,
                    reason=f"DPI Exploit Match: {sig['name']} ({sig['cve']})",
                    alert_id=alert.id
                )
        except Exception as e:
            session.rollback()
            logger.error(f"Error handling DPI alert: {e}")
        finally:
            session.close()

if __name__ == "__main__":
    engine = DPIEngine()
    test_packet = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "src_port": 49200,
        "dst_port": 80,
        "protocol": "TCP",
        "payload_raw": b"GET /index.php?id=1 UNION SELECT username, password FROM users -- HTTP/1.1\r\n\r\n"
    }
    matches = engine.inspect_packet(test_packet)
    print(f"Inspection test completed. Found {len(matches)} matches.")
