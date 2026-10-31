"""
action_engine.py — Automated Response & Playbook Execution Engine

Reads trigger events and executes multi-step playbooks stored in PostgreSQL.
Supports firewall blocking (iptables/netsh), TCP RST injection, honeypot redirects,
Redis hot-path updates, reputation adjustments, and alert generation.
"""

import os
import sys
import json
import logging
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

try:
    from scapy.all import IP, TCP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from models import (
    get_db_session, get_redis, get_mongo_db,
    Alert, BlockedIp, ThrottledFlow, HoneypotRedirect,
    Playbook, PlaybookStep, PlaybookExecution, IpReputation,
    NotificationChannel
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [ActionEngine] %(message)s")
logger = logging.getLogger("ActionEngine")

IS_WINDOWS = platform.system().lower() == "windows"

class ActionEngine:
    def __init__(self):
        self.redis = get_redis()
        logger.info(f"ActionEngine initialized. Host OS: {platform.system()}")

    def block_ip(self, ip: str, duration_minutes: int = 60, reason: str = "Automated threat response", alert_id: Optional[int] = None) -> bool:
        """Block IP in firewall, PostgreSQL blocked_ips, and Redis hot path."""
        logger.warning(f"EXECUTING BLOCK on IP: {ip} for {duration_minutes}m (Reason: {reason})")
        expires_at = datetime.utcnow() + timedelta(minutes=duration_minutes)

        # 1. Redis Hot Path Cache (Fast O(1) filter for packet sniffer)
        try:
            self.redis.sadd("blocked_ips_set", ip)
            self.redis.set(f"blocked_ip_exp:{ip}", expires_at.isoformat(), ex=duration_minutes * 60)
        except Exception as e:
            logger.error(f"Redis block cache update error for {ip}: {e}")

        # 2. Host Firewall Rule
        try:
            if IS_WINDOWS:
                rule_name = f"DBIDS_BLOCK_{ip.replace(':', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.error(f"Firewall execution failed for {ip}: {e}")

        # 3. PostgreSQL Database Record
        session = get_db_session()
        try:
            blocked_entry = BlockedIp(
                tenant_id=1,
                ip=ip,
                reason=reason,
                alert_id=alert_id,
                expires_at=expires_at,
                created_by="action_engine",
                active=True
            )
            session.add(blocked_entry)
            session.commit()
            logger.info(f"Successfully recorded blocked IP {ip} in DB (ID: {blocked_entry.id})")
            return True
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to record blocked IP in PostgreSQL: {e}")
            return False
        finally:
            session.close()

    def send_tcp_reset(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int = 0) -> bool:
        """Forge and inject a TCP RST packet to instantly terminate an active hostile socket connection."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available; skipping raw TCP RST transmission")
            return False
        try:
            rst_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", seq=seq)
            send(rst_pkt, verbose=False)
            logger.info(f"TCP RST injected to terminate socket {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
            return True
        except Exception as e:
            logger.error(f"Error injecting TCP RST: {e}")
            return False

    def update_reputation(self, ip: str, score_delta: int) -> int:
        """Update the threat reputation score for an IP address in PostgreSQL."""
        session = get_db_session()
        try:
            rep = session.query(IpReputation).filter(IpReputation.ip == ip).first()
            if not rep:
                rep = IpReputation(ip=ip, score=min(100, max(0, score_delta)), alert_count=1, last_seen=datetime.utcnow())
                session.add(rep)
            else:
                rep.score = min(100, max(0, rep.score + score_delta))
                rep.alert_count += 1
                rep.last_seen = datetime.utcnow()
            session.commit()
            new_score = rep.score
            logger.info(f"Updated IP reputation for {ip}: Score = {new_score}")
            return new_score
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating IP reputation: {e}")
            return 0
        finally:
            session.close()

    def execute_playbook(self, playbook_id: int, alert: Alert, packet_data: Dict[str, Any] = None) -> bool:
        """Execute all sequential steps of an incident response playbook defined in PostgreSQL."""
        session = get_db_session()
        execution = None
        try:
            playbook = session.query(Playbook).filter(Playbook.id == playbook_id).first()
            if not playbook:
                logger.error(f"Playbook {playbook_id} not found in database")
                return False

            execution = PlaybookExecution(
                playbook_id=playbook.id,
                alert_id=alert.id if alert else None,
                status="RUNNING",
                started_at=datetime.utcnow(),
                step_results=[]
            )
            session.add(execution)
            session.commit()

            steps = session.query(PlaybookStep).filter(PlaybookStep.playbook_id == playbook.id).order_by(PlaybookStep.step_order).all()
            results = []

            for step in steps:
                action_type = step.action_template.action_type if step.action_template else "UNKNOWN"
                params = step.parameters or {}
                step_success = True
                result_info = {"step": step.step_order, "action": action_type}

                logger.info(f"Executing Playbook Step {step.step_order}: {action_type}")

                if action_type == "BLOCK_SRC_IP":
                    duration = params.get("duration_minutes", 60)
                    step_success = self.block_ip(str(alert.src_ip), duration_minutes=duration, reason=f"Playbook: {playbook.name}", alert_id=alert.id)
                elif action_type == "TCP_RST" and packet_data:
                    step_success = self.send_tcp_reset(
                        packet_data.get("src_ip", str(alert.src_ip)),
                        packet_data.get("dst_ip", str(alert.dst_ip)),
                        packet_data.get("src_port", alert.src_port or 0),
                        packet_data.get("dst_port", alert.dst_port or 0)
                    )
                elif action_type == "UPDATE_REPUTATION":
                    delta = params.get("score_delta", 20)
                    self.update_reputation(str(alert.src_ip), delta)
                elif action_type == "THROTTLE_FLOW":
                    rate = params.get("rate_kbps", 128)
                    tf = ThrottledFlow(
                        tenant_id=1,
                        src_ip=alert.src_ip,
                        dst_ip=alert.dst_ip,
                        dst_port=alert.dst_port,
                        rate_kbps=rate,
                        reason=f"Playbook: {playbook.name}"
                    )
                    session.add(tf)
                    session.commit()
                elif action_type == "REDIRECT_HONEYPOT":
                    hp_ip = params.get("honeypot_ip", "10.0.99.100")
                    hp_port = params.get("honeypot_port", 2222)
                    hr = HoneypotRedirect(
                        tenant_id=1,
                        match_dst_ip=alert.dst_ip,
                        match_dst_port=alert.dst_port,
                        honeypot_ip=hp_ip,
                        honeypot_port=hp_port,
                        reason=f"Playbook: {playbook.name}"
                    )
                    session.add(hr)
                    session.commit()

                result_info["success"] = step_success
                results.append(result_info)

                if not step_success and not step.continue_on_failure:
                    logger.error(f"Playbook step {step.step_order} failed; halting playbook execution")
                    execution.status = "FAILED"
                    execution.step_results = results
                    execution.completed_at = datetime.utcnow()
                    session.commit()
                    return False

            execution.status = "COMPLETED"
            execution.step_results = results
            execution.completed_at = datetime.utcnow()
            session.commit()
            logger.info(f"Playbook '{playbook.name}' completed successfully")
            return True

        except Exception as e:
            logger.error(f"Playbook execution runtime exception: {e}")
            if execution:
                execution.status = "FAILED"
                execution.error_message = str(e)
                execution.completed_at = datetime.utcnow()
                session.commit()
            return False
        finally:
            session.close()

if __name__ == "__main__":
    engine = ActionEngine()
    print("ActionEngine test initialized successfully.")
