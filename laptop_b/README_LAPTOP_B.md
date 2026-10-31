# Laptop B — Attack & Stress Testing Suite for DB-IDS/IPS

This folder contains everything needed to run from **Laptop B** against **Laptop A** (the DB-IDS/IPS host).

---

## 🚀 Quick Start on Laptop B

1. Connect **Laptop B** to the **same Wi-Fi or local network** as Laptop A.
2. Copy this `laptop_b` folder onto Laptop B (via USB drive, Git, or network share).
3. Open a terminal or Command Prompt in this folder.
4. Run the 1-click launcher:

### Windows (Double-click or run in cmd):
```cmd
single_click_attack.bat
```

### Linux / macOS:
```bash
chmod +x single_click_attack.sh
./single_click_attack.sh
```

---

## 🎯 Test Options in the Menu

| Option | Test Type | What It Does | Expected Reaction on Laptop A (Database) |
|---|---|---|---|
| **[1] Full Suite** | All Tests | Executes all exploits, correlation patterns, and stress bursts | All alerts fire sequentially in GUI |
| **[2] SQL Injection** | DPI Signature | Transmits `UNION SELECT` & `OR 1=1` exploit payloads | `dpi_signatures` regex triggers -> Instant **BLOCK** |
| **[3] Log4Shell** | DPI Signature | Injects `${jndi:ldap:...}` header (CVE-2021-44228) | Database generates **CRITICAL** alert + TCP RST |
| **[4] EICAR Antivirus** | DPI Signature | Sends standard antivirus test pattern | Database logs signature match |
| **[5] Port Sweep** | Correlation | Probes 20 distinct TCP ports within 3 seconds | `correlation_rules` threshold exceeded -> Auto-block |
| **[6] SSH Brute Force**| Correlation | 8 rapid SYN handshakes on port 22 | Triggers **Playbook #1** (Firewall drop + PCAP capture) |
| **[7] High-Rate Flood** | Stress Test | 16 parallel threads flooding UDP packets | Tests throughput and Redis O(1) drop performance |
| **[8] TCP Flood** | Stress Test | 16 parallel threads generating rapid TCP flows | Tests PostgreSQL `ingress_packets` insertion rate |
| **[9] Benign Traffic** | Normal | Generates realistic web requests (`GET /`, `GET /health`) | Populates Dashboard charts and network topology |

---

## 📊 Viewing the Results in Real Time

While attacking from Laptop B, open Laptop A's dashboard in Laptop B's browser:
```
http://10.30.201.26:1234
```
- Login with `admin` / `admin123`.
- Watch the **Alert Feed** light up via real-time WebSocket.
- Click **Threat Intelligence** -> Check the **Active Blocklist** to see Laptop B's IP added to the firewall.
- Click **Session Inspector** to see packet streams.
