# Database-Driven IDS/IPS System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](engine/)
[![Node](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js)](gui/)

A database-driven Intrusion Detection and Prevention System (IDS/IPS). PostgreSQL is the source of truth for packet ingress, detection rules, threat indicators, sessions, alerts, block decisions, compliance checks, and audit history. MongoDB and Redis remain supporting services in the current Compose stack; they are not the authority for detection or block decisions.

Packet inspection, session updates, correlation, alert creation, and block decisions run in PostgreSQL triggers and functions. The packet-capture adapter only submits packets to PostgreSQL; a separate privileged adapter applies committed database firewall notifications to the host firewall. Packet capture and operating-system firewall changes cannot be performed by SQL alone.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Manual Setup](#manual-setup)
- [Environment Variables](#environment-variables)
- [Database Types and Connections](#database-types-and-connections)
- [API Endpoints](#api-endpoints)
- [GUI Pages](#gui-pages)
- [Database Schema](#database-schema)
- [Adding Custom Rules](#adding-custom-rules)
- [Contributing](#contributing)
- [License](#license)

---

## Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │             NGINX (8080/8443)                │
                     │  HTTP→HTTPS redirect · SSL termination       │
                     │  Rate limiting · WebSocket proxy             │
                     └────────────┬─────────────────┬──────────────┘
                                  │                 │
                     ┌────────────▼───┐     ┌───────▼──────────┐
                     │  Flask API     │     │  React SPA      │
                     │ (localhost:1234)│    │  GUI (service:80)│
                     └────────────┬───┘     └──────────────────┘
                                  │
         ┌────────────────────────┼──────────────────────────┐
         │                        │                          │
┌────────▼──────────┐   ┌─────────▼──────────┐   ┌──────────▼────────┐
│  TimescaleDB       │   │  MongoDB 7          │   │  Redis 7          │
│  (PostgreSQL 16)   │   │  (raw packets,      │   │  (rule cache,     │
│  Rules, Alerts,    │   │   threat intel,     │   │   session data,   │
│  Events, Tenants   │   │   geo-ip, ML vecs)  │   │   rate counters)  │
└────────────────────┘   └────────────────────┘   └───────────────────┘
         ▲
         │  SQL rules
┌────────┴──────────────────┐
│  Detection Engine          │
│  (Scapy / AsyncIO)         │
│  network_mode: host        │
│  CAP_NET_RAW + NET_ADMIN   │
└──────┬────────────────────┘
       │  live packets
       ▼
  Network Interface (eth0)
```

### Services

| Service | Image / Build | Port | Purpose |
|---------|--------------|------|---------|
| `postgres` | `timescale/timescaledb:latest-pg16` | localhost:5432 | Rules, alerts, events (time-series); not published to the LAN |
| `schema` | `timescale/timescaledb:latest-pg16` | — | Re-applies the idempotent PostgreSQL schema at startup |
| `mongodb` | `mongo:7` | internal only | Supporting forensic documents |
| `redis` | `redis:7-alpine` | internal only | Supporting cache and queues |
| `engine` | `./engine` | — | Optional Linux packet/firewall adapter (`linux-capture` profile) |
| `threat_feed_ingester` | `./engine` | — | Optional external feed poller (`threat-intel` profile) |
| `api` | `./api` | localhost:1234 | REST + WebSocket API; private host binding |
| `gui` | `./gui` | internal only | React dashboard |
| `nginx` | `./nginx` | 8080/8443 | HTTPS dashboard proxy; self-signed certificate for local/lab use |

---

## Prerequisites

| Dependency | Minimum Version | Notes |
|-----------|----------------|-------|
| Docker Engine | 24+ | With Docker Compose V2 |
| Docker Compose | 2.20+ | Bundled with Docker Desktop |
| Python | 3.11+ | Engine / API (manual setup) |
| Node.js | 18 LTS | GUI (manual setup) |
| npm / pnpm | 9+ | GUI package manager |
| Linux host | Any | `network_mode: host` required for raw capture |

> **Note:** On Windows, packet capture and firewall enforcement use the elevated host adapter, not the Linux container profile. On Linux, use the `run_all.sh` host adapter or explicitly enable the `linux-capture` profile.

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/db-ids-ips.git
cd db-ids-ips

# 2. Copy and edit the environment file. Set unique passwords, signing keys,
#    ADMIN_LOGIN_PASSWORD, and Laptop A's TLS_IP_ADDRESS.
cp .env.example .env
$EDITOR .env

# 3. Build and start the database, API, React UI, and HTTPS gateway.
#    NGINX generates a local self-signed certificate on first start.
docker compose up -d --build --wait

# 4. Verify service health
docker compose ps

# 5. Open https://localhost:8443 (browser warns for the self-signed certificate).
```

The dashboard login is `admin` plus the current `ADMIN_LOGIN_PASSWORD` in
`.env`. Set `INITIAL_ADMIN_NAME` and
`INITIAL_ADMIN_EMAIL` for its profile; schema startup syncs those fields without
resetting an existing user's password. If you reset the password in the
database, update `ADMIN_LOGIN_PASSWORD` in `.env` too.
`API_PORT` and PostgreSQL are loopback-only; Laptop B uses the HTTPS gateway.
Copy `nginx/ssl/self-signed.crt` to Laptop B if you want to validate the
certificate rather than opting into the lab-only certificate bypass.

### Useful commands

```bash
# Follow API and database logs
docker compose logs -f api postgres

# Tail all logs
docker compose logs -f

# Check service state
docker compose ps --all

# Apply the DB-owned trigger integration test (transaction rolls back)
Get-Content .\testing\verify_database_engine.sql -Raw |
  docker compose exec -T postgres psql -U idsips -d idsips -v ON_ERROR_STOP=1 -f -

# Restart a single service
docker compose restart api

# Stop everything (keep volumes)
docker compose down

# Destructive: stop and permanently wipe this Compose project's database data
docker compose down -v
```

### Windows host capture

For capture on the Windows host, run the launcher from an elevated terminal after configuring `.env`. It starts the database-backed API on port 1234, applies the schema to both new and existing database volumes, creates an isolated Python environment for the small packet/firewall adapter, and installs that adapter's two dependencies:

```powershell
.\run_all.bat
```

It starts PostgreSQL, MongoDB, Redis, the API, React UI, and HTTPS gateway and waits for health checks before starting the Windows packet/firewall adapter. The adapter requires administrator permission. The API and adapter fail on unavailable databases; they do not substitute SQLite or in-memory stores. `start_all.bat` delegates to this launcher.

The current Windows adapter uses Winsock `IPPROTO_IP` with
`SIO_RCVALL`. It is a host-level IPv4 packet receiver, not Wireshark-equivalent
link-layer capture: it does not decode Ethernet frames or capture IPv6, and it
chooses the local IPv4 address for the default route rather than using
`NETWORK_INTERFACE` (that setting is for Linux). Npcap is not used by this
implementation. For full adapter-level capture and Wireshark-style packet
details, the Windows adapter must be replaced with an Npcap-based capture
backend.

Capture is passive and does not require pinging a particular port. To create
test traffic after starting the elevated launcher, ping the current Wi-Fi
gateway:

```powershell
$gateway = (Get-NetIPConfiguration -InterfaceAlias "Wi-Fi").IPv4DefaultGateway.NextHop
ping.exe -n 3 $gateway
```

Then inspect the latest submitted packets:

```powershell
docker compose exec -T postgres psql -U idsips -d idsips -c `
  "SELECT created_at, src_ip, dst_ip, protocol, src_port, dst_port FROM ingress_packets ORDER BY id DESC LIMIT 10;"
```

Ping only generates ICMP traffic; it will not open a TCP port or guarantee an
alert. PostgreSQL creates an alert only when submitted traffic matches an
enabled detection rule. The sensor sees traffic available to its selected
interface, not all unicast traffic on a switched LAN.

The Linux equivalents are `sudo ./run_all.sh` and `./start_all.sh`. To run capture in a Linux container instead, enable it explicitly with `docker compose --profile linux-capture up -d --build`.

Laptop B's launcher only verifies the dashboard, database-backed API, and
service readiness. It does not generate attack traffic. See
[`laptop_b/README_LAPTOP_B.md`](./laptop_b/README_LAPTOP_B.md).

Run the database integration check after startup:

```powershell
Get-Content .\testing\verify_database_engine.sql -Raw |
  docker compose exec -T postgres psql -U idsips -d idsips -v ON_ERROR_STOP=1 -f -
```

The test runs in a transaction and rolls back its sample packets, alerts, and rules.

### Packet processing boundary

`engine/pure_db_socket_bridge.py` performs only packet parsing/ingestion and execution of firewall actions emitted on PostgreSQL's `db_firewall_action` channel. The Compose `engine` service uses this adapter, not the legacy Python detection engines. The `trg_packet_ingress` trigger calls the SQL DPI and correlation functions and updates sessions, alerts, reputation, and block records. REST/GraphQL manual IP blocks call the PostgreSQL block/unblock procedures. Add or change detection rules in PostgreSQL; do not add detection decisions to the capture adapter or API.

Sessions allow null transport ports so ICMP and other non-TCP/UDP packets can be recorded. The Windows firewall adapter accepts host CIDRs such as `10.0.0.1/32` from PostgreSQL notifications and rejects broader subnets rather than applying a broader firewall rule.

On existing databases, the schema migration locks `ingress_packets` before
`sessions`, matching the packet trigger's lock order and preventing a
migration-versus-capture deadlock. A packet transaction also retries transient
PostgreSQL deadlocks for up to three total attempts; if those fail, it logs the
packet drop and capture continues.

On Windows, UDP port 9999 is an optional test-packet listener. If another
process already owns that port, the adapter logs a warning and continues raw
capture and firewall monitoring; only the optional UDP test input is
unavailable. Avoid starting multiple packet-adapter instances because each
instance may ingest duplicate raw packets. To identify the process using that
port in PowerShell, run `Get-NetUDPEndpoint -LocalPort 9999` and inspect its
`OwningProcess` with `Get-Process -Id <PID>` before stopping anything.

Capture sees traffic delivered to the selected active interface, which may be
Ethernet, Wi-Fi, loopback, VPN, or a virtual adapter; it is not limited to a
physical Ethernet cable. It does not automatically see every device on a
switched LAN: network-wide visibility requires traffic to be routed through the
sensor or delivered through a mirror/TAP. TLS payloads remain encrypted unless
decryption is separately and lawfully configured. Database detection only
processes packets that the capture adapter actually submits. The optional
threat-feed ingester uses public Feodo Tracker and Emerging Threats feeds that
do not require provider API keys. The API can email high and critical alerts
through SMTP when mail settings are configured.

### Email alerts

Email notifications are optional and are sent for new `HIGH` and `CRITICAL`
alerts only. Add these values to Laptop A's local `.env` file:

```dotenv
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-sender@gmail.com
SMTP_PASSWORD=your-google-app-password
SMTP_FROM=
ALERT_EMAIL_TO=siddxadi@gmail.com
```

For Gmail, enable 2-Step Verification and create an App Password; use that
App Password for `SMTP_PASSWORD`, not the regular Google account password.
Keep `.env` private and never commit or share the App Password. Restart the
API container after changing the settings so it receives them:

```bash
docker compose up -d --force-recreate api
```

When the API starts, its log reports whether mail settings are configured;
SMTP delivery errors are logged, and alerts remain visible in the dashboard.
To test delivery, trigger the `canary` scenario from Laptop B; it creates a
critical synthetic alert. Check the recipient inbox and spam folder.
Simulations insert synthetic events; they do not send attack traffic.

---

## Manual Setup

### 1. PostgreSQL / TimescaleDB

```bash
psql -U idsips -d idsips -f db/postgres/init.sql
```

### 2. MongoDB

```bash
mongosh "mongodb://idsips:mongo_secret@localhost:27017/admin" \
  --file db/mongo/init.js
```

### 3. Detection Engine

```bash
cd engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-bridge.txt
# Requires NET_RAW capability or sudo on Linux
sudo python pure_db_socket_bridge.py
```

### 4. Threat Feed Ingester

```bash
cd engine
source .venv/bin/activate
python threat_feed_ingester.py
```

This polls public Feodo Tracker and Emerging Threats sources. Provider-specific
AbuseIPDB, VirusTotal, Shodan, and OTX credentials are not configured, and the
ingester does not insert simulated/mock IOCs for them.

### 5. REST API

```bash
cd api
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask run --host=0.0.0.0 --port=5000
```

### 6. GUI

```bash
cd gui
npm ci
npm start       # development server
npm run build   # production bundle (served by the GUI container)
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | Full PostgreSQL connection string |
| `POSTGRES_HOST` | `localhost` | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | PostgreSQL port |
| `POSTGRES_DB` | `idsips` | Database name |
| `POSTGRES_USER` | `idsips` | Database user |
| `POSTGRES_PASSWORD` | — | Database password |
| `MONGO_URI` | blank | Built from the MongoDB user/password/database settings |
| `MONGO_USER` | `idsips` | MongoDB root user |
| `MONGO_PASSWORD` | — | MongoDB root password |
| `MONGO_DB` | `idsips` | MongoDB database name |
| `REDIS_URL` | — | Redis connection URL |
| `REDIS_PASSWORD` | — | Redis AUTH password |
| `API_PORT` | `1234` | Loopback-only host port mapped to the API container |
| `WEB_PORT` | `8080` | HTTP port that redirects to HTTPS |
| `TLS_PORT` | `8443` | HTTPS dashboard port |
| `TLS_DNS_NAME` | `localhost` | DNS name in the generated self-signed certificate |
| `TLS_IP_ADDRESS` | `127.0.0.1` | IP address in the generated self-signed certificate |
| `SECRET_KEY` | — | Flask session secret (32+ chars) |
| `JWT_SECRET_KEY` | — | JWT signing secret (32+ chars) |
| `INITIAL_ADMIN_NAME` | — | Display name for the seeded administrator |
| `INITIAL_ADMIN_EMAIL` | — | Email address for the seeded administrator |
| `ADMIN_LOGIN_USERNAME` | `admin` | Dashboard username reminder; schema fixes this to `admin` |
| `ADMIN_LOGIN_PASSWORD` | — | Dashboard password and fresh-database seed password |
| `NETWORK_INTERFACE` | `eth0` | Interface for packet capture |
| `SMTP_HOST` | `smtp.gmail.com` | SMTP relay hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password or provider app password; keep it in local `.env` |
| `SMTP_FROM` | `SMTP_USER` | Optional sender address |
| `ALERT_EMAIL_TO` | — | Recipient for new high/critical alert emails |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `ENGINE_POLL_INTERVAL` | `1` | Packet batch flush interval (seconds) |
| `RULE_CACHE_TTL` | `60` | Redis rule cache TTL (seconds) |
| `MAX_PACKET_QUEUE` | `10000` | In-memory packet queue depth |
| `HONEYPOT_IP` | — | IP of internal honeypot host |
| `SINKHOLE_IP` | — | IP of internal DNS sinkhole |

> **Tip:** Generate strong secrets with: `python -c "import secrets; print(secrets.token_hex(32))"`

---

## Database Types and Connections

See [`DATABASE_TYPES_AND_CONNECTIONS.txt`](./DATABASE_TYPES_AND_CONNECTIONS.txt)
for a plain-language comparison of PostgreSQL/TimescaleDB, MongoDB, and Redis;
why the Compose `*_URL`/`*_URI` variables are intentionally blank; how the
services receive their actual connection settings; and how to verify live
connectivity.

---

## API Endpoints

All endpoints are served under `/api/` (proxied by NGINX).

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Obtain JWT access token |
| `POST` | `/api/auth/refresh` | Refresh JWT token |
| `POST` | `/api/auth/logout` | Revoke token |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/alerts` | List alerts (paginated, filterable) |
| `GET` | `/api/alerts/{id}` | Get single alert detail |
| `PATCH` | `/api/alerts/{id}` | Update alert status (ack/close/false-positive) |
| `GET` | `/api/alerts/stats` | Alert counts by severity / time |

### Rules

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/rules` | List all rules |
| `POST` | `/api/rules` | Create a new rule |
| `GET` | `/api/rules/{id}` | Get rule detail |
| `PUT` | `/api/rules/{id}` | Update rule |
| `DELETE` | `/api/rules/{id}` | Soft-delete rule |
| `POST` | `/api/rules/{id}/test` | Test rule against a sample packet |

### Traffic

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/traffic/summary` | Bandwidth/protocol breakdown |
| `GET` | `/api/traffic/top-talkers` | Top source IPs by volume |
| `GET` | `/api/traffic/flows` | Active/recent flows |

### Threat Intelligence

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/threat-intel/lookup/{ip}` | Multi-source IP reputation lookup |
| `GET` | `/api/threat-intel/blocklist` | Current active blocklist |
| `POST` | `/api/threat-intel/blocklist` | Add manual block entry |

### Geo & Fingerprint

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/geo/{ip}` | GeoIP data for an IP |
| `GET` | `/api/fingerprints` | OS/JA3 fingerprint database |

### WebSocket Events (Socket.IO)

Connect to `wss://hostname/socket.io/` and subscribe to rooms:

| Event | Direction | Payload |
|-------|-----------|---------|
| `alert:new` | Server→Client | New alert object |
| `traffic:tick` | Server→Client | 1-second traffic metrics |
| `engine:status` | Server→Client | Engine health status |
| `rule:updated` | Server→Client | Rule change notification |

### System

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Service health check |
| `GET` | `/api/metrics` | Prometheus-compatible metrics |

---

## GUI Pages

| Route | Description |
|-------|-------------|
| `/` | **Dashboard** – PostgreSQL alert, session, block, and service metrics |
| `/alerts` | **Alert Feed** – PostgreSQL alert filtering, acknowledgement, blocking, and CSV export |
| `/rules` | **Rule Manager** – PostgreSQL correlation, DPI, and L3/L4 rules |
| `/playbooks` | **Playbook Studio** – PostgreSQL definitions and execution history |
| `/threats` | **Threat Intel** – PostgreSQL feeds, IOC search, active blocklist, and manual block/unblock |
| `/sessions` | **Session Inspector** – PostgreSQL session records |
| `/forensics` | **Forensics** – PostgreSQL packet log; live rows require the host capture adapter |
| `/topology` | **Network Topology** – PostgreSQL connection graph |
| `/compliance` | **Compliance** – SQL checks, audit log, and HTML report export |
| `/settings` | **System Status** – live service health and adapter limitations |

The MongoDB-only NoSQL Explorer and DNS transaction tab are not in the current
navigation because they did not use PostgreSQL as their data source.

---

## Database Schema

### PostgreSQL (TimescaleDB)

> Full DDL is in [`db/postgres/init.sql`](db/postgres/init.sql).

| Table | Type | Description |
|-------|------|-------------|
| `tenants` | Regular | Multi-tenant isolation |
| `detection_rules` | Regular | Signature & threshold rules |
| `rule_categories` | Regular | Rule taxonomy |
| `alerts` | Hypertable | Time-series alert events |
| `blocked_ips` | Regular | Active IPS block entries |
| `threat_intel` | Regular | Deduplicated IoC store |
| `network_flows` | Hypertable | Aggregated per-minute flow stats |
| `engine_events` | Hypertable | Engine internal audit log |
| `notification_channels` | Regular | Alert delivery config |
| `users` | Regular | API user accounts |

### MongoDB

| Collection | TTL | Description |
|------------|-----|-------------|
| `raw_packets` | 7 days | Per-packet capture records |
| `pcap_chunks` | — | GridFS metadata sidecar |
| `geo_ip_cache` | — | GeoIP lookup cache |
| `threat_intel_raw` | — | Raw feed data (pre-processing) |
| `fingerprint_db` | — | OS / TLS / SSH fingerprints |
| `anomaly_vectors` | 30 days | ML feature vectors |
| `session_graphs` | — | IP communication graphs |
| `dns_query_log` | 14 days | DNS query/response log |
| `http_transaction_log` | — | HTTP DPI records |
| `tls_handshake_log` | — | TLS handshake details |
| `canary_access_log` | — | Canary token access events |

---

## Adding Custom Rules

Rules are stored in the `detection_rules` PostgreSQL table. Insert them directly via SQL or the API.

### Rule schema (simplified)

```sql
INSERT INTO detection_rules (
    name,
    category_id,
    description,
    protocol,          -- 'TCP', 'UDP', 'ICMP', 'ANY'
    src_ip_pattern,    -- CIDR or NULL for any
    dst_ip_pattern,
    dst_port,          -- integer or NULL
    flags,             -- TCP flags e.g. 'SYN' or NULL
    payload_pattern,   -- POSIX regex applied to payload_hex
    threshold_count,   -- trigger after N matches in window
    threshold_window,  -- window in seconds
    severity,          -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    action,            -- 'ALERT', 'BLOCK', 'LOG'
    enabled,
    tenant_id
) VALUES (
    'SSH Brute Force',
    (SELECT id FROM rule_categories WHERE slug = 'brute-force'),
    'More than 10 SSH connection attempts in 60 seconds from a single IP',
    'TCP',
    NULL,
    NULL,
    22,
    'SYN',
    NULL,
    10,
    60,
    'HIGH',
    'BLOCK',
    TRUE,
    NULL   -- NULL = applies to all tenants
);
```

### Rule categories

| Slug | Description |
|------|-------------|
| `recon` | Port scanning, OS fingerprinting |
| `brute-force` | Credential stuffing, dictionary attacks |
| `exploit` | Known CVE signatures |
| `malware-c2` | Command & control beaconing |
| `data-exfil` | Large data transfers, DNS tunneling |
| `policy` | Acceptable use policy violations |
| `anomaly` | Behavioural / ML-triggered |

---

## Contributing

1. Fork the repository and create a feature branch: `git checkout -b feature/my-feature`
2. Follow PEP 8 for Python and ESLint rules for TypeScript/JavaScript
3. Write tests for all new engine logic (`pytest engine/tests/`)
4. Add or update the relevant SQL migration in `db/postgres/`
5. Update `README.md` if you add new environment variables or API routes
6. Open a Pull Request against `main` with a clear description

### Validation

```bash
# GUI production build
cd gui && npm ci && npm run build

# Database trigger integration check (requires the Docker Compose stack)
Get-Content .\testing\verify_database_engine.sql -Raw |
  docker compose exec -T postgres psql -U idsips -d idsips -v ON_ERROR_STOP=1 -f -
```

There are currently no Python `pytest` suites or GUI lint/type-check scripts in
the repository. The GUI's `npm test` script is provided by Create React App and
requires test files to be added.

---

## License

```
MIT License

Copyright (c) 2024 Database-Driven IDS/IPS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
