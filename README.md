# Database-Driven IDS/IPS System

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](engine/)
[![Node](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js)](gui/)

A production-grade, **database-driven Intrusion Detection and Prevention System** (IDS/IPS) that captures network packets in real time, evaluates them against a rich rule engine backed by **TimescaleDB**, enriches them with threat intelligence from **MongoDB**, and caches hot data in **Redis** — all surfaced through a REST/WebSocket API and a React dashboard.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Manual Setup](#manual-setup)
- [Environment Variables](#environment-variables)
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
                     │               NGINX (80/443)                 │
                     │  HTTP→HTTPS redirect · SSL termination       │
                     │  Rate limiting · WebSocket proxy             │
                     └────────────┬─────────────────┬──────────────┘
                                  │                 │
                     ┌────────────▼───┐     ┌───────▼──────────┐
                     │  Flask API     │     │  React/Next.js   │
                     │  (port 5000)   │     │  GUI (port 3000) │
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
| `postgres` | `timescale/timescaledb:latest-pg16` | 5432 | Rules, alerts, events (time-series) |
| `mongodb` | `mongo:7` | 27017 | Raw packets, threat intel, ML vectors |
| `redis` | `redis:7-alpine` | 6379 | Rule cache, session store, rate limiting |
| `engine` | `./engine` | — | Packet capture & rule evaluation |
| `threat_feed_ingester` | `./engine` | — | Pulls external threat feeds |
| `api` | `./api` | 5000 | REST + WebSocket API (Flask) |
| `gui` | `./gui` | 3000 | React dashboard |
| `nginx` | `nginx:alpine` | 80/443 | Reverse proxy, SSL termination |

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

> **Note:** On macOS or Windows, raw packet capture inside Docker requires additional configuration (e.g., a Linux VM or WSL2). For development you can disable the engine service and replay pcap files.

---

## Quick Start (Docker)

```bash
# 1. Clone the repository
git clone https://github.com/your-org/db-ids-ips.git
cd db-ids-ips

# 2. Copy and edit the environment file
cp .env.example .env
$EDITOR .env   # Fill in API keys and secrets

# 3. Generate a self-signed TLS certificate for NGINX
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout nginx/ssl/self-signed.key \
  -out    nginx/ssl/self-signed.crt \
  -subj "/CN=idsips.local"

# 4. Start all services
docker compose up -d --build

# 5. Verify services are healthy
docker compose ps

# 6. Open the dashboard
#    https://localhost  (accept the self-signed certificate warning)
```

### Useful commands

```bash
# Follow engine logs
docker compose logs -f engine

# Tail all logs
docker compose logs -f

# Restart a single service
docker compose restart api

# Stop everything (keep volumes)
docker compose down

# Stop and wipe all data
docker compose down -v
```

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
pip install -r requirements.txt
# Requires NET_RAW capability or sudo on Linux
sudo python engine.py
```

### 4. Threat Feed Ingester

```bash
cd engine
source .venv/bin/activate
python threat_feed_ingester.py
```

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
npm install
npm run dev     # development
npm run build && npm start  # production
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
| `MONGO_URI` | — | MongoDB connection URI |
| `MONGO_DB` | `idsips` | MongoDB database name |
| `REDIS_URL` | — | Redis connection URL |
| `REDIS_PASSWORD` | — | Redis AUTH password |
| `SECRET_KEY` | — | Flask session secret (32+ chars) |
| `JWT_SECRET_KEY` | — | JWT signing secret (32+ chars) |
| `NETWORK_INTERFACE` | `eth0` | Interface for packet capture |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB threat feed key |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key |
| `SHODAN_API_KEY` | — | Shodan API key |
| `OTX_API_KEY` | — | AlienVault OTX API key |
| `SMTP_HOST` | — | SMTP relay hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `ENGINE_POLL_INTERVAL` | `1` | Packet batch flush interval (seconds) |
| `RULE_CACHE_TTL` | `60` | Redis rule cache TTL (seconds) |
| `MAX_PACKET_QUEUE` | `10000` | In-memory packet queue depth |
| `HONEYPOT_IP` | — | IP of internal honeypot host |
| `SINKHOLE_IP` | — | IP of internal DNS sinkhole |

> **Tip:** Generate strong secrets with: `python -c "import secrets; print(secrets.token_hex(32))"`

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
| `/` | **Dashboard** – real-time traffic graph, alert severity pie, top-talker map |
| `/alerts` | **Alert Center** – filterable alert table with drill-down |
| `/rules` | **Rule Manager** – CRUD editor for detection rules |
| `/traffic` | **Traffic Analysis** – flow table, protocol breakdown, bandwidth charts |
| `/threat-intel` | **Threat Intelligence** – IP lookup, blocklist management, feed status |
| `/geo-map` | **Geo Map** – world map of source IPs with heatmap overlay |
| `/fingerprints` | **Fingerprint DB** – OS/JA3/HASSH browser |
| `/anomalies` | **Anomaly Explorer** – ML anomaly score timelines |
| `/pcap` | **PCAP Viewer** – upload & replay .pcap files |
| `/settings` | **Settings** – notification config, API keys, tenant management |

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

### Running tests

```bash
# Engine unit tests
cd engine && pytest -v

# API integration tests
cd api && pytest -v

# GUI lint + type-check
cd gui && npm run lint && npm run type-check
```

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
