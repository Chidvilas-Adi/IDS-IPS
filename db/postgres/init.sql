-- =============================================================================
-- DB-IDS/IPS ULTRA — Complete Database Schema & Seed Data
-- Database-Driven Intrusion Detection & Prevention System
-- All rules, signatures, playbooks, threat intel, and configs reside here.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- 1. CONFIGURATION & MULTI-TENANCY
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    network_ranges INET[] DEFAULT '{}',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'analyst',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(64) NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions JSONB DEFAULT '["read"]',
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS engine_configs (
    id SERIAL PRIMARY KEY,
    engine_name VARCHAR(50) NOT NULL,
    config_key VARCHAR(100) NOT NULL,
    config_value TEXT NOT NULL,
    value_type VARCHAR(20) DEFAULT 'string',
    description TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(engine_name, config_key)
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    channel_type VARCHAR(30) NOT NULL, -- email, slack, teams, pagerduty, webhook
    config JSONB NOT NULL,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 2. RULES ENGINE
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rules (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    src_ip INET,
    src_ip_mask INET,
    dst_ip INET,
    dst_ip_mask INET,
    src_port_min INT,
    src_port_max INT,
    dst_port_min INT,
    dst_port_max INT,
    protocol VARCHAR(10) DEFAULT 'ANY', -- TCP, UDP, ICMP, ANY
    direction VARCHAR(10) DEFAULT 'inbound',
    action VARCHAR(20) DEFAULT 'ALERT', -- ALERT, DROP, REJECT, ALLOW, LOG
    priority INT DEFAULT 100,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS correlation_rules (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL, -- THRESHOLD, SEQUENCE, RATIO, GEO_FENCE, IOC_MATCH, BEHAVIORAL, LATERAL_MOVEMENT, PROTOCOL_ANOMALY, TLS_DOWNGRADE, DNS_TUNNEL, CANARY_ACCESS
    event_filter JSONB NOT NULL,
    threshold_count INT DEFAULT 1,
    window_seconds INT DEFAULT 60,
    sequence_pattern JSONB,
    ratio_field VARCHAR(50),
    ratio_threshold FLOAT,
    action VARCHAR(20) DEFAULT 'ALERT',
    severity VARCHAR(20) DEFAULT 'MEDIUM', -- LOW, MEDIUM, HIGH, CRITICAL
    playbook_id INT,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dpi_signatures (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    protocol VARCHAR(20) DEFAULT 'ANY',
    layer INT DEFAULT 7,
    pattern_type VARCHAR(20) DEFAULT 'REGEX', -- REGEX, HEX_BYTES, EXACT
    pattern TEXT NOT NULL,
    offset_bytes INT DEFAULT 0,
    depth_bytes INT DEFAULT 0,
    severity VARCHAR(20) DEFAULT 'HIGH',
    cve VARCHAR(50),
    action VARCHAR(20) DEFAULT 'BLOCK',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 3. SESSIONS, FLOWS & NETWORK GRAPH
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INT NOT NULL,
    dst_port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    state VARCHAR(30) DEFAULT 'ESTABLISHED',
    bytes_sent BIGINT DEFAULT 0,
    bytes_recv BIGINT DEFAULT 0,
    packets_sent INT DEFAULT 0,
    packets_recv INT DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    flags JSONB DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS session_fingerprints (
    id BIGSERIAL PRIMARY KEY,
    session_id BIGINT REFERENCES sessions(id) ON DELETE CASCADE,
    os_guess VARCHAR(100),
    ttl INT,
    window_size INT,
    ja3_hash VARCHAR(32),
    hassh_hash VARCHAR(32),
    confidence FLOAT DEFAULT 0.0,
    raw_fingerprint JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS flow_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INT NOT NULL,
    dst_port INT NOT NULL,
    protocol VARCHAR(10) NOT NULL,
    bytes BIGINT DEFAULT 0,
    packets BIGINT DEFAULT 0,
    duration_ms INT DEFAULT 0,
    flow_start TIMESTAMPTZ DEFAULT NOW(),
    flow_end TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connection_graph_edges (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    connection_count INT DEFAULT 1,
    total_bytes BIGINT DEFAULT 0,
    UNIQUE(src_ip, dst_ip)
);

-- -----------------------------------------------------------------------------
-- 4. THREAT INTELLIGENCE & REPUTATION
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS threat_feeds (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    feed_type VARCHAR(50) DEFAULT 'JSON', -- JSON, CSV, TAXII, PLAIN_IP
    api_key_encrypted TEXT,
    poll_interval_minutes INT DEFAULT 60,
    last_polled_at TIMESTAMPTZ,
    enabled BOOLEAN DEFAULT true,
    ioc_count INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ioc_ipv4 (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    description TEXT
);

CREATE TABLE IF NOT EXISTS ioc_ipv6 (
    id BIGSERIAL PRIMARY KEY,
    ip INET NOT NULL,
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    description TEXT
);

CREATE TABLE IF NOT EXISTS ioc_domains (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ioc_urls (
    id BIGSERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ioc_hashes (
    id BIGSERIAL PRIMARY KEY,
    hash_type VARCHAR(20) NOT NULL, -- MD5, SHA1, SHA256
    hash_value VARCHAR(128) NOT NULL,
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    tags TEXT[] DEFAULT '{}',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ioc_certificates (
    id BIGSERIAL PRIMARY KEY,
    fingerprint VARCHAR(64) NOT NULL,
    subject VARCHAR(255),
    issuer VARCHAR(255),
    confidence INT DEFAULT 100,
    severity VARCHAR(20) DEFAULT 'HIGH',
    source VARCHAR(100) DEFAULT 'manual',
    first_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS geo_rules (
    id SERIAL PRIMARY KEY,
    country_code CHAR(2) NOT NULL,
    country_name VARCHAR(100),
    action VARCHAR(20) DEFAULT 'BLOCK', -- BLOCK, ALERT, ALLOW
    direction VARCHAR(10) DEFAULT 'inbound',
    severity VARCHAR(20) DEFAULT 'HIGH',
    enabled BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    id BIGSERIAL PRIMARY KEY,
    ip INET UNIQUE NOT NULL,
    score INT DEFAULT 0,
    alert_count INT DEFAULT 0,
    block_count INT DEFAULT 0,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    tags TEXT[] DEFAULT '{}',
    notes TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_behavior_profiles (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,
    normal_hours_start TIME DEFAULT '08:00:00',
    normal_hours_end TIME DEFAULT '19:00:00',
    avg_bytes_per_day BIGINT DEFAULT 100000000,
    avg_sessions_per_day INT DEFAULT 50,
    normal_src_ips INET[] DEFAULT '{}',
    normal_dst_ips INET[] DEFAULT '{}',
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS anomaly_models (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    algorithm VARCHAR(50) DEFAULT 'IsolationForest',
    parameters JSONB NOT NULL DEFAULT '{}',
    feature_names TEXT[] DEFAULT '{}',
    trained_at TIMESTAMPTZ DEFAULT NOW(),
    accuracy FLOAT DEFAULT 0.95,
    enabled BOOLEAN DEFAULT true
);

-- -----------------------------------------------------------------------------
-- 5. ALERTS & INCIDENTS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    rule_id INT,
    rule_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(10),
    packet_summary JSONB,
    enrichment JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'open', -- open, acknowledged, resolved, false_positive
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',
    alert_ids BIGINT[] DEFAULT '{}',
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT REFERENCES incidents(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    description TEXT,
    actor VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS false_positive_feedback (
    id BIGSERIAL PRIMARY KEY,
    alert_id BIGINT REFERENCES alerts(id) ON DELETE CASCADE,
    analyst_id INT REFERENCES users(id) ON DELETE SET NULL,
    feedback VARCHAR(50) NOT NULL,
    reason TEXT,
    rule_adjustment JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- 6. AUTOMATED RESPONSE & PLAYBOOKS
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS action_templates (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- BLOCK_SRC_IP, CREATE_ALERT, SEND_NOTIFICATION, CAPTURE_PCAP, UPDATE_REPUTATION, THROTTLE_FLOW, REDIRECT_HONEYPOT, TCP_RST, DNS_SINKHOLE, ISOLATE_HOST
    description TEXT,
    parameters JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS playbooks (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(150) NOT NULL,
    description TEXT,
    trigger_severity VARCHAR(20),
    trigger_rule_type VARCHAR(50),
    auto_execute BOOLEAN DEFAULT true,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbook_steps (
    id SERIAL PRIMARY KEY,
    playbook_id INT REFERENCES playbooks(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    action_template_id INT REFERENCES action_templates(id) ON DELETE CASCADE,
    parameters JSONB DEFAULT '{}',
    wait_seconds_after INT DEFAULT 0,
    continue_on_failure BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS playbook_executions (
    id BIGSERIAL PRIMARY KEY,
    playbook_id INT REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    status VARCHAR(30) DEFAULT 'RUNNING', -- RUNNING, COMPLETED, FAILED
    step_results JSONB DEFAULT '[]',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    ip INET NOT NULL,
    reason TEXT NOT NULL,
    alert_id BIGINT REFERENCES alerts(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(50) DEFAULT 'engine',
    active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS throttled_flows (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    dst_port INT,
    rate_kbps INT DEFAULT 100,
    reason TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS honeypot_redirects (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    match_dst_ip INET,
    match_dst_port INT,
    honeypot_ip INET NOT NULL,
    honeypot_port INT NOT NULL,
    reason TEXT,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS honeypot_configs (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    honeypot_ip INET NOT NULL,
    honeypot_port INT NOT NULL,
    service_type VARCHAR(50) DEFAULT 'SSH', -- SSH, HTTP, FTP, TELNET
    emulation_config JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sinkhole_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    sinkhole_ip INET NOT NULL,
    reason TEXT,
    source VARCHAR(100) DEFAULT 'manual',
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS canary_tokens (
    id SERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
    token_name VARCHAR(100) NOT NULL,
    token_value TEXT NOT NULL,
    description TEXT,
    alert_severity VARCHAR(20) DEFAULT 'CRITICAL',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_accessed TIMESTAMPTZ,
    access_count INT DEFAULT 0
);

-- -----------------------------------------------------------------------------
-- 7. AUDIT, COMPLIANCE & RETENTION
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL,
    actor VARCHAR(100) NOT NULL,
    actor_type VARCHAR(50) DEFAULT 'user', -- user, engine, api
    action VARCHAR(50) NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    record_id BIGINT,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_checks (
    id SERIAL PRIMARY KEY,
    framework VARCHAR(50) NOT NULL, -- PCI-DSS, HIPAA, SOC2, ISO27001
    check_name VARCHAR(150) NOT NULL,
    description TEXT,
    check_query TEXT NOT NULL,
    expected_result JSONB NOT NULL,
    severity VARCHAR(20) DEFAULT 'HIGH',
    last_run_at TIMESTAMPTZ,
    last_status VARCHAR(20) DEFAULT 'NOT_RUN', -- PASS, FAIL, ERROR, NOT_RUN
    last_result JSONB
);

CREATE TABLE IF NOT EXISTS data_retention_policies (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(100) UNIQUE NOT NULL,
    retention_days INT NOT NULL,
    cleanup_column VARCHAR(50) DEFAULT 'created_at',
    enabled BOOLEAN DEFAULT true
);

-- -----------------------------------------------------------------------------
-- INDEXES FOR MAXIMUM THROUGHPUT
-- -----------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_sessions_ips ON sessions(src_ip, dst_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(active);
CREATE INDEX IF NOT EXISTS idx_ioc_ipv4_ip ON ioc_ipv4(ip);
CREATE INDEX IF NOT EXISTS idx_ioc_domains_domain ON ioc_domains(domain);
CREATE INDEX IF NOT EXISTS idx_rules_enabled_priority ON rules(enabled, priority ASC);
CREATE INDEX IF NOT EXISTS idx_correlation_rules_enabled ON correlation_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_dpi_signatures_enabled ON dpi_signatures(enabled);
CREATE INDEX IF NOT EXISTS idx_ip_reputation_ip ON ip_reputation(ip);
CREATE INDEX IF NOT EXISTS idx_connection_graph_src_dst ON connection_graph_edges(src_ip, dst_ip);

-- -----------------------------------------------------------------------------
-- SEED DATA: TENANT & USERS
-- -----------------------------------------------------------------------------

INSERT INTO tenants (id, name, description, network_ranges)
VALUES (1, 'Default SOC Org', 'Main corporate protected perimeter', '{"192.168.0.0/16", "10.0.0.0/8"}')
ON CONFLICT (id) DO NOTHING;

-- Default password is 'admin123' hashed with SHA256 for demo
INSERT INTO users (id, tenant_id, username, email, password_hash, role)
VALUES (1, 1, 'admin', 'soc-admin@idsips.local', '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', 'admin')
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- SEED DATA: ACTION TEMPLATES
-- -----------------------------------------------------------------------------

INSERT INTO action_templates (id, name, action_type, description, parameters) VALUES
(1, 'BLOCK_SRC_IP', 'BLOCK_SRC_IP', 'Add IP to firewall drop list and Redis hot cache', '{"duration_minutes": 60}'),
(2, 'CREATE_ALERT', 'CREATE_ALERT', 'Record formal alert in PostgreSQL with packet metadata', '{}'),
(3, 'SEND_NOTIFICATION', 'SEND_NOTIFICATION', 'Dispatch alert to Slack/Teams/Email channels', '{"channels": ["slack", "email"]}'),
(4, 'CAPTURE_PCAP', 'CAPTURE_PCAP', 'Trigger Scapy sniffer to record full PCAP flow', '{"duration_seconds": 30}'),
(5, 'UPDATE_REPUTATION', 'UPDATE_REPUTATION', 'Increase IP threat score', '{"score_delta": 40}'),
(6, 'THROTTLE_FLOW', 'THROTTLE_FLOW', 'Rate limit traffic from source IP using tc qdisc', '{"rate_kbps": 128}'),
(7, 'REDIRECT_HONEYPOT', 'REDIRECT_HONEYPOT', 'Transparently redirect source flow to honeypot decoy', '{"honeypot_ip": "10.0.99.100", "honeypot_port": 2222}'),
(8, 'TCP_RST', 'TCP_RST', 'Forge and transmit immediate TCP RST termination packet', '{}'),
(9, 'DNS_SINKHOLE', 'DNS_SINKHOLE', 'Poison DNS resolution to redirect C2 malware domain', '{"sinkhole_ip": "127.0.0.1"}')
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- SEED DATA: PLAYBOOKS
-- -----------------------------------------------------------------------------

INSERT INTO playbooks (id, tenant_id, name, description, trigger_severity, trigger_rule_type, auto_execute) VALUES
(1, 1, 'SSH Brute Force Mitigation', 'Blocks attacker, alerts SOC, and captures PCAP evidence', 'HIGH', 'THRESHOLD', true),
(2, 1, 'Exploit Attempt Instant Defense', 'Zero-tolerance block, TCP RST injection, and reputation update', 'CRITICAL', 'DPI_SIGNATURE', true),
(3, 1, 'Lateral Movement Containment', 'Isolates internal source host exhibiting worm/scanning behavior', 'CRITICAL', 'LATERAL_MOVEMENT', true)
ON CONFLICT (id) DO NOTHING;

INSERT INTO playbook_steps (playbook_id, step_order, action_template_id, parameters) VALUES
(1, 1, 1, '{"duration_minutes": 120}'),
(1, 2, 2, '{}'),
(1, 3, 5, '{"score_delta": 50}'),
(2, 1, 8, '{}'),
(2, 2, 1, '{"duration_minutes": 1440}'),
(2, 3, 4, '{"duration_seconds": 60}'),
(2, 4, 2, '{}'),
(3, 1, 1, '{"duration_minutes": 720}'),
(3, 2, 3, '{"channels": ["slack"]}')
ON CONFLICT DO NOTHING;

-- -----------------------------------------------------------------------------
-- SEED DATA: CORRELATION RULES (Fully Database-Driven!)
-- -----------------------------------------------------------------------------

INSERT INTO correlation_rules (tenant_id, name, description, rule_type, event_filter, threshold_count, window_seconds, action, severity, playbook_id) VALUES
(1, 'SSH Brute Force Detection', 'More than 5 SYN connection attempts to SSH port 22 within 60s', 'THRESHOLD', '{"dst_port": 22, "protocol": "TCP", "tcp_flags": "S"}', 5, 60, 'BLOCK', 'HIGH', 1),
(1, 'TCP Port Sweep Scan', 'Single source probing more than 15 distinct destination ports within 10s', 'THRESHOLD', '{"protocol": "TCP", "unique_ports": true}', 15, 10, 'BLOCK', 'HIGH', 1),
(1, 'SYN Flood Attack', 'Excessive raw TCP SYN packets from single source over 100 per 5 seconds', 'THRESHOLD', '{"protocol": "TCP", "tcp_flags": "S"}', 100, 5, 'BLOCK', 'CRITICAL', 2),
(1, 'HTTP Brute Force Login', 'More than 10 HTTP POST requests to /login in 30 seconds', 'THRESHOLD', '{"dst_port": 80, "protocol": "TCP", "uri": "/login"}', 10, 30, 'BLOCK', 'MEDIUM', 1),
(1, 'DNS NXDOMAIN Tunneling Detection', 'Over 30 NXDOMAIN DNS queries from internal host in 60s', 'DNS_TUNNEL', '{"protocol": "UDP", "dst_port": 53}', 30, 60, 'ALERT', 'HIGH', NULL),
(1, 'High-Risk Geo-Location Access', 'Inbound connection originating from geoblocked jurisdiction', 'GEO_FENCE', '{"direction": "inbound"}', 1, 1, 'BLOCK', 'HIGH', 1),
(1, 'Threat Feed Known Bad IP Match', 'Connection to or from active global IOC list IP', 'IOC_MATCH', '{}', 1, 1, 'BLOCK', 'CRITICAL', 2),
(1, 'Internal Lateral Movement Probe', 'Source connects to more than 8 internal hosts on RPC/SMB within 60s', 'LATERAL_MOVEMENT', '{"dst_ports": [445, 135, 139]}', 8, 60, 'BLOCK', 'CRITICAL', 3),
(1, 'Canary Token Unauthorized Access', 'Query triggered against internal deception canary token', 'CANARY_ACCESS', '{}', 1, 1, 'ALERT', 'CRITICAL', 2)
ON CONFLICT DO NOTHING;

-- -----------------------------------------------------------------------------
-- SEED DATA: DPI SIGNATURES
-- -----------------------------------------------------------------------------

INSERT INTO dpi_signatures (tenant_id, name, description, protocol, layer, pattern_type, pattern, severity, cve, action) VALUES
(1, 'SQL Injection - Generic UNION SELECT', 'Detects UNION based SQL injection in HTTP query/body', 'HTTP', 7, 'REGEX', '(?i)(union(\s+all)?\s+select)', 'CRITICAL', 'CWE-89', 'BLOCK'),
(1, 'SQL Injection - OR 1=1 Boolean Bypass', 'Detects classic SQL auth bypass payload', 'HTTP', 7, 'REGEX', '(?i)(\''\s*or\s*[\''\d]+\s*=\s*[\''\d]+|--\s*$)', 'HIGH', 'CWE-89', 'BLOCK'),
(1, 'Log4Shell JNDI Lookup', 'Detects Log4j CVE-2021-44228 remote code execution payloads', 'TCP', 7, 'REGEX', '\$\{(jndi|j\$\{:\-n\}di):(ldap|rmi|dns|nis):', 'CRITICAL', 'CVE-2021-44228', 'BLOCK'),
(1, 'EternalBlue SMBv1 Exploit Header', 'Detects WannaCry / EternalBlue MS17-010 SMB exploit packet', 'TCP', 7, 'HEX_BYTES', 'ff534d427200000000', 'CRITICAL', 'CVE-2017-0144', 'BLOCK'),
(1, 'Spring4Shell Spring Core RCE', 'Detects Spring4Shell class.module.classLoader manipulation', 'HTTP', 7, 'REGEX', '(?i)class\.module\.classLoader', 'CRITICAL', 'CVE-2022-22965', 'BLOCK'),
(1, 'Cross-Site Scripting (XSS) Tag Injection', 'Detects unencoded script tag injections in payload', 'HTTP', 7, 'REGEX', '(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>', 'HIGH', 'CWE-79', 'BLOCK'),
(1, 'Unix Bash Reverse Shell Pattern', 'Detects bash interactive socket redirection in traffic', 'TCP', 7, 'REGEX', 'bash\s+-i\s+>&?\s*/dev/tcp/', 'CRITICAL', 'CWE-78', 'BLOCK'),
(1, 'EICAR Standard Antivirus Test String', 'Standard benign file test pattern for security verification', 'ANY', 7, 'EXACT', 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*', 'MEDIUM', 'EICAR-TEST', 'ALERT')
ON CONFLICT DO NOTHING;

-- -----------------------------------------------------------------------------
-- SEED DATA: THREAT FEEDS & SINKHOLES & CANARY
-- -----------------------------------------------------------------------------

INSERT INTO threat_feeds (name, url, feed_type, poll_interval_minutes, enabled) VALUES
('Feodo Tracker Botnet C2', 'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 'JSON', 30, true),
('Emerging Threats Compromised IPs', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 'PLAIN_IP', 60, true),
('AbuseIPDB Global Blacklist', 'https://api.abuseipdb.com/api/v2/blacklist', 'JSON', 120, false)
ON CONFLICT DO NOTHING;

INSERT INTO canary_tokens (tenant_id, token_name, token_value, description, alert_severity) VALUES
(1, 'DB_ADMIN_CREDENTIAL_CANARY', 'CANARY_SQL_KEY_9882a17f', 'Fake DB admin password planted in mock table', 'CRITICAL'),
(1, 'INTERNAL_AWS_S3_KEY_CANARY', 'AKIA_FAKE_CANARY_TEST_0019', 'Fake AWS API credential monitored for exfiltration', 'CRITICAL')
ON CONFLICT DO NOTHING;

INSERT INTO data_retention_policies (table_name, retention_days, cleanup_column) VALUES
('sessions', 14, 'last_seen_at'),
('flow_records', 30, 'flow_start'),
('alerts', 90, 'created_at'),
('audit_log', 180, 'created_at'),
('playbook_executions', 30, 'started_at')
ON CONFLICT (table_name) DO NOTHING;

INSERT INTO compliance_checks (framework, check_name, description, check_query, expected_result, severity) VALUES
('PCI-DSS', '1.1.4 - Firewall Rule Review', 'Verify that default deny or active firewall rules exist', 'SELECT COUNT(*) FROM rules WHERE enabled = true', '{"min_count": 1}', 'CRITICAL'),
('PCI-DSS', '10.2.1 - Audit Trail Verification', 'Verify audit trail logging is capturing modifications', 'SELECT COUNT(*) FROM audit_log', '{"min_count": 1}', 'HIGH'),
('HIPAA', '164.312(b) - Audit Controls', 'Ensure security events and alert history are maintained', 'SELECT COUNT(*) FROM alerts', '{"min_count": 0}', 'HIGH')
ON CONFLICT DO NOTHING;
-- =============================================================================
-- DB-IDS/IPS ULTRA: 100% IN-DATABASE INTELLIGENCE ENGINE (PL/pgSQL)
-- ALL CALCULATIONS, CORRELATIONS, SIGNATURE MATCHES, AND ACTIONS OCCUR INSIDE SQL.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. INGRESS PACKETS TABLE (Direct destination for raw socket dumps)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingress_packets (
    id BIGSERIAL PRIMARY KEY,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INT,
    dst_port INT,
    protocol VARCHAR(10) NOT NULL,
    tcp_flags VARCHAR(10) DEFAULT '',
    packet_length INT DEFAULT 0,
    payload_text TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ingress_src_time ON ingress_packets(src_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ingress_dst_port ON ingress_packets(dst_port, created_at DESC);

-- -----------------------------------------------------------------------------
-- 2. IN-DATABASE STORED PROCEDURE: DPI PATTERN MATCHING
-- Uses PostgreSQL's native regular expression engine (~*) inside the database
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_sql_dpi_inspect(
    p_packet_id BIGINT,
    p_src_ip INET,
    p_dst_ip INET,
    p_src_port INT,
    p_dst_port INT,
    p_protocol VARCHAR,
    p_payload TEXT
) RETURNS VOID AS $$
DECLARE
    v_sig RECORD;
    v_alert_id BIGINT;
BEGIN
    IF p_payload IS NULL OR length(p_payload) = 0 THEN
        RETURN;
    END IF;

    -- Query active DPI signatures directly inside PostgreSQL
    FOR v_sig IN 
        SELECT id, name, pattern, severity, action, cve 
        FROM dpi_signatures 
        WHERE enabled = true 
          AND (protocol = 'ANY' OR UPPER(protocol) = UPPER(p_protocol))
    LOOP
        -- Execute regex or exact pattern matching using SQL native operators
        IF p_payload ~* v_sig.pattern THEN
            -- 1. Insert alert generated by SQL
            INSERT INTO alerts (
                tenant_id, rule_id, rule_type, severity, 
                src_ip, dst_ip, src_port, dst_port, protocol, 
                packet_summary, status, created_at
            ) VALUES (
                1, v_sig.id, 'SQL_DPI_SIGNATURE', v_sig.severity,
                p_src_ip, p_dst_ip, p_src_port, p_dst_port, p_protocol,
                json_build_object(
                    'detected_by', 'PL/pgSQL in-database engine',
                    'signature_name', v_sig.name,
                    'cve', v_sig.cve,
                    'packet_id', p_packet_id
                ),
                'open', NOW()
            ) RETURNING id INTO v_alert_id;

            -- 2. If action is BLOCK, update database blocked_ips table and notify OS
            IF v_sig.action = 'BLOCK' THEN
                INSERT INTO blocked_ips (tenant_id, ip, reason, alert_id, expires_at, created_by, active)
                VALUES (
                    1, p_src_ip, 
                    'Triggered by PL/pgSQL DPI: ' || v_sig.name || ' (' || COALESCE(v_sig.cve, 'CWE') || ')',
                    v_alert_id, NOW() + INTERVAL '120 minutes', 'PostgreSQL_Trigger', true
                );

                -- Trigger database notification event for firewall actuators
                PERFORM pg_notify('db_firewall_action', json_build_object(
                    'action', 'BLOCK',
                    'ip', p_src_ip::text,
                    'reason', v_sig.name,
                    'alert_id', v_alert_id
                )::text);
            END IF;

            -- 3. Update reputation score directly in SQL
            INSERT INTO ip_reputation (ip, score, alert_count, last_seen, first_seen)
            VALUES (p_src_ip, 50, 1, NOW(), NOW())
            ON CONFLICT (ip) DO UPDATE SET 
                score = LEAST(100, ip_reputation.score + 40),
                alert_count = ip_reputation.alert_count + 1,
                last_seen = NOW();
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- 3. IN-DATABASE STORED PROCEDURE: MULTI-EVENT CORRELATION ENGINE
-- Calculates thresholds, sliding-windows, and port sweeps directly inside SQL!
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_sql_correlate_threats(
    p_src_ip INET,
    p_dst_port INT,
    p_protocol VARCHAR,
    p_tcp_flags VARCHAR
) RETURNS VOID AS $$
DECLARE
    v_recent_syn_count INT;
    v_distinct_port_count INT;
    v_alert_id BIGINT;
    v_is_already_blocked BOOLEAN;
BEGIN
    -- Check if IP is already blocked in SQL
    SELECT EXISTS(SELECT 1 FROM blocked_ips WHERE ip = p_src_ip AND active = true) INTO v_is_already_blocked;
    IF v_is_already_blocked THEN
        RETURN;
    END IF;

    -- -------------------------------------------------------------------------
    -- Correlation Rule A: SSH Brute Force (> 5 attempts in 60s window in SQL)
    -- -------------------------------------------------------------------------
    IF p_dst_port = 22 AND p_protocol = 'TCP' THEN
        SELECT COUNT(*) INTO v_recent_syn_count
        FROM ingress_packets
        WHERE src_ip = p_src_ip 
          AND dst_port = 22 
          AND created_at >= NOW() - INTERVAL '60 seconds';

        IF v_recent_syn_count >= 5 THEN
            INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
            VALUES (
                1, 'SQL_CORRELATION', 'HIGH', p_src_ip, '0.0.0.0'::inet, 22, 'TCP',
                json_build_object(
                    'rule_name', 'SSH Brute Force Detection',
                    'engine', 'PostgreSQL PL/pgSQL Sliding Window',
                    'window_seconds', 60,
                    'calculated_count', v_recent_syn_count
                ),
                'open'
            ) RETURNING id INTO v_alert_id;

            INSERT INTO blocked_ips (tenant_id, ip, reason, alert_id, expires_at, created_by, active)
            VALUES (1, p_src_ip, 'In-Database SSH Brute Force Threshold Exceeded', v_alert_id, NOW() + INTERVAL '60 minutes', 'PL/pgSQL', true);

            PERFORM pg_notify('db_firewall_action', json_build_object('action', 'BLOCK', 'ip', p_src_ip::text, 'reason', 'SSH Brute Force', 'alert_id', v_alert_id)::text);
            RETURN;
        END IF;
    END IF;

    -- -------------------------------------------------------------------------
    -- Correlation Rule B: Horizontal Port Scan (> 15 distinct ports in 10s window in SQL)
    -- -------------------------------------------------------------------------
    IF p_protocol = 'TCP' THEN
        SELECT COUNT(DISTINCT dst_port) INTO v_distinct_port_count
        FROM ingress_packets
        WHERE src_ip = p_src_ip 
          AND created_at >= NOW() - INTERVAL '10 seconds';

        IF v_distinct_port_count >= 15 THEN
            INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
            VALUES (
                1, 'SQL_CORRELATION', 'HIGH', p_src_ip, '0.0.0.0'::inet, p_dst_port, 'TCP',
                json_build_object(
                    'rule_name', 'TCP Port Sweep Scan',
                    'engine', 'PostgreSQL DISTINCT Port Aggregation',
                    'unique_ports_scanned', v_distinct_port_count
                ),
                'open'
            ) RETURNING id INTO v_alert_id;

            INSERT INTO blocked_ips (tenant_id, ip, reason, alert_id, expires_at, created_by, active)
            VALUES (1, p_src_ip, 'In-Database Port Sweep Scan Detected', v_alert_id, NOW() + INTERVAL '120 minutes', 'PL/pgSQL', true);

            PERFORM pg_notify('db_firewall_action', json_build_object('action', 'BLOCK', 'ip', p_src_ip::text, 'reason', 'Port Sweep Scan', 'alert_id', v_alert_id)::text);
            RETURN;
        END IF;
    END IF;

    -- -------------------------------------------------------------------------
    -- Correlation Rule C: IOC Database Match against ioc_ipv4 table
    -- -------------------------------------------------------------------------
    IF EXISTS(SELECT 1 FROM ioc_ipv4 WHERE ip = p_src_ip) THEN
        INSERT INTO alerts (tenant_id, rule_type, severity, src_ip, dst_ip, dst_port, protocol, packet_summary, status)
        VALUES (
            1, 'SQL_IOC_MATCH', 'CRITICAL', p_src_ip, '0.0.0.0'::inet, p_dst_port, p_protocol,
            json_build_object('rule_name', 'Global Threat Feed Match', 'source', 'ioc_ipv4 table'),
            'open'
        ) RETURNING id INTO v_alert_id;

        INSERT INTO blocked_ips (tenant_id, ip, reason, alert_id, expires_at, created_by, active)
        VALUES (1, p_src_ip, 'In-Database Threat Feed IOC Match', v_alert_id, NOW() + INTERVAL '1440 minutes', 'PL/pgSQL', true);

        PERFORM pg_notify('db_firewall_action', json_build_object('action', 'BLOCK', 'ip', p_src_ip::text, 'reason', 'IOC Blacklist', 'alert_id', v_alert_id)::text);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- 4. THE MASTER IN-DATABASE TRIGGER: ON INSERT INTO ingress_packets
-- Fired for every single packet entering the database.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION trg_fn_process_packet_ingress() 
RETURNS TRIGGER AS $$
BEGIN
    -- 1. In-Database Session Upsert (Stateful Tracking in SQL)
    INSERT INTO sessions (
        tenant_id, src_ip, dst_ip, src_port, dst_port, 
        protocol, state, bytes_sent, packets_sent, started_at, last_seen_at
    ) VALUES (
        1, NEW.src_ip, NEW.dst_ip, NEW.src_port, NEW.dst_port,
        NEW.protocol, 'ACTIVE', NEW.packet_length, 1, NOW(), NOW()
    )
    ON CONFLICT DO NOTHING;

    -- 2. In-Database Network Topology Graph Edge Upsert
    INSERT INTO connection_graph_edges (tenant_id, src_ip, dst_ip, first_seen, last_seen, connection_count, total_bytes)
    VALUES (1, NEW.src_ip, NEW.dst_ip, NOW(), NOW(), 1, NEW.packet_length)
    ON CONFLICT (src_ip, dst_ip) DO UPDATE SET
        last_seen = NOW(),
        connection_count = connection_graph_edges.connection_count + 1,
        total_bytes = connection_graph_edges.total_bytes + NEW.packet_length;

    -- 3. Execute In-Database DPI (Deep Packet Inspection)
    PERFORM fn_sql_dpi_inspect(
        NEW.id, NEW.src_ip, NEW.dst_ip, 
        NEW.src_port, NEW.dst_port, NEW.protocol, NEW.payload_text
    );

    -- 4. Execute In-Database Sliding-Window Event Correlation
    PERFORM fn_sql_correlate_threats(
        NEW.src_ip, NEW.dst_port, NEW.protocol, NEW.tcp_flags
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Bind Trigger to ingress_packets
DROP TRIGGER IF EXISTS trg_packet_ingress ON ingress_packets;
CREATE TRIGGER trg_packet_ingress
AFTER INSERT ON ingress_packets
FOR EACH ROW
EXECUTE FUNCTION trg_fn_process_packet_ingress();
