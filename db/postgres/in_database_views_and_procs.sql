-- =============================================================================
-- IN-DATABASE STORED PROCEDURES & ANALYTICAL VIEWS (PL/pgSQL)
-- Ensures 100% of calculations, aggregations, and actions are performed in SQL.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. STORED PROCEDURES FOR IN-DATABASE MANAGEMENT
-- -----------------------------------------------------------------------------

-- Procedure to manually or automatically block an IP directly in the database
CREATE OR REPLACE PROCEDURE sp_block_ip(
    p_ip INET,
    p_duration_minutes INT DEFAULT 60,
    p_reason TEXT DEFAULT 'Manual Admin Action',
    p_actor VARCHAR DEFAULT 'admin'
)
LANGUAGE plpgsql AS $$
DECLARE
    v_alert_id BIGINT;
BEGIN
    -- 1. Check if already active
    IF EXISTS (SELECT 1 FROM blocked_ips WHERE ip = p_ip AND active = true) THEN
        UPDATE blocked_ips 
        SET expires_at = NOW() + (p_duration_minutes || ' minutes')::interval,
            reason = p_reason
        WHERE ip = p_ip AND active = true;
    ELSE
        INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, created_by, active)
        VALUES (1, p_ip, p_reason, NOW() + (p_duration_minutes || ' minutes')::interval, p_actor, true);
    END IF;

    -- 2. Audit log recorded by SQL
    INSERT INTO audit_log (tenant_id, actor, actor_type, action, table_name, ip_address)
    VALUES (1, p_actor, 'database_procedure', 'BLOCK_IP', 'blocked_ips', p_ip);

    -- 3. Emit PostgreSQL NOTIFY event to host firewall
    PERFORM pg_notify('db_firewall_action', json_build_object(
        'action', 'BLOCK',
        'ip', p_ip::text,
        'reason', p_reason
    )::text);
END;
$$;

-- Procedure to unblock an IP directly in the database
CREATE OR REPLACE PROCEDURE sp_unblock_ip(
    p_ip INET,
    p_actor VARCHAR DEFAULT 'admin'
)
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE blocked_ips SET active = false WHERE ip = p_ip;

    INSERT INTO audit_log (tenant_id, actor, actor_type, action, table_name, ip_address)
    VALUES (1, p_actor, 'database_procedure', 'UNBLOCK_IP', 'blocked_ips', p_ip);

    PERFORM pg_notify('db_firewall_action', json_build_object(
        'action', 'UNBLOCK',
        'ip', p_ip::text
    )::text);
END;
$$;

-- Procedure for automated in-database housekeeping & expired block cleanup
CREATE OR REPLACE PROCEDURE sp_purge_expired_records()
LANGUAGE plpgsql AS $$
DECLARE
    v_unblocked_count INT := 0;
BEGIN
    -- Deactivate expired blocked IPs
    UPDATE blocked_ips 
    SET active = false 
    WHERE active = true AND expires_at < NOW();

    -- Clean old raw ingress packets older than 48 hours to conserve disk
    DELETE FROM ingress_packets 
    WHERE created_at < NOW() - INTERVAL '48 hours';
END;
$$;

-- -----------------------------------------------------------------------------
-- 2. IN-DATABASE ANALYTICAL VIEWS
-- All calculations, sums, averages, and group-bys are rendered directly by PostgreSQL.
-- -----------------------------------------------------------------------------

CREATE OR REPLACE VIEW v_live_dashboard_stats AS
SELECT
    (SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours') AS alerts_24h,
    (SELECT COUNT(*) FROM blocked_ips WHERE active = true) AS active_blocked_ips,
    (SELECT COUNT(*) FROM sessions WHERE last_seen_at >= NOW() - INTERVAL '15 minutes') AS active_sessions_count,
    (SELECT COUNT(*) FROM ingress_packets WHERE created_at >= NOW() - INTERVAL '5 minutes') AS packets_last_5min,
    COALESCE((SELECT ROUND(AVG(score)::numeric, 1) FROM ip_reputation WHERE score > 0), 10.0) AS avg_threat_score;

CREATE OR REPLACE VIEW v_top_attackers AS
SELECT 
    src_ip::text AS attacker_ip,
    COUNT(*) AS total_alerts,
    MAX(severity) AS peak_severity,
    MAX(created_at) AS latest_incident_time
FROM alerts
GROUP BY src_ip
ORDER BY total_alerts DESC
LIMIT 10;

CREATE OR REPLACE VIEW v_protocol_breakdown AS
SELECT 
    COALESCE(protocol, 'OTHER') AS protocol_name,
    COUNT(*) AS packet_count,
    ROUND((COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM ingress_packets), 0))::numeric, 2) AS percentage
FROM ingress_packets
GROUP BY protocol
ORDER BY packet_count DESC;

CREATE OR REPLACE VIEW v_active_blocked_ips AS
SELECT 
    id,
    ip::text,
    reason,
    created_at,
    expires_at,
    created_by
FROM blocked_ips
WHERE active = true
ORDER BY created_at DESC;
