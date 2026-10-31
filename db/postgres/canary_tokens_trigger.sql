-- =============================================================================
-- CANARY DECEPTION TOKENS (Pure In-Database Insider Threat Detection)
-- Any SELECT query on canary views automatically executes a PL/pgSQL function
-- that writes a CRITICAL alert to the alerts table and emits pg_notify.
-- =============================================================================

CREATE OR REPLACE FUNCTION fn_trigger_canary_access(
    p_token_name TEXT,
    p_token_desc TEXT
)
RETURNS TABLE (id int, credential_key text, secret_token text, privilege_level text) AS $$
DECLARE
    v_alert_id BIGINT;
    v_client_ip INET;
BEGIN
    v_client_ip := COALESCE(inet_client_addr(), '127.0.0.1'::inet);

    -- 1. Update access count and timestamp in canary_tokens table
    UPDATE canary_tokens 
    SET last_accessed = NOW(),
        access_count = access_count + 1
    WHERE token_name = p_token_name;

    -- 2. Insert CRITICAL alert generated purely by the database query
    INSERT INTO alerts (
        tenant_id, rule_type, severity, 
        src_ip, dst_ip, src_port, dst_port, protocol, 
        packet_summary, status, created_at
    ) VALUES (
        1, NULL, 'INSIDER_CANARY_ACCESSED', 'CRITICAL',
        v_client_ip, '127.0.0.1'::inet, 5432, 5432, 'POSTGRES',
        json_build_object(
            'canary_token', p_token_name,
            'description', p_token_desc,
            'db_user', current_user,
            'session_user', session_user,
            'client_ip', v_client_ip::text,
            'detection_method', 'PL/pgSQL Security Definer Function on SELECT'
        ),
        'open', NOW()
    ) RETURNING alerts.id INTO v_alert_id;

    -- 3. Emit PostgreSQL notification event for instant firewall/admin notification
    PERFORM pg_notify('db_firewall_action', json_build_object(
        'action', 'ALERT',
        'severity', 'CRITICAL',
        'ip', v_client_ip::text,
        'reason', 'Canary Honey-Token Accessed: ' || p_token_name,
        'alert_id', v_alert_id
    )::text);

    -- 4. Return decoy canary rows to prevent attacker suspicion
    RETURN QUERY 
    SELECT 
        101,
        'AWS_SECRET_CANARY_HONEYPOT_KEY'::text,
        'AKIA_FAKE_CANARY_HONEYPOT_STRING_0099'::text,
        'GLOBAL_ADMIN'::text;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- View 1: Disguised as high-privilege AWS credentials
CREATE OR REPLACE VIEW canary_aws_admin_vault AS 
SELECT * FROM fn_trigger_canary_access('AWS_ADMIN_VAULT_CANARY', 'Planted AWS production credentials honey-token');

-- View 2: Disguised as database root passwords
CREATE OR REPLACE VIEW canary_root_credentials AS 
SELECT * FROM fn_trigger_canary_access('DB_ROOT_PW_CANARY', 'Planted root DB password table honey-token');
