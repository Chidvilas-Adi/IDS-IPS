BEGIN;

DO $$
DECLARE
    v_count BIGINT;
    v_bytes BIGINT;
    v_packet_id BIGINT;
BEGIN
    INSERT INTO dpi_signatures (
        tenant_id, name, protocol, pattern_type, pattern, severity, action, enabled
    ) VALUES (
        1, '__database_engine_test__', 'ANY', 'EXACT',
        '__database_engine_test_marker__', 'LOW', 'ALERT', true
    );

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, packet_length, payload_text
    ) VALUES (
        '192.0.2.254', '192.0.2.253', 40000, 8080, 'TCP', 48,
        '__database_engine_test_marker__'
    ) RETURNING id INTO v_packet_id;

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, packet_length, payload_text
    ) VALUES (
        '192.0.2.254', '192.0.2.253', 40000, 8080, 'TCP', 52,
        '__database_engine_test_marker__'
    );

    SELECT COUNT(*), SUM(bytes_sent)
    INTO v_count, v_bytes
    FROM sessions
    WHERE src_ip = '192.0.2.254'
      AND dst_ip = '192.0.2.253'
      AND src_port = 40000
      AND dst_port = 8080;

    IF v_count <> 1 OR v_bytes <> 100 THEN
        RAISE EXCEPTION 'Session upsert failed: rows %, bytes %', v_count, v_bytes;
    END IF;

    INSERT INTO ingress_packets (
        src_ip, dst_ip, protocol, packet_length, payload_text
    ) VALUES
        ('192.0.2.248', '192.0.2.247', 'ICMP', 40, ''),
        ('192.0.2.248', '192.0.2.247', 'ICMP', 44, '');

    SELECT COUNT(*), SUM(bytes_sent)
    INTO v_count, v_bytes
    FROM sessions
    WHERE src_ip = '192.0.2.248'
      AND dst_ip = '192.0.2.247'
      AND protocol = 'ICMP'
      AND src_port IS NULL
      AND dst_port IS NULL;

    IF v_count <> 1 OR v_bytes <> 84 THEN
        RAISE EXCEPTION 'Session upsert failed for packets without transport ports: rows %, bytes %', v_count, v_bytes;
    END IF;

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, packet_length
    ) VALUES (
        '192.0.2.246', '192.0.2.247', 40002, 443, 'TCP',
        'FIN,SYN,RST,PSH,ACK,URG', 60
    );

    IF NOT EXISTS (
        SELECT 1
        FROM ingress_packets
        WHERE src_ip = '192.0.2.246'
          AND tcp_flags = 'FIN,SYN,RST,PSH,ACK,URG'
    ) THEN
        RAISE EXCEPTION 'Session packet with combined TCP flags was not stored';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM alerts
        WHERE src_ip = '192.0.2.254'
          AND packet_summary->>'signature_name' = '__database_engine_test__'
          AND packet_summary->>'packet_id' = v_packet_id::text
    ) THEN
        RAISE EXCEPTION 'DPI trigger did not create its alert';
    END IF;

    INSERT INTO dpi_signatures (
        tenant_id, name, protocol, pattern_type, pattern, severity, action, enabled
    ) VALUES
        (1, '__database_regex_test__', 'HTTP', 'REGEX', '(?i)(union(\s+all)?\s+select)', 'LOW', 'ALERT', true),
        (1, '__database_hex_test__', 'ANY', 'HEX_BYTES', 'deadbeef', 'LOW', 'ALERT', true);

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, packet_length, payload_text, payload_bytes
    ) VALUES
        ('192.0.2.240', '192.0.2.253', 40001, 80, 'TCP', 80, 'UNION SELECT test', convert_to('UNION SELECT test', 'UTF8')),
        ('192.0.2.241', '192.0.2.253', 40002, 8080, 'TCP', 44, '', decode('deadbeef', 'hex'));

    IF NOT EXISTS (
        SELECT 1 FROM alerts
        WHERE src_ip = '192.0.2.240'
          AND packet_summary->>'signature_name' = '__database_regex_test__'
    ) OR NOT EXISTS (
        SELECT 1 FROM alerts
        WHERE src_ip = '192.0.2.241'
          AND packet_summary->>'signature_name' = '__database_hex_test__'
    ) THEN
        RAISE EXCEPTION 'Regex or binary DPI matching failed';
    END IF;

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, tcp_flags, packet_length
    )
    SELECT '192.0.2.252', '192.0.2.253', 41000, 22, 'TCP', 'SYN', 60
    FROM generate_series(1, 5);

    SELECT COUNT(*) INTO v_count
    FROM alerts
    WHERE src_ip = '192.0.2.252'
      AND rule_type = 'SQL_CORRELATION'
      AND packet_summary->>'rule_name' = 'SSH Brute Force Detection';

    IF v_count <> 1 OR NOT EXISTS (
        SELECT 1 FROM blocked_ips WHERE ip = '192.0.2.252' AND active
    ) THEN
        RAISE EXCEPTION 'SSH correlation/block action failed: alerts %', v_count;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM audit_log a
        JOIN blocked_ips b ON b.id = a.record_id
        WHERE a.action = 'BLOCK_IP'
          AND a.ip_address = '192.0.2.252'
          AND b.active = true
    ) THEN
        RAISE EXCEPTION 'SSH correlation block was not audited';
    END IF;

    INSERT INTO ingress_packets (
        src_ip, dst_ip, src_port, dst_port, protocol, packet_length
    )
    SELECT '198.51.100.251', '192.0.2.253', 42000, 10000 + port, 'TCP', 60
    FROM generate_series(1, 15) AS port;

    IF NOT EXISTS (
        SELECT 1 FROM alerts
        WHERE src_ip = '198.51.100.251'
          AND packet_summary->>'rule_name' = 'TCP Port Sweep Scan'
    ) OR NOT EXISTS (
        SELECT 1 FROM blocked_ips WHERE ip = '198.51.100.251' AND active
    ) THEN
        RAISE EXCEPTION 'Port sweep correlation/block action failed';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM audit_log a
        JOIN blocked_ips b ON b.id = a.record_id
        WHERE a.action = 'BLOCK_IP'
          AND a.ip_address = '198.51.100.251'
          AND b.active = true
    ) THEN
        RAISE EXCEPTION 'Port sweep block was not audited';
    END IF;

    CALL sp_block_ip('198.51.100.250', 1, 'Database engine test', 'verification');
    IF NOT EXISTS (
        SELECT 1 FROM blocked_ips b
        JOIN audit_log a ON a.record_id = b.id
        WHERE b.ip = '198.51.100.250' AND b.active
          AND a.action = 'BLOCK_IP' AND a.ip_address = b.ip
    ) THEN
        RAISE EXCEPTION 'sp_block_ip did not update database state';
    END IF;

    CALL sp_unblock_ip('198.51.100.250', 'verification');
    IF EXISTS (
        SELECT 1 FROM blocked_ips WHERE ip = '198.51.100.250' AND active
    ) THEN
        RAISE EXCEPTION 'sp_unblock_ip did not update database state';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_log
        WHERE action = 'UNBLOCK_IP' AND ip_address = '198.51.100.250'
    ) THEN
        RAISE EXCEPTION 'sp_unblock_ip did not record an audit event';
    END IF;

    INSERT INTO blocked_ips (tenant_id, ip, reason, expires_at, active)
    VALUES (1, '198.51.100.249', 'Database engine test', NOW() - INTERVAL '1 minute', true);
    CALL sp_purge_expired_records();
    IF EXISTS (
        SELECT 1 FROM blocked_ips WHERE ip = '198.51.100.249' AND active
    ) THEN
        RAISE EXCEPTION 'sp_purge_expired_records did not expire a block';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM audit_log
        WHERE action = 'EXPIRE_BLOCK' AND ip_address = '198.51.100.249'
    ) THEN
        RAISE EXCEPTION 'Expired block was not recorded in the audit log';
    END IF;

    PERFORM COUNT(*) FROM canary_aws_admin_vault;

    IF NOT EXISTS (
        SELECT 1 FROM alerts
        WHERE rule_type = 'INSIDER_CANARY_ACCESSED'
          AND packet_summary->>'canary_token' = 'AWS_ADMIN_VAULT_CANARY'
    ) THEN
        RAISE EXCEPTION 'Canary view did not create a correctly shaped alert';
    END IF;
END;
$$;

ROLLBACK;
