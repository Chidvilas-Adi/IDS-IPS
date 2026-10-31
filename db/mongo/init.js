// =============================================================
//  MongoDB Initialization Script – Database-Driven IDS/IPS
//  Runs once when the container starts for the first time.
//  Creates all collections with JSON Schema validators,
//  indexes, TTL indexes, and text indexes.
// =============================================================

// Switch to the idsips database (created automatically)
db = db.getSiblingDB("idsips");

// =============================================================
//  Helper: create a collection only if it doesn't exist
// =============================================================
function createCollection(name, options) {
    var existing = db.getCollectionNames();
    if (existing.indexOf(name) === -1) {
        db.createCollection(name, options);
        print("Created collection: " + name);
    } else {
        print("Collection already exists (skipped): " + name);
    }
}

// =============================================================
//  1. raw_packets
//     High-frequency write of dissected packet summaries.
// =============================================================
createCollection("raw_packets", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["timestamp", "src_ip", "dst_ip", "protocol"],
            properties: {
                timestamp:     { bsonType: "date",   description: "Capture timestamp (UTC)" },
                src_ip:        { bsonType: "string",  description: "Source IP address" },
                dst_ip:        { bsonType: "string",  description: "Destination IP address" },
                src_port:      { bsonType: ["int", "null"], minimum: 0, maximum: 65535 },
                dst_port:      { bsonType: ["int", "null"], minimum: 0, maximum: 65535 },
                protocol:      { bsonType: "string",  enum: ["TCP","UDP","ICMP","DNS","HTTP","HTTPS","TLS","ARP","OTHER"] },
                length:        { bsonType: ["int","null"],  minimum: 0 },
                ttl:           { bsonType: ["int","null"],  minimum: 0, maximum: 255 },
                flags:         { bsonType: ["string","null"] },
                payload_hex:   { bsonType: ["string","null"] },
                parsed_layers: { bsonType: ["object","null"] },
                tenant_id:     { bsonType: ["string","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  2. pcap_chunks  (GridFS metadata sidecar)
// =============================================================
createCollection("pcap_chunks", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["file_id", "captured_at"],
            properties: {
                file_id:      { bsonType: "objectId" },
                captured_at:  { bsonType: "date" },
                interface:    { bsonType: ["string","null"] },
                size_bytes:   { bsonType: ["int","null"] },
                packet_count: { bsonType: ["int","null"] },
                tenant_id:    { bsonType: ["string","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  3. geo_ip_cache
// =============================================================
createCollection("geo_ip_cache", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["ip", "cached_at"],
            properties: {
                ip:               { bsonType: "string" },
                country_code:     { bsonType: ["string","null"] },
                country_name:     { bsonType: ["string","null"] },
                city:             { bsonType: ["string","null"] },
                latitude:         { bsonType: ["double","null"] },
                longitude:        { bsonType: ["double","null"] },
                asn:              { bsonType: ["string","null"] },
                org:              { bsonType: ["string","null"] },
                reputation_score: { bsonType: ["double","null"], minimum: 0, maximum: 100 },
                cached_at:        { bsonType: "date" }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  4. threat_intel_raw
// =============================================================
createCollection("threat_intel_raw", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["source", "ingested_at"],
            properties: {
                source:      { bsonType: "string" },
                raw_data:    { bsonType: ["string","object","null"] },
                ingested_at: { bsonType: "date" },
                processed:   { bsonType: "bool" }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  5. fingerprint_db
// =============================================================
createCollection("fingerprint_db", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["ip"],
            properties: {
                ip:          { bsonType: "string" },
                os_guess:    { bsonType: ["string","null"] },
                ttl:         { bsonType: ["int","null"] },
                window_size: { bsonType: ["int","null"] },
                ja3_hash:    { bsonType: ["string","null"] },
                hassh_hash:  { bsonType: ["string","null"] },
                confidence:  { bsonType: ["double","null"], minimum: 0.0, maximum: 1.0 },
                last_seen:   { bsonType: ["date","null"] },
                history:     { bsonType: ["array","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  6. anomaly_vectors
// =============================================================
createCollection("anomaly_vectors", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["ip", "timestamp"],
            properties: {
                ip:            { bsonType: "string" },
                timestamp:     { bsonType: "date" },
                features:      { bsonType: ["object","null"] },
                anomaly_score: { bsonType: ["double","null"] },
                model_id:      { bsonType: ["string","null"] },
                flagged:       { bsonType: ["bool","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  7. session_graphs
// =============================================================
createCollection("session_graphs", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["tenant_id"],
            properties: {
                tenant_id: { bsonType: "string" },
                nodes: {
                    bsonType: ["array","null"],
                    items: {
                        bsonType: "object",
                        properties: {
                            ip:         { bsonType: "string" },
                            first_seen: { bsonType: "date" },
                            last_seen:  { bsonType: "date" },
                            role:       { bsonType: ["string","null"] }
                        }
                    }
                },
                edges: {
                    bsonType: ["array","null"],
                    items: {
                        bsonType: "object",
                        properties: {
                            src:       { bsonType: "string" },
                            dst:       { bsonType: "string" },
                            count:     { bsonType: ["int","null"] },
                            bytes:     { bsonType: ["long","int","null"] },
                            protocols: { bsonType: ["array","null"] }
                        }
                    }
                }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  8. dns_query_log
// =============================================================
createCollection("dns_query_log", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["timestamp", "src_ip", "query_name"],
            properties: {
                timestamp:      { bsonType: "date" },
                src_ip:         { bsonType: "string" },
                query_name:     { bsonType: "string" },
                query_type:     { bsonType: ["string","null"] },
                response_code:  { bsonType: ["string","null"] },
                response_ips:   { bsonType: ["array","null"] },
                classification: { bsonType: ["string","null"] },
                tenant_id:      { bsonType: ["string","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  9. http_transaction_log
// =============================================================
createCollection("http_transaction_log", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["timestamp", "src_ip"],
            properties: {
                timestamp:     { bsonType: "date" },
                src_ip:        { bsonType: "string" },
                dst_ip:        { bsonType: ["string","null"] },
                method:        { bsonType: ["string","null"] },
                uri:           { bsonType: ["string","null"] },
                host:          { bsonType: ["string","null"] },
                headers:       { bsonType: ["object","null"] },
                body_preview:  { bsonType: ["string","null"] },
                response_code: { bsonType: ["int","null"] },
                content_type:  { bsonType: ["string","null"] },
                dpi_matches:   { bsonType: ["array","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  10. tls_handshake_log
// =============================================================
createCollection("tls_handshake_log", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["timestamp", "src_ip"],
            properties: {
                timestamp:       { bsonType: "date" },
                src_ip:          { bsonType: "string" },
                dst_ip:          { bsonType: ["string","null"] },
                dst_port:        { bsonType: ["int","null"] },
                tls_version:     { bsonType: ["string","null"] },
                cipher_suite:    { bsonType: ["string","null"] },
                ja3:             { bsonType: ["string","null"] },
                ja3s:            { bsonType: ["string","null"] },
                sni:             { bsonType: ["string","null"] },
                cert_fingerprint:{ bsonType: ["string","null"] },
                cert_subject:    { bsonType: ["string","null"] },
                alert_fired:     { bsonType: ["bool","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  11. canary_access_log
// =============================================================
createCollection("canary_access_log", {
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["token_name", "accessed_at"],
            properties: {
                token_name:    { bsonType: "string" },
                accessor_ip:   { bsonType: ["string","null"] },
                accessor_user: { bsonType: ["string","null"] },
                accessed_at:   { bsonType: "date" },
                metadata:      { bsonType: ["object","null"] }
            }
        }
    },
    validationAction: "warn"
});

// =============================================================
//  INDEXES
// =============================================================
print("\n--- Creating indexes ---");

// raw_packets
db.raw_packets.createIndex({ timestamp: 1 }, { name: "idx_raw_packets_timestamp" });
db.raw_packets.createIndex({ src_ip: 1 },    { name: "idx_raw_packets_src_ip" });
db.raw_packets.createIndex({ dst_ip: 1 },    { name: "idx_raw_packets_dst_ip" });
db.raw_packets.createIndex({ tenant_id: 1 }, { name: "idx_raw_packets_tenant" });
db.raw_packets.createIndex({ src_ip: 1, dst_ip: 1, timestamp: -1 }, { name: "idx_raw_packets_flow" });
// TTL: expire after 7 days
db.raw_packets.createIndex(
    { timestamp: 1 },
    { name: "ttl_raw_packets_7d", expireAfterSeconds: 604800 }
);

// pcap_chunks
db.pcap_chunks.createIndex({ captured_at: 1 }, { name: "idx_pcap_captured_at" });
db.pcap_chunks.createIndex({ tenant_id: 1 },   { name: "idx_pcap_tenant" });

// geo_ip_cache
db.geo_ip_cache.createIndex({ ip: 1 }, { unique: true, name: "idx_geo_ip_unique" });
db.geo_ip_cache.createIndex({ cached_at: 1 }, { name: "idx_geo_cached_at" });

// threat_intel_raw
db.threat_intel_raw.createIndex({ ingested_at: 1 }, { name: "idx_threat_ingested_at" });
db.threat_intel_raw.createIndex({ processed: 1 },   { name: "idx_threat_processed" });
db.threat_intel_raw.createIndex({ source: 1 },      { name: "idx_threat_source" });
// Full-text index on raw_data (string fields)
db.threat_intel_raw.createIndex(
    { raw_data: "text" },
    { name: "text_idx_threat_raw_data", default_language: "none" }
);

// fingerprint_db
db.fingerprint_db.createIndex({ ip: 1 },        { unique: true, name: "idx_fp_ip_unique" });
db.fingerprint_db.createIndex({ last_seen: -1 }, { name: "idx_fp_last_seen" });
db.fingerprint_db.createIndex({ ja3_hash: 1 },   { name: "idx_fp_ja3" });
db.fingerprint_db.createIndex({ hassh_hash: 1 }, { name: "idx_fp_hassh" });

// anomaly_vectors
db.anomaly_vectors.createIndex({ ip: 1 },         { name: "idx_av_ip" });
db.anomaly_vectors.createIndex({ timestamp: 1 },   { name: "idx_av_timestamp" });
db.anomaly_vectors.createIndex({ flagged: 1 },     { name: "idx_av_flagged" });
db.anomaly_vectors.createIndex({ model_id: 1 },    { name: "idx_av_model" });
// TTL: expire after 30 days
db.anomaly_vectors.createIndex(
    { timestamp: 1 },
    { name: "ttl_anomaly_vectors_30d", expireAfterSeconds: 2592000 }
);

// session_graphs
db.session_graphs.createIndex({ tenant_id: 1 }, { name: "idx_sg_tenant" });

// dns_query_log
db.dns_query_log.createIndex({ timestamp: 1 },  { name: "idx_dns_timestamp" });
db.dns_query_log.createIndex({ src_ip: 1 },     { name: "idx_dns_src_ip" });
db.dns_query_log.createIndex({ query_name: 1 }, { name: "idx_dns_query_name" });
db.dns_query_log.createIndex({ tenant_id: 1 },  { name: "idx_dns_tenant" });
// TTL: expire after 14 days
db.dns_query_log.createIndex(
    { timestamp: 1 },
    { name: "ttl_dns_query_log_14d", expireAfterSeconds: 1209600 }
);

// http_transaction_log
db.http_transaction_log.createIndex({ timestamp: 1 }, { name: "idx_http_timestamp" });
db.http_transaction_log.createIndex({ src_ip: 1 },    { name: "idx_http_src_ip" });
db.http_transaction_log.createIndex({ host: 1 },      { name: "idx_http_host" });
db.http_transaction_log.createIndex({ method: 1 },    { name: "idx_http_method" });

// tls_handshake_log
db.tls_handshake_log.createIndex({ timestamp: 1 },   { name: "idx_tls_timestamp" });
db.tls_handshake_log.createIndex({ src_ip: 1 },      { name: "idx_tls_src_ip" });
db.tls_handshake_log.createIndex({ ja3: 1 },         { name: "idx_tls_ja3" });
db.tls_handshake_log.createIndex({ sni: 1 },         { name: "idx_tls_sni" });
db.tls_handshake_log.createIndex({ alert_fired: 1 }, { name: "idx_tls_alert_fired" });

// canary_access_log
db.canary_access_log.createIndex({ accessed_at: 1 },  { name: "idx_canary_accessed_at" });
db.canary_access_log.createIndex({ token_name: 1 },   { name: "idx_canary_token_name" });
db.canary_access_log.createIndex({ accessor_ip: 1 },  { name: "idx_canary_accessor_ip" });

print("\n--- MongoDB initialization complete ---");
print("Collections: " + db.getCollectionNames().join(", "));
