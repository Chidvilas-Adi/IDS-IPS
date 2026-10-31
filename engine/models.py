"""
models.py — SQLAlchemy 2.0 ORM models for the DB-Driven IDS/IPS system.

Every table defined in the schema is represented here with full columns,
indexes, relationships, and helper functions for PostgreSQL, Redis, and
MongoDB connectivity.
"""

import os
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Index,
    Integer, Interval, LargeBinary, String, Text, UniqueConstraint,
    create_engine, text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker
from sqlalchemy.pool import QueuePool

import redis as redis_lib
from pymongo import MongoClient

# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)

# ---------------------------------------------------------------------------
# Database connection setup
# ---------------------------------------------------------------------------

_PG_URL = _env(
    "POSTGRES_URL",
    "postgresql+psycopg2://ids:ids@localhost:5432/ids_ips",
)

_engine = create_engine(
    _PG_URL,
    poolclass=QueuePool,
    pool_size=int(_env("PG_POOL_SIZE", "10")),
    max_overflow=int(_env("PG_MAX_OVERFLOW", "20")),
    pool_pre_ping=True,
    pool_recycle=int(_env("PG_POOL_RECYCLE", "3600")),
    echo=_env("SQLALCHEMY_ECHO", "false").lower() == "true",
)

_SessionFactory = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def get_db_session() -> Session:
    """Return a new SQLAlchemy Session from the connection pool."""
    return _SessionFactory()


# ---------------------------------------------------------------------------
# Redis connection helper
# ---------------------------------------------------------------------------

_redis_client: Optional[redis_lib.Redis] = None


def get_redis() -> redis_lib.Redis:
    """Return a singleton Redis client (thread-safe)."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_lib.Redis.from_url(
            _env("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
    return _redis_client


# ---------------------------------------------------------------------------
# MongoDB connection helper
# ---------------------------------------------------------------------------

_mongo_client: Optional[MongoClient] = None


def get_mongo() -> MongoClient:
    """Return a singleton MongoClient."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(
            _env("MONGO_URL", "mongodb://localhost:27017"),
            serverSelectionTimeoutMS=5000,
        )
    return _mongo_client


def get_mongo_db():
    """Return the IDS/IPS MongoDB database."""
    return get_mongo()[_env("MONGO_DB", "ids_ips")]


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = Column(String(255), nullable=False, unique=True)
    config = Column(JSONB, server_default=text("'{}'"))
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    engine_configs = relationship("EngineConfig", back_populates="tenant", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    username = Column(String(128), nullable=False, unique=True)
    email = Column(String(255), nullable=False, unique=True)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(64), nullable=False, server_default=text("'analyst'"))
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    last_login_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    tenant = relationship("Tenant", back_populates="users")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_users_tenant_id", "tenant_id"),
        Index("ix_users_email", "email"),
    )


# ---------------------------------------------------------------------------
# ApiKey
# ---------------------------------------------------------------------------

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash = Column(String(512), nullable=False, unique=True)
    name = Column(String(128), nullable=False)
    scopes = Column(ARRAY(Text), server_default=text("'{}'"))
    expires_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_used_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))

    user = relationship("User", back_populates="api_keys")


# ---------------------------------------------------------------------------
# EngineConfig
# ---------------------------------------------------------------------------

class EngineConfig(Base):
    __tablename__ = "engine_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    component = Column(String(128), nullable=False)
    config_key = Column(String(255), nullable=False)
    config_value = Column(JSONB, nullable=False)
    description = Column(Text)
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    tenant = relationship("Tenant", back_populates="engine_configs")

    __table_args__ = (
        UniqueConstraint("tenant_id", "component", "config_key", name="uq_engine_config"),
        Index("ix_engine_configs_tenant_component", "tenant_id", "component"),
    )


# ---------------------------------------------------------------------------
# Rules (detection rules)
# ---------------------------------------------------------------------------

class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(32), nullable=False, server_default=text("'medium'"))
    rule_type = Column(String(64), nullable=False)  # SIGNATURE, THRESHOLD, ANOMALY, etc.
    protocol = Column(String(32))
    src_ip_range = Column(INET)
    dst_ip_range = Column(INET)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    direction = Column(String(16), server_default=text("'any'"))
    action = Column(String(64), nullable=False, server_default=text("'alert'"))
    conditions = Column(JSONB, server_default=text("'{}'"))
    tags = Column(ARRAY(Text), server_default=text("'{}'"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    false_positive_rate = Column(Float, server_default=text("0.0"))
    priority = Column(Integer, server_default=text("100"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_rules_tenant_enabled", "tenant_id", "is_enabled"),
        Index("ix_rules_type", "rule_type"),
        Index("ix_rules_protocol", "protocol"),
    )


# ---------------------------------------------------------------------------
# CorrelationRule
# ---------------------------------------------------------------------------

class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_type = Column(String(64), nullable=False)  # THRESHOLD, SEQUENCE, RATIO, GEO_FENCE, IOC_MATCH, etc.
    severity = Column(String(32), nullable=False, server_default=text("'medium'"))
    event_filter = Column(JSONB, server_default=text("'{}'"))
    window_seconds = Column(Integer, server_default=text("300"))
    threshold_count = Column(Integer)
    threshold_ratio = Column(Float)
    sequence_events = Column(JSONB)  # ordered list of event patterns
    geo_config = Column(JSONB)
    behavioral_config = Column(JSONB)
    action = Column(String(64), nullable=False, server_default=text("'alert'"))
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="SET NULL"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    priority = Column(Integer, server_default=text("100"))
    suppress_seconds = Column(Integer, server_default=text("60"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    playbook = relationship("Playbook", foreign_keys=[playbook_id])

    __table_args__ = (
        Index("ix_correlation_rules_tenant_enabled", "tenant_id", "is_enabled"),
        Index("ix_correlation_rules_type", "rule_type"),
    )


# ---------------------------------------------------------------------------
# DpiSignature
# ---------------------------------------------------------------------------

class DpiSignature(Base):
    __tablename__ = "dpi_signatures"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    protocol = Column(String(32))  # HTTP, DNS, TLS, ARP, ANY
    match_type = Column(String(32), nullable=False)  # REGEX, HEX, KEYWORD, YARA
    pattern = Column(Text, nullable=False)
    pattern_flags = Column(String(64))
    match_field = Column(String(64))  # payload, uri, header, body, query_name
    severity = Column(String(32), nullable=False, server_default=text("'medium'"))
    action = Column(String(64), nullable=False, server_default=text("'alert'"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    cvss_score = Column(Float)
    cve_refs = Column(ARRAY(Text))
    tags = Column(ARRAY(Text))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_dpi_signatures_tenant_enabled", "tenant_id", "is_enabled"),
        Index("ix_dpi_signatures_protocol", "protocol"),
    )


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session(Base):
    __tablename__ = "sessions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(16), nullable=False)
    state = Column(String(32), server_default=text("'NEW'"))
    bytes_in = Column(BigInteger, server_default=text("0"))
    bytes_out = Column(BigInteger, server_default=text("0"))
    packets_in = Column(BigInteger, server_default=text("0"))
    packets_out = Column(BigInteger, server_default=text("0"))
    first_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    duration_ms = Column(BigInteger)
    tcp_flags = Column(String(32))
    application = Column(String(64))
    country_src = Column(String(8))
    country_dst = Column(String(8))
    asn_src = Column(Integer)
    asn_dst = Column(Integer)
    risk_score = Column(Float, server_default=text("0.0"))
    metadata = Column(JSONB, server_default=text("'{}'"))

    fingerprints = relationship("SessionFingerprint", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "first_seen",
                         name="uq_session_5tuple"),
        Index("ix_sessions_src_ip", "src_ip"),
        Index("ix_sessions_dst_ip", "dst_ip"),
        Index("ix_sessions_last_seen", "last_seen"),
        Index("ix_sessions_tenant", "tenant_id"),
    )


# ---------------------------------------------------------------------------
# SessionFingerprint
# ---------------------------------------------------------------------------

class SessionFingerprint(Base):
    __tablename__ = "session_fingerprints"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id = Column(BigInteger, ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    fingerprint_type = Column(String(32), nullable=False)  # JA3, HASSH, HTTP2, QUIC
    fingerprint_hash = Column(String(128), nullable=False)
    raw_value = Column(Text)
    matched_tool = Column(String(128))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    session = relationship("Session", back_populates="fingerprints")

    __table_args__ = (
        Index("ix_session_fingerprints_hash", "fingerprint_hash"),
        Index("ix_session_fingerprints_type", "fingerprint_type"),
    )


# ---------------------------------------------------------------------------
# FlowRecord (TimescaleDB hypertable candidate)
# ---------------------------------------------------------------------------

class FlowRecord(Base):
    __tablename__ = "flow_records"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, server_default=text("NOW()"))
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(16), nullable=False)
    packets = Column(BigInteger, server_default=text("0"))
    bytes = Column(BigInteger, server_default=text("0"))
    duration_ms = Column(BigInteger)
    tcp_flags = Column(String(32))
    application = Column(String(64))
    direction = Column(String(16))

    __table_args__ = (
        Index("ix_flow_records_ts", "ts"),
        Index("ix_flow_records_src_ip_ts", "src_ip", "ts"),
        Index("ix_flow_records_tenant_ts", "tenant_id", "ts"),
    )


# ---------------------------------------------------------------------------
# ConnectionGraphEdge
# ---------------------------------------------------------------------------

class ConnectionGraphEdge(Base):
    __tablename__ = "connection_graph_edges"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET, nullable=False)
    first_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    connection_count = Column(BigInteger, server_default=text("1"))
    protocols = Column(ARRAY(Text))
    dst_ports = Column(ARRAY(Integer))

    __table_args__ = (
        UniqueConstraint("tenant_id", "src_ip", "dst_ip", name="uq_conn_graph_edge"),
        Index("ix_conn_graph_src_ip", "src_ip"),
        Index("ix_conn_graph_dst_ip", "dst_ip"),
        Index("ix_conn_graph_last_seen", "last_seen"),
    )


# ---------------------------------------------------------------------------
# ThreatFeed
# ---------------------------------------------------------------------------

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    feed_type = Column(String(64), nullable=False)  # ABUSEIPDB, OTX, FEODO, EMERGING_THREATS, CSV, JSON
    url = Column(Text)
    api_key_encrypted = Column(LargeBinary)
    config = Column(JSONB, server_default=text("'{}'"))
    poll_interval_minutes = Column(Integer, server_default=text("60"))
    last_polled_at = Column(DateTime)
    ioc_count = Column(BigInteger, server_default=text("0"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)


# ---------------------------------------------------------------------------
# IOC tables
# ---------------------------------------------------------------------------

class IocIPv4(Base):
    __tablename__ = "ioc_ipv4"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    ip = Column(INET, nullable=False)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    tags = Column(ARRAY(Text))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    expires_at = Column(DateTime)
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")

    __table_args__ = (
        Index("ix_ioc_ipv4_ip", "ip"),
        Index("ix_ioc_ipv4_feed_ip", "feed_id", "ip", unique=True),
        Index("ix_ioc_ipv4_expires_at", "expires_at"),
    )


class IocIPv6(Base):
    __tablename__ = "ioc_ipv6"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    ip = Column(INET, nullable=False)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    tags = Column(ARRAY(Text))
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    expires_at = Column(DateTime)
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")

    __table_args__ = (
        Index("ix_ioc_ipv6_ip", "ip"),
        Index("ix_ioc_ipv6_feed_ip", "feed_id", "ip", unique=True),
    )


class IocDomain(Base):
    __tablename__ = "ioc_domains"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    domain = Column(Text, nullable=False)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    tags = Column(ARRAY(Text))
    expires_at = Column(DateTime)
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")

    __table_args__ = (
        Index("ix_ioc_domains_domain", "domain"),
        Index("ix_ioc_domains_feed_domain", "feed_id", "domain", unique=True),
    )


class IocUrl(Base):
    __tablename__ = "ioc_urls"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    tags = Column(ARRAY(Text))
    expires_at = Column(DateTime)
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")

    __table_args__ = (Index("ix_ioc_urls_url_hash", text("md5(url)")),)


class IocHash(Base):
    __tablename__ = "ioc_hashes"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    hash_type = Column(String(16), nullable=False)  # MD5, SHA1, SHA256
    hash_value = Column(String(128), nullable=False)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    file_name = Column(String(512))
    tags = Column(ARRAY(Text))
    expires_at = Column(DateTime)
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")

    __table_args__ = (
        Index("ix_ioc_hashes_value", "hash_value"),
        UniqueConstraint("feed_id", "hash_type", "hash_value", name="uq_ioc_hash"),
    )


class IocCertificate(Base):
    __tablename__ = "ioc_certificates"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    fingerprint_sha256 = Column(String(128), nullable=False, unique=True)
    subject_cn = Column(Text)
    issuer_cn = Column(Text)
    serial_number = Column(String(128))
    not_before = Column(DateTime)
    not_after = Column(DateTime)
    confidence = Column(Float, server_default=text("50.0"))
    threat_type = Column(String(128))
    raw_data = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    feed = relationship("ThreatFeed")


# ---------------------------------------------------------------------------
# GeoRule
# ---------------------------------------------------------------------------

class GeoRule(Base):
    __tablename__ = "geo_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    country_codes = Column(ARRAY(Text), nullable=False)
    direction = Column(String(16), server_default=text("'src'"))
    action = Column(String(64), nullable=False, server_default=text("'alert'"))
    severity = Column(String(32), server_default=text("'medium'"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    __table_args__ = (Index("ix_geo_rules_tenant_enabled", "tenant_id", "is_enabled"),)


# ---------------------------------------------------------------------------
# IpReputation
# ---------------------------------------------------------------------------

class IpReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ip = Column(INET, nullable=False)
    score = Column(Float, nullable=False, server_default=text("0.0"))
    ioc_score = Column(Float, server_default=text("0.0"))
    alert_score = Column(Float, server_default=text("0.0"))
    geo_score = Column(Float, server_default=text("0.0"))
    anomaly_score = Column(Float, server_default=text("0.0"))
    total_alerts = Column(Integer, server_default=text("0"))
    first_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_seen = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_decay_at = Column(DateTime)
    country = Column(String(8))
    asn = Column(Integer)
    org = Column(String(255))
    tags = Column(ARRAY(Text))
    metadata = Column(JSONB, server_default=text("'{}'"))

    __table_args__ = (
        UniqueConstraint("tenant_id", "ip", name="uq_ip_reputation"),
        Index("ix_ip_reputation_ip", "ip"),
        Index("ix_ip_reputation_score", "score"),
    )


# ---------------------------------------------------------------------------
# UserBehaviorProfile
# ---------------------------------------------------------------------------

class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String(32), nullable=False)  # IP, USER, HOST
    entity_id = Column(String(255), nullable=False)
    feature_name = Column(String(128), nullable=False)
    mean = Column(Float, nullable=False, server_default=text("0.0"))
    std_dev = Column(Float, nullable=False, server_default=text("1.0"))
    min_val = Column(Float)
    max_val = Column(Float)
    sample_count = Column(BigInteger, server_default=text("0"))
    window_hours = Column(Integer, server_default=text("24"))
    last_updated = Column(DateTime, nullable=False, server_default=text("NOW()"))

    __table_args__ = (
        UniqueConstraint("tenant_id", "entity_type", "entity_id", "feature_name", name="uq_behavior_profile"),
        Index("ix_ubp_entity", "entity_type", "entity_id"),
    )


# ---------------------------------------------------------------------------
# AnomalyModel
# ---------------------------------------------------------------------------

class AnomalyModel(Base):
    __tablename__ = "anomaly_models"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    model_type = Column(String(64), nullable=False)  # ISOLATION_FOREST, Z_SCORE, LOF, AUTOENCODER
    version = Column(Integer, server_default=text("1"))
    parameters = Column(JSONB, nullable=False, server_default=text("'{}'"))
    feature_names = Column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    threshold = Column(Float, server_default=text("0.5"))
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    trained_at = Column(DateTime)
    training_samples = Column(BigInteger, server_default=text("0"))
    accuracy_metrics = Column(JSONB)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    __table_args__ = (Index("ix_anomaly_models_tenant_active", "tenant_id", "is_active"),)


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_id = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"))
    correlation_rule_id = Column(Integer, ForeignKey("correlation_rules.id", ondelete="SET NULL"))
    dpi_signature_id = Column(Integer, ForeignKey("dpi_signatures.id", ondelete="SET NULL"))
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, server_default=text("'open'"))
    src_ip = Column(INET)
    dst_ip = Column(INET)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(16))
    alert_ts = Column(DateTime, nullable=False, server_default=text("NOW()"))
    closed_at = Column(DateTime)
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    incident_id = Column(BigInteger, ForeignKey("incidents.id", ondelete="SET NULL"))
    enrichments = Column(JSONB, server_default=text("'{}'"))
    raw_event = Column(JSONB)
    pcap_ref = Column(Text)  # GridFS object id
    tags = Column(ARRAY(Text))
    false_positive = Column(Boolean, server_default=text("false"))

    rule = relationship("Rule")
    correlation_rule = relationship("CorrelationRule")
    dpi_signature = relationship("DpiSignature")
    incident = relationship("Incident", back_populates="alerts")
    feedback = relationship("FalsePositiveFeedback", back_populates="alert", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_alerts_tenant_status", "tenant_id", "status"),
        Index("ix_alerts_src_ip", "src_ip"),
        Index("ix_alerts_alert_ts", "alert_ts"),
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_incident_id", "incident_id"),
    )


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, server_default=text("'open'"))
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)
    closed_at = Column(DateTime)
    tags = Column(ARRAY(Text))
    metadata = Column(JSONB, server_default=text("'{}'"))

    alerts = relationship("Alert", back_populates="incident")
    timeline = relationship("IncidentTimeline", back_populates="incident", cascade="all, delete-orphan",
                            order_by="IncidentTimeline.ts")

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# IncidentTimeline
# ---------------------------------------------------------------------------

class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    incident_id = Column(BigInteger, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)
    ts = Column(DateTime, nullable=False, server_default=text("NOW()"))
    event_type = Column(String(64), nullable=False)
    actor = Column(String(255))  # user email or system component
    description = Column(Text)
    metadata = Column(JSONB)

    incident = relationship("Incident", back_populates="timeline")

    __table_args__ = (Index("ix_incident_timeline_incident_ts", "incident_id", "ts"),)


# ---------------------------------------------------------------------------
# FalsePositiveFeedback
# ---------------------------------------------------------------------------

class FalsePositiveFeedback(Base):
    __tablename__ = "false_positive_feedback"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    submitted_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    is_false_positive = Column(Boolean, nullable=False)
    reason = Column(Text)
    submitted_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    processed = Column(Boolean, server_default=text("false"))

    alert = relationship("Alert", back_populates="feedback")

    __table_args__ = (Index("ix_fp_feedback_alert_id", "alert_id"),)


# ---------------------------------------------------------------------------
# ActionTemplate
# ---------------------------------------------------------------------------

class ActionTemplate(Base):
    __tablename__ = "action_templates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    action_type = Column(String(64), nullable=False)
    parameters = Column(JSONB, nullable=False, server_default=text("'{}'"))
    description = Column(Text)
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------

class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    trigger_severity = Column(ARRAY(Text))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    steps = relationship("PlaybookStep", back_populates="playbook",
                         order_by="PlaybookStep.step_order", cascade="all, delete-orphan")
    executions = relationship("PlaybookExecution", back_populates="playbook", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_playbooks_tenant_enabled", "tenant_id", "is_enabled"),)


# ---------------------------------------------------------------------------
# PlaybookStep
# ---------------------------------------------------------------------------

class PlaybookStep(Base):
    __tablename__ = "playbook_steps"

    id = Column(Integer, primary_key=True, autoincrement=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    step_order = Column(Integer, nullable=False)
    action_type = Column(String(64), nullable=False)
    parameters = Column(JSONB, nullable=False, server_default=text("'{}'"))
    on_failure = Column(String(32), server_default=text("'CONTINUE'"))  # CONTINUE, ABORT, RETRY
    retry_count = Column(Integer, server_default=text("0"))
    description = Column(Text)

    playbook = relationship("Playbook", back_populates="steps")


# ---------------------------------------------------------------------------
# PlaybookExecution
# ---------------------------------------------------------------------------

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="SET NULL"))
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    started_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    finished_at = Column(DateTime)
    status = Column(String(32), nullable=False, server_default=text("'RUNNING'"))  # RUNNING, SUCCESS, FAILED, PARTIAL
    step_results = Column(JSONB, server_default=text("'[]'"))
    error_message = Column(Text)
    triggered_by = Column(String(128))

    playbook = relationship("Playbook", back_populates="executions")

    __table_args__ = (
        Index("ix_pb_executions_playbook_id", "playbook_id"),
        Index("ix_pb_executions_alert_id", "alert_id"),
        Index("ix_pb_executions_started_at", "started_at"),
    )


# ---------------------------------------------------------------------------
# BlockedIp
# ---------------------------------------------------------------------------

class BlockedIp(Base):
    __tablename__ = "blocked_ips"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ip = Column(INET, nullable=False)
    reason = Column(Text)
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"))
    playbook_execution_id = Column(BigInteger, ForeignKey("playbook_executions.id", ondelete="SET NULL"))
    blocked_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    block_method = Column(String(64))  # IPTABLES, NETSH, ACL
    metadata = Column(JSONB)

    __table_args__ = (
        UniqueConstraint("tenant_id", "ip", name="uq_blocked_ip"),
        Index("ix_blocked_ips_ip", "ip"),
        Index("ix_blocked_ips_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# ThrottledFlow
# ---------------------------------------------------------------------------

class ThrottledFlow(Base):
    __tablename__ = "throttled_flows"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    src_ip = Column(INET, nullable=False)
    dst_ip = Column(INET)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String(16))
    rate_kbps = Column(Integer)
    burst_kb = Column(Integer)
    throttled_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    tc_handle = Column(String(64))

    __table_args__ = (Index("ix_throttled_flows_src_ip", "src_ip"),)


# ---------------------------------------------------------------------------
# HoneypotRedirect
# ---------------------------------------------------------------------------

class HoneypotRedirect(Base):
    __tablename__ = "honeypot_redirects"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    src_ip = Column(INET, nullable=False)
    honeypot_ip = Column(INET, nullable=False)
    honeypot_port = Column(Integer)
    original_dst_port = Column(Integer)
    redirected_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"))

    __table_args__ = (Index("ix_honeypot_redirects_src_ip", "src_ip"),)


# ---------------------------------------------------------------------------
# HoneypotConfig
# ---------------------------------------------------------------------------

class HoneypotConfig(Base):
    __tablename__ = "honeypot_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    honeypot_ip = Column(INET, nullable=False)
    listen_ports = Column(ARRAY(Integer))
    service_type = Column(String(64))  # SSH, HTTP, FTP, TELNET
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    config = Column(JSONB, server_default=text("'{}'"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))


# ---------------------------------------------------------------------------
# SinkholeDomain
# ---------------------------------------------------------------------------

class SinkholeDomain(Base):
    __tablename__ = "sinkhole_domains"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    domain = Column(Text, nullable=False)
    sinkhole_ip = Column(INET)
    reason = Column(Text)
    alert_id = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    expires_at = Column(DateTime)
    is_active = Column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (
        Index("ix_sinkhole_domains_domain", "domain"),
        UniqueConstraint("tenant_id", "domain", name="uq_sinkhole_domain"),
    )


# ---------------------------------------------------------------------------
# CanaryToken
# ---------------------------------------------------------------------------

class CanaryToken(Base):
    __tablename__ = "canary_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(256), nullable=False, unique=True)
    token_type = Column(String(64), nullable=False)  # FILE, URL, DNS, DB_RECORD
    description = Column(Text)
    metadata = Column(JSONB)
    deployed_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    last_triggered_at = Column(DateTime)
    trigger_count = Column(Integer, server_default=text("0"))
    is_active = Column(Boolean, nullable=False, server_default=text("true"))
    alert_on_access = Column(Boolean, nullable=False, server_default=text("true"))

    __table_args__ = (Index("ix_canary_tokens_tenant_active", "tenant_id", "is_active"),)


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    ts = Column(DateTime, nullable=False, server_default=text("NOW()"))
    actor = Column(String(255))
    action = Column(String(128), nullable=False)
    resource_type = Column(String(128))
    resource_id = Column(String(255))
    outcome = Column(String(32), server_default=text("'SUCCESS'"))
    ip_address = Column(INET)
    details = Column(JSONB)

    __table_args__ = (
        Index("ix_audit_log_tenant_ts", "tenant_id", "ts"),
        Index("ix_audit_log_actor", "actor"),
        Index("ix_audit_log_action", "action"),
    )


# ---------------------------------------------------------------------------
# ComplianceCheck
# ---------------------------------------------------------------------------

class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    framework = Column(String(64), nullable=False)  # PCI-DSS, HIPAA, SOC2, ISO27001
    control_id = Column(String(64), nullable=False)
    control_name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(32), nullable=False, server_default=text("'PENDING'"))
    last_checked_at = Column(DateTime)
    evidence = Column(JSONB)
    remediation = Column(Text)

    __table_args__ = (
        UniqueConstraint("tenant_id", "framework", "control_id", name="uq_compliance_check"),
        Index("ix_compliance_checks_tenant_framework", "tenant_id", "framework"),
    )


# ---------------------------------------------------------------------------
# DataRetentionPolicy
# ---------------------------------------------------------------------------

class DataRetentionPolicy(Base):
    __tablename__ = "data_retention_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    table_name = Column(String(128), nullable=False)
    cleanup_column = Column(String(128), nullable=False, server_default=text("'created_at'"))
    retention_days = Column(Integer, nullable=False)
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    last_run_at = Column(DateTime)
    rows_deleted_last_run = Column(BigInteger, server_default=text("0"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))

    __table_args__ = (
        UniqueConstraint("tenant_id", "table_name", name="uq_retention_policy"),
    )


# ---------------------------------------------------------------------------
# NotificationChannel
# ---------------------------------------------------------------------------

class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    channel_type = Column(String(64), nullable=False)  # EMAIL, SLACK, TEAMS, PAGERDUTY
    config = Column(JSONB, nullable=False)
    severity_filter = Column(ARRAY(Text))
    is_enabled = Column(Boolean, nullable=False, server_default=text("true"))
    created_at = Column(DateTime, nullable=False, server_default=text("NOW()"))
    updated_at = Column(DateTime, nullable=False, server_default=text("NOW()"), onupdate=datetime.utcnow)

    __table_args__ = (Index("ix_notification_channels_tenant_enabled", "tenant_id", "is_enabled"),)
