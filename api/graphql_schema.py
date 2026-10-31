"""
graphql_schema.py – Strawberry GraphQL schema for the IDS/IPS API.

Exposes Queries, Mutations, and Subscriptions for dashboards and SIEM
integrations that prefer GraphQL over REST.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import AsyncGenerator, List, Optional

import strawberry
from strawberry.scalars import JSON

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scalar helpers
# ---------------------------------------------------------------------------
DatetimeScalar = strawberry.scalar(
    datetime,
    serialize=lambda v: v.isoformat() if v else None,
    parse_value=lambda v: datetime.fromisoformat(v),
    description="ISO-8601 datetime string",
)


# ---------------------------------------------------------------------------
# GraphQL Types
# ---------------------------------------------------------------------------


@strawberry.type
class Alert:
    id: int
    rule_id: Optional[int]
    rule_name: Optional[str]
    severity: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    message: Optional[str]
    status: str
    assigned_to: Optional[str]
    created_at: Optional[datetime]
    acknowledged_at: Optional[datetime]


@strawberry.type
class Rule:
    id: int
    name: str
    rule_type: str
    severity: str
    protocol: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    action: str
    enabled: bool
    description: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


@strawberry.type
class CorrelationRule:
    id: int
    name: str
    description: Optional[str]
    logic: Optional[JSON]
    threshold: Optional[int]
    time_window_seconds: Optional[int]
    severity: str
    enabled: bool
    created_at: Optional[datetime]


@strawberry.type
class Session:
    id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    state: Optional[str]
    bytes_sent: Optional[int]
    bytes_recv: Optional[int]
    packets_sent: Optional[int]
    packets_recv: Optional[int]
    started_at: Optional[datetime]
    last_seen_at: Optional[datetime]


@strawberry.type
class IocIP:
    id: int
    ip_address: str
    feed_id: Optional[int]
    threat_type: Optional[str]
    confidence: Optional[int]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: Optional[JSON]
    active: bool


@strawberry.type
class ThreatFeed:
    id: int
    name: str
    url: Optional[str]
    feed_type: str
    enabled: bool
    last_polled: Optional[datetime]
    poll_interval_minutes: Optional[int]
    record_count: Optional[int]


@strawberry.type
class IpReputation:
    id: int
    ip_address: str
    reputation_score: Optional[float]
    abuse_confidence: Optional[int]
    is_tor: Optional[bool]
    is_vpn: Optional[bool]
    is_proxy: Optional[bool]
    country_code: Optional[str]
    asn: Optional[str]
    isp: Optional[str]
    updated_at: Optional[datetime]


@strawberry.type
class PlaybookStep:
    id: int
    playbook_id: int
    step_order: int
    action_type: str
    action_params: Optional[JSON]
    condition: Optional[str]
    on_success: Optional[str]
    on_failure: Optional[str]


@strawberry.type
class Playbook:
    id: int
    name: str
    description: Optional[str]
    trigger_severity: Optional[str]
    trigger_rule_type: Optional[str]
    enabled: bool
    steps: Optional[List[PlaybookStep]]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]


@strawberry.type
class Incident:
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    assigned_to: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]


@strawberry.type
class StatsOverview:
    total_alerts_today: int
    critical_alerts_today: int
    blocked_ips: int
    active_sessions: int
    threat_score: float
    alerts_last_hour: int


@strawberry.type
class AlertsResult:
    items: List[Alert]
    total: int
    page: int
    page_size: int


@strawberry.type
class RulesResult:
    items: List[Rule]
    total: int


@strawberry.type
class MutationResult:
    success: bool
    message: str
    id: Optional[int]


# ---------------------------------------------------------------------------
# Input types
# ---------------------------------------------------------------------------


@strawberry.input
class AlertFilters:
    severity: Optional[str] = None
    status: Optional[str] = None
    rule_type: Optional[str] = None
    src_ip: Optional[str] = None
    page: Optional[int] = 1
    page_size: Optional[int] = 50


@strawberry.input
class RuleFilters:
    rule_type: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None


@strawberry.input
class CreateRuleInput:
    name: str
    rule_type: str
    severity: str
    action: str
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    description: Optional[str] = None
    enabled: Optional[bool] = True


@strawberry.input
class UpdateRuleInput:
    name: Optional[str] = None
    severity: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# DB helpers (lazy imports to avoid circular deps)
# ---------------------------------------------------------------------------


def _db():
    from app import db
    return db


def _get_pg():
    """Return a raw psycopg2 connection from SQLAlchemy engine for text queries."""
    from app import db
    return db.engine.connect()


def _run_query(sql: str, params: dict | None = None) -> list[dict]:
    from sqlalchemy import text
    from app import db

    with db.engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        cols = result.keys()
        return [dict(zip(cols, row)) for row in result.fetchall()]


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


@strawberry.type
class Query:
    @strawberry.field(description="Fetch paginated alerts with optional filters.")
    def alerts(self, filters: Optional[AlertFilters] = None) -> AlertsResult:
        f = filters or AlertFilters()
        page = max(1, f.page or 1)
        page_size = min(200, max(1, f.page_size or 50))
        offset = (page - 1) * page_size

        conditions = []
        params: dict = {"limit": page_size, "offset": offset}

        if f.severity:
            conditions.append("a.severity = :severity")
            params["severity"] = f.severity
        if f.status:
            conditions.append("a.status = :status")
            params["status"] = f.status
        if f.src_ip:
            conditions.append("a.src_ip = :src_ip")
            params["src_ip"] = f.src_ip

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        count_sql = f"SELECT COUNT(*) FROM alerts a {where}"
        rows_sql = (
            f"SELECT a.id, a.rule_id, r.name AS rule_name, a.severity, "
            f"a.src_ip, a.dst_ip, a.src_port, a.dst_port, a.protocol, "
            f"a.message, a.status, a.assigned_to, a.created_at, a.acknowledged_at "
            f"FROM alerts a LEFT JOIN rules r ON r.id = a.rule_id "
            f"{where} ORDER BY a.created_at DESC LIMIT :limit OFFSET :offset"
        )

        try:
            total_rows = _run_query(count_sql, {k: v for k, v in params.items() if k not in ("limit", "offset")})
            total = total_rows[0]["count"] if total_rows else 0
            rows = _run_query(rows_sql, params)
        except Exception as exc:
            logger.error("GraphQL alerts query failed: %s", exc)
            return AlertsResult(items=[], total=0, page=page, page_size=page_size)

        items = [Alert(**{k: row.get(k) for k in Alert.__dataclass_fields__}) for row in rows]
        return AlertsResult(items=items, total=total, page=page, page_size=page_size)

    @strawberry.field(description="Fetch all rules with optional filters.")
    def rules(self, filters: Optional[RuleFilters] = None) -> RulesResult:
        f = filters or RuleFilters()
        conditions = []
        params: dict = {}

        if f.rule_type:
            conditions.append("rule_type = :rule_type")
            params["rule_type"] = f.rule_type
        if f.severity:
            conditions.append("severity = :severity")
            params["severity"] = f.severity
        if f.enabled is not None:
            conditions.append("enabled = :enabled")
            params["enabled"] = f.enabled

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql = (
            f"SELECT id, name, rule_type, severity, protocol, src_ip, dst_ip, "
            f"src_port, dst_port, action, enabled, description, created_at, updated_at "
            f"FROM rules {where} ORDER BY id"
        )

        try:
            rows = _run_query(sql, params)
        except Exception as exc:
            logger.error("GraphQL rules query failed: %s", exc)
            return RulesResult(items=[], total=0)

        items = [Rule(**{k: row.get(k) for k in Rule.__dataclass_fields__}) for row in rows]
        return RulesResult(items=items, total=len(items))

    @strawberry.field(description="Fetch active network sessions.")
    def sessions(self, active_only: bool = True) -> List[Session]:
        extra = "WHERE state = 'ESTABLISHED'" if active_only else ""
        sql = (
            f"SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, state, "
            f"bytes_sent, bytes_recv, packets_sent, packets_recv, started_at, last_seen_at "
            f"FROM sessions {extra} ORDER BY last_seen_at DESC LIMIT 500"
        )
        try:
            rows = _run_query(sql)
            return [Session(**{k: row.get(k) for k in Session.__dataclass_fields__}) for row in rows]
        except Exception as exc:
            logger.error("GraphQL sessions query failed: %s", exc)
            return []

    @strawberry.field(description="Search IOC IP table by IP, subnet or threat type.")
    def ioc_search(self, query: str) -> List[IocIP]:
        sql = (
            "SELECT id, ip_address, feed_id, threat_type, confidence, "
            "first_seen, last_seen, tags, active "
            "FROM ioc_ip_addresses "
            "WHERE ip_address::text ILIKE :q OR threat_type ILIKE :q "
            "ORDER BY last_seen DESC LIMIT 100"
        )
        try:
            rows = _run_query(sql, {"q": f"%{query}%"})
            return [IocIP(**{k: row.get(k) for k in IocIP.__dataclass_fields__}) for row in rows]
        except Exception as exc:
            logger.error("GraphQL ioc_search failed: %s", exc)
            return []

    @strawberry.field(description="System overview statistics.")
    def stats(self) -> StatsOverview:
        sql = """
            SELECT
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) AS total_alerts_today,
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE AND severity = 'critical') AS critical_alerts_today,
                COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') AS alerts_last_hour
            FROM alerts
        """
        blocked_sql = "SELECT COUNT(*) AS cnt FROM blocked_ips WHERE active = true"
        sessions_sql = "SELECT COUNT(*) AS cnt FROM sessions WHERE state = 'ESTABLISHED'"
        score_sql = "SELECT COALESCE(AVG(reputation_score), 0) AS avg FROM ip_reputation WHERE updated_at >= NOW() - INTERVAL '1 hour'"

        try:
            alert_row = _run_query(sql)[0]
            blocked = _run_query(blocked_sql)[0]["cnt"]
            sessions = _run_query(sessions_sql)[0]["cnt"]
            score_row = _run_query(score_sql)
            score = float(score_row[0]["avg"]) if score_row else 0.0
        except Exception as exc:
            logger.error("GraphQL stats query failed: %s", exc)
            return StatsOverview(
                total_alerts_today=0, critical_alerts_today=0,
                blocked_ips=0, active_sessions=0,
                threat_score=0.0, alerts_last_hour=0,
            )

        return StatsOverview(
            total_alerts_today=alert_row.get("total_alerts_today", 0),
            critical_alerts_today=alert_row.get("critical_alerts_today", 0),
            blocked_ips=blocked,
            active_sessions=sessions,
            threat_score=round(score, 2),
            alerts_last_hour=alert_row.get("alerts_last_hour", 0),
        )


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


@strawberry.type
class Mutation:
    @strawberry.mutation(description="Create a new detection rule.")
    def create_rule(self, input: CreateRuleInput) -> MutationResult:
        from sqlalchemy import text
        from app import db

        sql = text(
            "INSERT INTO rules (name, rule_type, severity, action, protocol, "
            "src_ip, dst_ip, src_port, dst_port, description, enabled, created_at, updated_at) "
            "VALUES (:name, :rule_type, :severity, :action, :protocol, :src_ip, :dst_ip, "
            ":src_port, :dst_port, :description, :enabled, NOW(), NOW()) RETURNING id"
        )
        try:
            with db.engine.begin() as conn:
                result = conn.execute(sql, {
                    "name": input.name, "rule_type": input.rule_type,
                    "severity": input.severity, "action": input.action,
                    "protocol": input.protocol, "src_ip": input.src_ip,
                    "dst_ip": input.dst_ip, "src_port": input.src_port,
                    "dst_port": input.dst_port, "description": input.description,
                    "enabled": input.enabled,
                })
                new_id = result.scalar()
            return MutationResult(success=True, message="Rule created.", id=new_id)
        except Exception as exc:
            logger.error("createRule mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)

    @strawberry.mutation(description="Update an existing rule by ID.")
    def update_rule(self, id: int, input: UpdateRuleInput) -> MutationResult:
        from sqlalchemy import text
        from app import db

        sets = []
        params: dict = {"id": id}
        if input.name is not None:
            sets.append("name = :name"); params["name"] = input.name
        if input.severity is not None:
            sets.append("severity = :severity"); params["severity"] = input.severity
        if input.action is not None:
            sets.append("action = :action"); params["action"] = input.action
        if input.enabled is not None:
            sets.append("enabled = :enabled"); params["enabled"] = input.enabled
        if input.description is not None:
            sets.append("description = :description"); params["description"] = input.description

        if not sets:
            return MutationResult(success=False, message="Nothing to update.", id=id)

        sets.append("updated_at = NOW()")
        sql = text(f"UPDATE rules SET {', '.join(sets)} WHERE id = :id RETURNING id")
        try:
            with db.engine.begin() as conn:
                result = conn.execute(sql, params)
                if result.rowcount == 0:
                    return MutationResult(success=False, message="Rule not found.", id=None)
            return MutationResult(success=True, message="Rule updated.", id=id)
        except Exception as exc:
            logger.error("updateRule mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)

    @strawberry.mutation(description="Delete a rule by ID.")
    def delete_rule(self, id: int) -> MutationResult:
        from sqlalchemy import text
        from app import db

        try:
            with db.engine.begin() as conn:
                result = conn.execute(text("DELETE FROM rules WHERE id = :id"), {"id": id})
                if result.rowcount == 0:
                    return MutationResult(success=False, message="Rule not found.", id=None)
            return MutationResult(success=True, message="Rule deleted.", id=id)
        except Exception as exc:
            logger.error("deleteRule mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)

    @strawberry.mutation(description="Block an IP address immediately.")
    def block_ip(self, ip: str, reason: Optional[str] = None) -> MutationResult:
        from sqlalchemy import text
        from app import db

        try:
            with db.engine.begin() as conn:
                result = conn.execute(
                    text(
                        "INSERT INTO blocked_ips (ip_address, reason, blocked_at, active) "
                        "VALUES (:ip, :reason, NOW(), true) "
                        "ON CONFLICT (ip_address) DO UPDATE SET active = true, reason = :reason, blocked_at = NOW() "
                        "RETURNING id"
                    ),
                    {"ip": ip, "reason": reason or "Manual block via GraphQL"},
                )
                new_id = result.scalar()
            return MutationResult(success=True, message=f"IP {ip} blocked.", id=new_id)
        except Exception as exc:
            logger.error("blockIp mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)

    @strawberry.mutation(description="Acknowledge an alert (set status to acknowledged).")
    def acknowledge_alert(self, id: int, assigned_to: Optional[str] = None) -> MutationResult:
        from sqlalchemy import text
        from app import db

        try:
            with db.engine.begin() as conn:
                result = conn.execute(
                    text(
                        "UPDATE alerts SET status = 'acknowledged', acknowledged_at = NOW(), "
                        "assigned_to = COALESCE(:assigned_to, assigned_to) WHERE id = :id RETURNING id"
                    ),
                    {"id": id, "assigned_to": assigned_to},
                )
                if result.rowcount == 0:
                    return MutationResult(success=False, message="Alert not found.", id=None)
            return MutationResult(success=True, message="Alert acknowledged.", id=id)
        except Exception as exc:
            logger.error("acknowledgeAlert mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)

    @strawberry.mutation(description="Manually trigger a playbook for a given alert ID.")
    def run_playbook(self, playbook_id: int, alert_id: int) -> MutationResult:
        try:
            from celery_worker import execute_playbook_task
            task = execute_playbook_task.delay(playbook_id, alert_id)
            return MutationResult(success=True, message=f"Playbook queued (task={task.id}).", id=playbook_id)
        except Exception as exc:
            logger.error("runPlaybook mutation failed: %s", exc)
            return MutationResult(success=False, message=str(exc), id=None)


# ---------------------------------------------------------------------------
# Subscriptions
# ---------------------------------------------------------------------------


@strawberry.type
class Subscription:
    @strawberry.subscription(description="Stream of new alerts pushed in real time.")
    async def on_new_alert(self) -> AsyncGenerator[Alert, None]:
        """
        Uses Redis pub/sub to receive new alerts.  The app.py background task
        publishes to 'ids:alerts' whenever a new alert is detected.
        """
        import json
        import redis.asyncio as aioredis
        from config import get_config

        cfg = get_config()
        client = aioredis.from_url(cfg.REDIS_URL)
        pubsub = client.pubsub()
        await pubsub.subscribe(cfg.REDIS_CHANNEL_ALERTS)

        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    data = json.loads(message["data"])
                    yield Alert(**{k: data.get(k) for k in Alert.__dataclass_fields__})
                except Exception as parse_exc:
                    logger.warning("Could not parse alert from Redis: %s", parse_exc)
        finally:
            await pubsub.unsubscribe(cfg.REDIS_CHANNEL_ALERTS)
            await client.aclose()


# ---------------------------------------------------------------------------
# Build the schema
# ---------------------------------------------------------------------------
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    scalar_overrides={datetime: DatetimeScalar},
)
