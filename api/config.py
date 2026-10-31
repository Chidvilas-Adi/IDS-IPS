"""
config.py – centralised configuration for the IDS/IPS API.
All values are read from environment variables; sensible defaults are
provided so the application can start without a .env file during development.
"""
import os
from datetime import timedelta


class Config:
    # ── Flask ──────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production-please")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    TESTING: bool = os.getenv("TESTING", "false").lower() == "true"

    # ── JWT ────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(
        minutes=int(os.getenv("JWT_ACCESS_EXPIRES_MINUTES", "60"))
    )
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(
        days=int(os.getenv("JWT_REFRESH_EXPIRES_DAYS", "30"))
    )
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")

    # ── PostgreSQL / TimescaleDB ───────────────────────────────────────────
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "ids_ips")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "ids_user")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "ids_pass")
    SQLALCHEMY_DATABASE_URI: str = os.getenv(
        "DATABASE_URL",
        f"postgresql+psycopg2://{os.getenv('POSTGRES_USER', 'ids_user')}:"
        f"{os.getenv('POSTGRES_PASSWORD', 'ids_pass')}@"
        f"{os.getenv('POSTGRES_HOST', 'localhost')}:"
        f"{os.getenv('POSTGRES_PORT', '5432')}/"
        f"{os.getenv('POSTGRES_DB', 'ids_ips')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", "20")),
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # ── MongoDB ────────────────────────────────────────────────────────────
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
    MONGO_DB: str = os.getenv("MONGO_DB", "ids_forensics")

    # ── Redis ──────────────────────────────────────────────────────────────
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_CHANNEL_ALERTS: str = "ids:alerts"
    REDIS_CHANNEL_STATS: str = "ids:stats"

    # ── Celery ─────────────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = os.getenv(
        "CELERY_RESULT_BACKEND", "redis://localhost:6379/2"
    )

    # ── CORS ───────────────────────────────────────────────────────────────
    CORS_ORIGINS: list = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    ).split(",")

    # ── WebSocket ──────────────────────────────────────────────────────────
    SOCKETIO_ASYNC_MODE: str = os.getenv("SOCKETIO_ASYNC_MODE", "eventlet")
    SOCKETIO_MESSAGE_QUEUE: str = os.getenv("SOCKETIO_MESSAGE_QUEUE", "redis://localhost:6379/3")

    # ── Alert push intervals (seconds) ────────────────────────────────────
    ALERT_PUSH_INTERVAL: int = int(os.getenv("ALERT_PUSH_INTERVAL", "2"))
    STATS_PUSH_INTERVAL: int = int(os.getenv("STATS_PUSH_INTERVAL", "5"))

    # ── API key settings ───────────────────────────────────────────────────
    API_KEY_PREFIX: str = "ids_"
    API_KEY_BYTES: int = 32

    # ── Threat feed settings ───────────────────────────────────────────────
    THREAT_FEED_TIMEOUT: int = int(os.getenv("THREAT_FEED_TIMEOUT", "30"))

    # ── Compliance / audit ─────────────────────────────────────────────────
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "365"))

    # ── Report storage ─────────────────────────────────────────────────────
    REPORT_DIR: str = os.getenv("REPORT_DIR", "/tmp/ids_reports")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}


def get_config() -> Config:
    env = os.getenv("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)()
