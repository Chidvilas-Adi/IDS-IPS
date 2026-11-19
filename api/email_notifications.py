"""SMTP delivery for high and critical IDS/IPS alerts."""

import os
import smtplib
import ssl
from email.message import EmailMessage


EMAIL_ALERT_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
REQUIRED_EMAIL_SETTINGS = ("ALERT_EMAIL_TO", "SMTP_USER", "SMTP_PASSWORD")


def missing_email_settings() -> list[str]:
    """Return required email settings that are not configured."""
    return [name for name in REQUIRED_EMAIL_SETTINGS if not os.getenv(name)]


def should_email_alert(alert: dict) -> bool:
    """Email only high and critical alerts."""
    return str(alert.get("severity", "")).upper() in EMAIL_ALERT_SEVERITIES


def send_alert_email(alert: dict) -> None:
    """Send one alert using STARTTLS-authenticated SMTP."""
    missing = missing_email_settings()
    if missing:
        raise RuntimeError(
            "Email notifications are not configured; missing " + ", ".join(missing)
        )

    username = os.environ["SMTP_USER"]
    message = EmailMessage()
    message["Subject"] = (
        f"DB-IDS/IPS {str(alert['severity']).upper()} severity alert"
    )
    message["From"] = os.getenv("SMTP_FROM") or username
    message["To"] = os.environ["ALERT_EMAIL_TO"]
    message.set_content(
        "\n".join(
            (
                "A new IDS/IPS alert was recorded.",
                "",
                f"Severity: {alert['severity']}",
                f"Detection: {alert['rule_type']}",
                f"Source IP: {alert['src_ip']}",
                f"Destination IP: {alert['dst_ip']}",
                f"Source port: {alert.get('src_port') or 'N/A'}",
                f"Destination port: {alert.get('dst_port') or 'N/A'}",
                f"Protocol: {alert.get('protocol') or 'N/A'}",
                f"Created at: {alert['created_at']}",
                f"Alert ID: {alert['id']}",
            )
        )
    )

    with smtplib.SMTP(
        os.getenv("SMTP_HOST", "smtp.gmail.com"),
        int(os.getenv("SMTP_PORT", "587")),
        timeout=10,
    ) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(username, os.environ["SMTP_PASSWORD"])
        smtp.send_message(message)
