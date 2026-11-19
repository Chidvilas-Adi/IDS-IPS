import os
import unittest
from unittest.mock import patch

from email_notifications import send_alert_email, should_email_alert


class EmailNotificationTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {
                "ALERT_EMAIL_TO": "recipient@example.com",
                "SMTP_USER": "sender@example.com",
                "SMTP_PASSWORD": "test-app-password",
                "SMTP_HOST": "smtp.example.com",
                "SMTP_PORT": "587",
            },
            clear=True,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_only_high_and_critical_alerts_are_selected(self):
        self.assertTrue(should_email_alert({"severity": "HIGH"}))
        self.assertTrue(should_email_alert({"severity": "critical"}))
        self.assertFalse(should_email_alert({"severity": "MEDIUM"}))
        self.assertFalse(should_email_alert({"severity": "LOW"}))

    @patch("email_notifications.smtplib.SMTP")
    def test_sends_formatted_email_using_starttls(self, smtp_factory):
        alert = {
            "id": 42,
            "severity": "HIGH",
            "rule_type": "SQL_DPI_SIGNATURE",
            "src_ip": "198.51.100.189",
            "dst_ip": "192.0.2.10",
            "src_port": 49200,
            "dst_port": 80,
            "protocol": "TCP",
            "created_at": "2026-11-01T20:00:00+00:00",
        }

        with patch(
            "email_notifications.ssl.create_default_context",
            return_value="test-ssl-context",
        ):
            send_alert_email(alert)

        smtp_factory.assert_called_once_with(
            "smtp.example.com", 587, timeout=10
        )
        smtp = smtp_factory.return_value.__enter__.return_value
        smtp.starttls.assert_called_once_with(context="test-ssl-context")
        smtp.login.assert_called_once_with("sender@example.com", "test-app-password")
        message = smtp.send_message.call_args.args[0]
        self.assertEqual(message["To"], "recipient@example.com")
        self.assertIn("HIGH", message["Subject"])
        self.assertIn("198.51.100.189", message.get_content())
        self.assertIn("Alert ID: 42", message.get_content())

    def test_missing_credentials_are_reported(self):
        with patch.dict(os.environ, {"SMTP_PASSWORD": ""}):
            with self.assertRaisesRegex(RuntimeError, "SMTP_PASSWORD"):
                send_alert_email({"severity": "HIGH"})


if __name__ == "__main__":
    unittest.main()
