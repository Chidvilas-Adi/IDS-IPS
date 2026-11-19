#!/usr/bin/env python3
"""Run authorized synthetic IDS/IPS demo scenarios against Laptop A."""

import argparse
import getpass
import json
import ssl
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, Request, build_opener


DEFAULT_TARGET = "https://10.17.31.79:8443"
USER_AGENT = "DB-IDS-IPS-LaptopB-Demo/1.0"
ALERT_WAIT_SECONDS = 12
POLL_INTERVAL_SECONDS = 1

SCENARIOS = (
    {
        "name": "benign",
        "label": "Benign baseline",
        "alert_ip": None,
        "rule_type": None,
        "expects_alert": False,
    },
    {
        "name": "sqli",
        "label": "SQL injection signature (synthetic)",
        "alert_ip": "198.51.100.189",
        "rule_type": "SQL_DPI_SIGNATURE",
        "expects_alert": True,
    },
    {
        "name": "log4shell",
        "label": "Log4Shell signature (synthetic)",
        "alert_ip": "198.51.100.190",
        "rule_type": "SQL_DPI_SIGNATURE",
        "expects_alert": True,
    },
    {
        "name": "portscan",
        "label": "TCP port-sweep correlation (synthetic)",
        "alert_ip": "198.51.100.191",
        "rule_type": "SQL_CORRELATION",
        "expects_alert": True,
    },
    {
        "name": "sshbrute",
        "label": "SSH-attempt correlation (synthetic)",
        "alert_ip": "198.51.100.192",
        "rule_type": "SQL_CORRELATION",
        "expects_alert": True,
    },
    {
        "name": "canary",
        "label": "Database canary access (synthetic)",
        "alert_ip": None,
        "rule_type": "INSIDER_CANARY_ACCESSED",
        "expects_alert": True,
    },
)


class DemoError(Exception):
    """Expected, user-actionable demo failure."""


class APIClient:
    def __init__(self, base_url, opener, timeout):
        self.base_url = base_url.rstrip("/")
        self.opener = opener
        self.timeout = timeout

    def request_json(self, method, path, body=None, token=None):
        headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            if exc.code == 401 and path == "/api/auth/login":
                raise DemoError(
                    "Login rejected (401). Use username 'admin' and the current "
                    "admin password configured on Laptop A."
                ) from exc
            raise DemoError(f"API returned HTTP {exc.code}: {detail}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise DemoError(f"Could not reach Laptop A: {exc}") from exc

        if not payload:
            return {}
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise DemoError(f"API returned invalid JSON for {path}.") from exc

    def get_bytes(self, path):
        request = Request(
            self.base_url + path,
            headers={"Accept": "text/html", "User-Agent": USER_AGENT},
        )
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise DemoError(f"Dashboard check failed: {exc}") from exc


def build_client(args):
    target = (args.target or input(f"Laptop A URL [{DEFAULT_TARGET}]: ").strip() or DEFAULT_TARGET).rstrip("/")
    parsed = urlsplit(target)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise DemoError("Target must be an HTTPS base URL, e.g. https://192.168.1.20:8443")

    base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    if args.ca_cert and args.allow_self_signed:
        raise DemoError("Choose either --ca-cert or --allow-self-signed, not both.")

    if args.ca_cert:
        try:
            context = ssl.create_default_context(cafile=args.ca_cert)
        except (OSError, ssl.SSLError) as exc:
            raise DemoError(f"Could not load CA certificate: {exc}") from exc
    elif args.allow_self_signed:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        local_cert = Path(__file__).with_name("self-signed.crt")
        if local_cert.is_file():
            context = ssl.create_default_context(cafile=str(local_cert))
        else:
            raise DemoError(
                "TLS certificate is not configured. Copy Laptop A's "
                "self-signed.crt beside this script and rerun, or explicitly "
                "use --allow-self-signed on your trusted isolated lab network."
            )

    opener = build_opener(HTTPSHandler(context=context))
    return APIClient(base_url, opener, args.timeout)


def verify_health(client):
    status, page = client.get_bytes("/")
    if status != 200 or b'id="root"' not in page:
        raise DemoError("Dashboard page did not return the expected React app.")
    print("[PASS] Dashboard page")

    health = client.request_json("GET", "/health")
    if health.get("status") != "UP":
        raise DemoError(f"API health is {health.get('status', 'unknown')}.")
    for component, state in sorted(health.get("components", {}).items()):
        print(f"[{'PASS' if state == 'UP' else 'FAIL'}] {component}: {state}")
        if state != "UP":
            raise DemoError(f"{component} is not healthy.")

    stats = client.request_json("GET", "/api/stats/overview")
    if "alerts_today" not in stats:
        raise DemoError("PostgreSQL-backed dashboard stats response was incomplete.")
    print("[PASS] PostgreSQL-backed statistics endpoint")


def login(client):
    username = input("Dashboard username [admin]: ").strip() or "admin"
    password = getpass.getpass("Dashboard password: ")
    if not password:
        raise DemoError("Password cannot be empty.")
    try:
        response = client.request_json(
            "POST",
            "/api/auth/login",
            {"username": username, "password": password},
        )
    finally:
        password = None

    token = response.get("access_token")
    if not token:
        raise DemoError("Login response did not contain an access token.")
    print(f"[PASS] Authenticated as {username}; token kept in memory.")
    return token


def alert_query(scenario):
    params = {"limit": "100"}
    if scenario["alert_ip"]:
        params["src_ip"] = scenario["alert_ip"]
    if scenario["rule_type"]:
        params["rule_type"] = scenario["rule_type"]
    return "/api/alerts?" + urlencode(params)


def list_alerts(client, scenario, token):
    result = client.request_json("GET", alert_query(scenario), token=token)
    return result.get("items", [])


def run_scenario(client, scenario, token):
    old_ids = {
        str(alert.get("id"))
        for alert in list_alerts(client, scenario, token)
        if alert.get("id") is not None
    }

    result = client.request_json(
        "POST",
        f"/api/simulate/{scenario['name']}",
        {},
        token=token,
    )
    if result.get("success") is not True:
        raise DemoError(result.get("message", "The simulator did not confirm success."))

    if not scenario["expects_alert"]:
        print(f"[PASS] {scenario['label']}: submitted; no alert is expected.")
        return True

    deadline = time.monotonic() + ALERT_WAIT_SECONDS
    while time.monotonic() < deadline:
        alerts = list_alerts(client, scenario, token)
        new_alerts = [
            alert for alert in alerts
            if alert.get("id") is not None and str(alert["id"]) not in old_ids
        ]
        if new_alerts:
            alert = new_alerts[0]
            print(
                f"[PASS] {scenario['label']}: alert #{alert['id']} "
                f"({alert.get('severity', 'severity unknown')}, "
                f"{alert.get('rule_name') or alert.get('rule_type', 'rule unknown')})."
            )
            return True
        time.sleep(POLL_INTERVAL_SECONDS)

    print(
        f"[WARN] {scenario['label']}: packets submitted, but no new matching "
        "alert appeared. Check that the corresponding database rule/signature "
        "is enabled and inspect Laptop A's API/database logs."
    )
    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Check Laptop A, then run its authenticated synthetic IDS/IPS "
            "demo scenarios. No exploit traffic is sent to network services."
        )
    )
    parser.add_argument("--target", help="Laptop A HTTPS URL")
    parser.add_argument("--ca-cert", help="Trusted certificate copied from Laptop A")
    parser.add_argument(
        "--allow-self-signed",
        action="store_true",
        help="Skip TLS validation for an isolated, trusted lab only",
    )
    parser.add_argument("--timeout", type=float, default=8, help="HTTP timeout in seconds")
    parser.add_argument(
        "--health-only",
        action="store_true",
        help="Check dashboard/API/database health without login or simulations",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation before inserting synthetic lab events",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.timeout <= 0:
        print("Error: --timeout must be positive.", file=sys.stderr)
        return 2

    try:
        client = build_client(args)
        print("\nDB-IDS/IPS LAPTOP B LAB DEMO")
        print("=" * 31)
        print(f"Target: {client.base_url}")
        verify_health(client)

        if args.health_only:
            print("\nHealth check complete. No login or simulation was performed.")
            return 0

        print(
            "\nThe following scenarios insert synthetic data directly through "
            "the authenticated API. They do not attack network services. "
            "Detection scenarios can create alerts and temporary test-IP block "
            "records in the lab database."
        )
        if not args.yes and input("Run all six demo scenarios? [y/N]: ").strip().lower() not in {"y", "yes"}:
            print("Cancelled; no simulation events were submitted.")
            return 0

        token = login(client)
        passed = 0
        for scenario in SCENARIOS:
            print(f"\nRunning: {scenario['label']}")
            try:
                passed += run_scenario(client, scenario, token)
            except DemoError as exc:
                print(f"[FAIL] {scenario['label']}: {exc}")

        print("\nDemo summary")
        print(f"Scenarios successful/verified: {passed}/{len(SCENARIOS)}")
        print("Open the dashboard's Alert Feed to review generated alerts.")
        print("Synthetic test events are not evidence of live attack detection.")
        return 0 if passed == len(SCENARIOS) else 1
    except (DemoError, KeyboardInterrupt) as exc:
        message = "Interrupted." if isinstance(exc, KeyboardInterrupt) else str(exc)
        print(f"\nError: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
