#!/usr/bin/env python3
"""Verify that the IDS/IPS dashboard, API, and PostgreSQL are reachable."""

import argparse
import json
import ssl
import sys
from urllib.error import URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPSHandler, Request, build_opener


def build_context(ca_cert: str | None, allow_self_signed: bool) -> ssl.SSLContext:
    if ca_cert:
        return ssl.create_default_context(cafile=ca_cert)
    if allow_self_signed:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context()


def get(opener, base_url: str, path: str):
    request = Request(
        f"{base_url}{path}",
        headers={"Accept": "application/json, text/html", "User-Agent": "DB-IDS-IPS-LaptopB-HealthCheck/1.0"},
    )
    with opener.open(request, timeout=8) as response:
        return response.status, response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Laptop A dashboard base URL, e.g. https://192.168.1.10:8443")
    parser.add_argument("--ca-cert", help="Path to the trusted self-signed certificate copied from Laptop A")
    parser.add_argument(
        "--allow-self-signed",
        action="store_true",
        help="Skip TLS certificate verification for an isolated test network only",
    )
    args = parser.parse_args()

    target = (args.target or input("Laptop A dashboard URL (https://HOST:8443): ")).strip().rstrip("/")
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
        parser.error("Target must be an http(s) URL with a host and no path, query, or fragment.")
    if parsed.username or parsed.password:
        parser.error("Do not put credentials in the target URL.")
    base_url = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))

    context = build_context(args.ca_cert, args.allow_self_signed)
    opener = build_opener(HTTPSHandler(context=context))

    try:
        status, page = get(opener, base_url, "/")
        if status != 200 or b'id="root"' not in page:
            raise RuntimeError("The dashboard did not return the expected React page.")
        print("Dashboard page: PASS")

        status, health_body = get(opener, base_url, "/health")
        health = json.loads(health_body)
        components = health.get("components", {})
        if status != 200 or health.get("status") != "UP":
            raise RuntimeError(f"API readiness check failed: {health.get('status', 'unknown')}.")
        for component, state in sorted(components.items()):
            print(f"{component}: {'PASS' if state == 'UP' else 'FAIL'}")
            if state != "UP":
                raise RuntimeError(f"{component} is not ready.")

        status, stats_body = get(opener, base_url, "/api/stats/overview")
        stats = json.loads(stats_body)
        if status != 200 or "alerts_today" not in stats:
            raise RuntimeError("The database-backed stats endpoint did not return the expected response.")
        print("PostgreSQL-backed API: PASS")
        print("Laptop A is reachable and the database-backed dashboard is ready.")
        return 0
    except (OSError, URLError, ssl.SSLError, json.JSONDecodeError, RuntimeError) as exc:
        message = str(exc)
        if isinstance(exc, URLError) and isinstance(exc.reason, ssl.SSLCertVerificationError):
            message = (
                "TLS certificate is not trusted. Copy Laptop A's self-signed certificate here "
                "and pass --ca-cert, or use --allow-self-signed on an isolated lab network."
            )
        print(f"Health check failed: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
