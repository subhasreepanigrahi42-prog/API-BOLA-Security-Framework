#!/usr/bin/env python3
"""
API BOLA Security Framework
Subhashree Panigrahi

A conservative, configuration-driven checker for Broken Object Level Authorization
(BOLA/IDOR) in APIs you own or are explicitly authorized to test.

This tool sends only the requests described in a local JSON config. It does not
discover endpoints, brute-force identifiers, or exploit systems automatically.
Use a staging/local lab and test accounts with explicit permission.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests


DEFAULT_TIMEOUT = 10
DENIAL_STATUSES = {401, 403, 404}


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    for key in ("base_url", "users", "tests"):
        if key not in config:
            raise ValueError(f"Config is missing required key: {key}")
    if not isinstance(config["users"], dict) or not isinstance(config["tests"], list):
        raise ValueError("'users' must be an object and 'tests' must be a list")
    return config


def make_headers(user: dict[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    headers.update(user.get("headers", {}))
    token = user.get("token")
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")
    return headers


def request_resource(
    session: requests.Session,
    base_url: str,
    test: dict[str, Any],
    user: dict[str, Any],
    timeout: int,
) -> requests.Response:
    path = test["path"].format(**test.get("path_params", {}))
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    method = test.get("method", "GET").upper()
    kwargs: dict[str, Any] = {
        "headers": make_headers(user),
        "timeout": timeout,
        "allow_redirects": False,
    }
    if "json" in test:
        kwargs["json"] = test["json"]
    if "params" in test:
        kwargs["params"] = test["params"]
    return session.request(method, url, **kwargs)


def run_test(
    base_url: str,
    users: dict[str, Any],
    test: dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    test_id = test.get("id", "unnamed-test")
    owner_name = test.get("owner_user")
    other_name = test.get("other_user")
    if owner_name not in users or other_name not in users:
        return {
            "test_id": test_id, "status": "CONFIG_ERROR",
            "detail": "owner_user or other_user is not defined in users",
        }

    with requests.Session() as session:
        try:
            owner_response = request_resource(
                session, base_url, test, users[owner_name], timeout
            )
            other_response = request_resource(
                session, base_url, test, users[other_name], timeout
            )
        except requests.RequestException as exc:
            return {
                "test_id": test_id, "status": "ERROR",
                "detail": f"Request failed: {type(exc).__name__}: {exc}",
            }

    expected_owner = set(test.get("owner_expected_statuses", [200]))
    denied_statuses = set(test.get("denied_statuses", sorted(DENIAL_STATUSES)))
    owner_ok = owner_response.status_code in expected_owner
    other_denied = other_response.status_code in denied_statuses

    if not owner_ok:
        status = "REVIEW_OWNER_ACCESS"
        detail = "Owner request did not return an expected status."
    elif other_denied:
        status = "PASS"
        detail = "Owner can access resource; other user received a denial status."
    else:
        # A successful response to a cross-user request is a signal for review,
        # not definitive proof: some endpoints legitimately expose shared objects.
        status = "POTENTIAL_BOLA"
        detail = (
            "Other user was not denied. Verify object ownership/sharing rules "
            "and inspect the response before classifying this as a vulnerability."
        )

    return {
        "test_id": test_id,
        "description": test.get("description", ""),
        "status": status,
        "owner_user": owner_name,
        "owner_http_status": owner_response.status_code,
        "other_user": other_name,
        "other_http_status": other_response.status_code,
        "other_response_content_type": other_response.headers.get("Content-Type", ""),
        "detail": detail,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run configured BOLA checks against an authorized API."
    )
    parser.add_argument("--config", required=True, help="Path to JSON test configuration")
    parser.add_argument("--output", default="bola_report.json", help="Output report path")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()

    try:
        config = load_config(Path(args.config))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    base_url = config["base_url"]
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        print("Configuration error: base_url must start with http:// or https://", file=sys.stderr)
        return 2

    results = [
        run_test(base_url, config["users"], test, max(1, args.timeout))
        for test in config["tests"]
    ]
    report = {
        "project": "API BOLA Security Framework",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_base_url": base_url,
        "authorization_note": "Run only against systems you own or are authorized to test.",
        "summary": {
            "total": len(results),
            "pass": sum(r["status"] == "PASS" for r in results),
            "potential_bola": sum(r["status"] == "POTENTIAL_BOLA" for r in results),
            "errors": sum(r["status"] in {"ERROR", "CONFIG_ERROR"} for r in results),
            "review_owner_access": sum(r["status"] == "REVIEW_OWNER_ACCESS" for r in results),
        },
        "results": results,
    }
    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(f"Detailed report saved to: {output_path.resolve()}")
    return 1 if report["summary"]["potential_bola"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
