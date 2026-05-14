from __future__ import annotations

import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "http://localhost:8050"
PATHS = [
    "/healthz",
    "/readyz",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
]


def fetch(path: str) -> tuple[int, str | None, str]:
    request = Request(f"{BASE_URL}{path}", headers={"Accept": "application/json"})
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urlopen(request, timeout=5) as response:
        body = response.read().decode("utf-8")
        request_id = response.headers.get("X-Request-Id")
        return response.status, request_id, body


def main() -> int:
    failures: list[str] = []

    for path in PATHS:
        try:
            status, request_id, body = fetch(path)
        except HTTPError as error:
            failures.append(f"{path}: unexpected status {error.code}")
            continue
        except URLError as error:
            failures.append(f"{path}: unable to connect: {error.reason}")
            continue

        if status != 200:
            failures.append(f"{path}: unexpected status {status}")
            continue
        if not request_id:
            failures.append(f"{path}: missing X-Request-Id header")
            continue

        if path in ("/healthz", "/readyz"):
            data = json.loads(body)
            if data.get("request_id") != request_id:
                failures.append(f"{path}: request id mismatch")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("auth-server smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
