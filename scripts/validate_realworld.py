"""Real-world validation harness for BARAQ.

The default evaluation fixtures are synthetic; this script runs the existing
hold-out endpoint with ``use_real_baseline=true`` so the NEGATIVE class is
real host telemetry (true negatives) instead of a synthetic benign baseline.
That is the external-validity check that proves detections hold up against
genuine, noisy enterprise traffic - see documentation/red_team_validation.md.

Usage:
    python scripts/validate_realworld.py --base-url http://127.0.0.1:8000 \
        --api-key baraq-dev-admin

Requires a running BARAQ server with admin credentials. Prints the precision /
recall / FPR summary for the real-baseline run.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import urllib.error


def _post(base_url: str, api_key: str, path: str, params: str) -> dict:
    url = f"{base_url}{path}?{params}"
    req = urllib.request.Request(url, data=b"", method="POST")
    req.add_header("X-API-Key", api_key)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # surface server-side errors clearly
        body = exc.read().decode("utf-8", "replace")
        print(f"ERROR {exc.code}: {body}", file=sys.stderr)
        raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="BARAQ real-world validation")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="baraq-dev-admin")
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Run rule-only (skip the ML anomaly layer).",
    )
    parser.add_argument(
        "--randomize",
        action="store_true",
        help="Apply seeded domain randomization to the hold-out attacks.",
    )
    args = parser.parse_args()

    params = (
        f"use_real_baseline=true&with_ml={str(not args.no_ml).lower()}"
        f"&randomize={str(args.randomize).lower()}"
    )
    print(f"[*] Running hold-out evaluation with REAL host-telemetry baseline "
          f"against {args.base_url} ...")
    result = _post(args.base_url, args.api_key, "/api/evaluation/holdout", params)

    summary = result.get("summary") or result
    print(json.dumps(summary, indent=2))
    print("\n[+] Real-world validation complete. Compare these numbers against the "
          "synthetic-baseline run (POST /api/evaluation/holdout?use_real_baseline=false).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
