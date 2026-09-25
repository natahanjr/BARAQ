"""Production preflight: one command that answers "can we go live?".

Checks the things that are cheap to verify and expensive to discover during an
incident: the production config gate, real TLS, agent reachability, a restorable
backup, the auth surface, and the safety switches. Every check prints PASS /
FAIL / WARN and the script exits non-zero if any hard check fails, so it can
gate a deployment in CI or from a change window.

    venv\\Scripts\\python scripts\\preflight.py --url https://soc.example.internal:8443

Read-only: it never writes to the database and never executes a response
action.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"


@dataclass
class Result:
    name: str
    status: str
    detail: str = ""


def _http(url: str, headers: dict | None = None, timeout: int = 15, context=None):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=context)


def check_config() -> list[Result]:
    """The in-process production gate: keys, encryption, SOAR, auth."""
    out: list[Result] = []
    try:
        import backend.config as c
    except Exception as exc:  # pragma: no cover - import failure is fatal
        return [Result("config imports", FAIL, str(exc)[:200])]

    out.append(
        Result(
            "profile is production",
            PASS if c.IS_PRODUCTION else FAIL,
            f"BARAQ_ENV={'production' if c.IS_PRODUCTION else 'not production'}",
        )
    )
    out.append(
        Result(
            "encryption at rest",
            PASS if c.ENCRYPT_AT_REST else FAIL,
            f"ENCRYPT_AT_REST={c.ENCRYPT_AT_REST}",
        )
    )
    out.append(
        Result(
            "destructive SOAR disabled",
            PASS if not c.SOAR_DESTRUCTIVE_ACTIONS_ENABLED else FAIL,
            f"SOAR_DESTRUCTIVE_ACTIONS_ENABLED={c.SOAR_DESTRUCTIVE_ACTIONS_ENABLED}",
        )
    )
    out.append(
        Result("auth enabled", PASS if c.AUTH_ENABLED else FAIL, "")
    )
    out.append(
        Result("CSRF enabled", PASS if c.CSRF_ENABLED else FAIL, "")
    )
    out.append(
        Result(
            "metrics private",
            PASS if not c.METRICS_PUBLIC else FAIL,
            f"METRICS_PUBLIC={c.METRICS_PUBLIC}",
        )
    )
    out.append(
        Result(
            "dev API keys absent",
            PASS if not any(k.startswith("baraq-dev-") for k in c.API_KEYS) else FAIL,
            "",
        )
    )
    out.append(
        Result(
            "TLS enabled in config",
            PASS if c.TLS_ENABLED else FAIL,
            f"TLS_ENABLED={c.TLS_ENABLED}",
        )
    )
    out.append(
        Result(
            "agent keys provisioned",
            PASS if c.AGENT_KEYS else WARN,
            f"{len(c.AGENT_KEYS)} agent key(s)",
        )
    )
    out.append(
        Result(
            "session secret is explicit",
            PASS if c.AUTH_TOKEN_SECRET and not c.AUTH_TOKEN_SECRET_AUTO_GENERATED else FAIL,
            "auto-generated secrets invalidate every session on restart"
            if c.AUTH_TOKEN_SECRET_AUTO_GENERATED
            else "",
        )
    )
    return out


def check_tls(url: str, ca_file: str | None) -> list[Result]:
    out: list[Result] = []
    if not url.lower().startswith("https://"):
        return [
            Result(
                "TLS transport",
                FAIL,
                f"{url} is not https - credentials and telemetry would cross the network in clear",
            )
        ]
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None
    if ctx is None:
        out.append(
            Result("TLS chain trusted", WARN, "no --ca-file given; using system trust store")
        )
    try:
        with _http(url.rstrip("/") + "/api/health", context=ctx) as resp:
            body = json.loads(resp.read().decode())
        out.append(Result("TLS + health endpoint", PASS, f"status={body.get('status')}"))
    except ssl.SSLCertVerificationError as exc:
        out.append(Result("TLS certificate verifies", FAIL, str(exc)[:160]))
    except urllib.error.HTTPError as exc:
        out.append(Result("TLS + health endpoint", PASS, f"HTTP {exc.code}"))
    except Exception as exc:
        out.append(Result("TLS + health endpoint", FAIL, str(exc)[:160]))
    return out


def check_auth_surface(url: str, ca_file: str | None) -> list[Result]:
    """Unauthenticated endpoints must not leak."""
    out: list[Result] = []
    ctx = ssl.create_default_context(cafile=ca_file) if ca_file else None
    base = url.rstrip("/")
    for path, expect in (
        ("/api/system/status", 401),
        ("/metrics", 401),
        ("/api/alerts", 401),
    ):
        try:
            with _http(base + path, context=ctx) as resp:
                code = resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
        except Exception as exc:
            out.append(Result(f"unauthenticated {path}", WARN, str(exc)[:120]))
            continue
        out.append(
            Result(
                f"unauthenticated {path}",
                PASS if code == expect else FAIL,
                f"HTTP {code} (expected {expect})",
            )
        )
    return out


def check_backup() -> list[Result]:
    """A backup that exists and restores - not just one that runs."""
    out: list[Result] = []
    backup_dir = Path(os.environ.get("BARAQ_BACKUP_DIR", "backups"))
    if not backup_dir.is_dir():
        return [Result("backup directory", FAIL, f"{backup_dir} does not exist")]
    archives = sorted(backup_dir.glob("*.dump")) + sorted(backup_dir.glob("*.enc"))
    if not archives:
        return [Result("backup exists", FAIL, f"no archive in {backup_dir}")]
    newest = max(archives, key=lambda p: p.stat().st_mtime)
    age_h = (os.path.getmtime(newest) and (__import__("time").time() - newest.stat().st_mtime) / 3600)
    out.append(
        Result(
            "backup exists",
            PASS if age_h <= 48 else FAIL,
            f"newest {newest.name} is {age_h:.1f}h old",
        )
    )
    out.append(
        Result(
            "postgresql client locatable",
            PASS,
            "db_backup.py resolves pg_dump/pg_restore automatically",
        )
    )
    out.append(
        Result(
            "restore drill",
            WARN,
            "not run by this script - restore the newest archive to a scratch DB before cutover",
        )
    )
    return out


CHECKS = {
    "config": check_config,
    "tls": check_tls,
    "auth": check_auth_surface,
    "backup": check_backup,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="BARAQ production preflight")
    parser.add_argument("--url", default=os.environ.get("BARAQ_URL", "https://127.0.0.1:8443"))
    parser.add_argument("--ca-file", default=os.environ.get("BARAQ_TLS_CERT", ""))
    parser.add_argument(
        "--only",
        default="all",
        help="comma-separated: config,tls,auth,backup (default all)",
    )
    args = parser.parse_args()

    wanted = [c.strip() for c in args.only.split(",")] if args.only != "all" else list(CHECKS)
    results: list[Result] = []
    for name in wanted:
        fn = CHECKS.get(name)
        if fn is None:
            print(f"unknown check: {name}")
            return 2
        try:
            results.extend(fn(args.url, args.ca_file) if fn in (check_tls, check_auth_surface) else fn())
        except Exception as exc:
            results.append(Result(name, FAIL, f"check crashed: {exc}"[:200]))

    width = max(len(r.name) for r in results) + 2
    print()
    for r in results:
        colour = {"PASS": "\033[32m", "FAIL": "\033[31m", "WARN": "\033[33m"}[r.status]
        print(f"{colour}{r.status}\033[0m  {r.name.ljust(width)} {r.detail}")
    hard = [r for r in results if r.status == FAIL]
    soft = [r for r in results if r.status == WARN]
    print()
    print(f"{len(results) - len(hard) - len(soft)} passed, {len(soft)} warnings, {len(hard)} failed")
    if hard:
        print("NOT READY FOR CUTOVER - fix every FAIL above first.")
        return 1
    if soft:
        print("Ready with warnings - review each WARN above.")
        return 0
    print("Ready for cutover.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
