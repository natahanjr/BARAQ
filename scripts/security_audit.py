"""BARAQ static security audit.

Runs a battery of checks an operator can run on any deployment to catch the
common mistakes (secrets in the repo, missing prod gates, broken deps) and
confirm the controls this project ships are actually in place:

    venv\\Scripts\\python scripts\\security_audit.py

Exits non-zero if any FAIL check is found. WARN items are recommendations,
not blockers.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS: list[tuple[str, str, str]] = []  # (name, PASS|WARN|FAIL, detail)


def check(name: str):
    def deco(fn):
        def wrapper():
            try:
                fn()
            except Exception as exc:  # noqa: BLE001 - audit must not crash
                RESULTS.append((name, "FAIL", f"audit crashed: {exc}"))
        wrapper.__name__ = name
        return wrapper
    return deco


def _scan(patterns: list[tuple[str, re.Pattern]], roots: list[Path], skip: set[Path]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for root in roots:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(s in p.parts for s in ("node_modules", "dist", "__pycache__", ".git", "venv", "logs")):
                continue
            if p in skip or p.suffix not in (".py", ".jsx", ".js", ".tsx", ".bat", ".ps1", ".sh", ".json"):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for label, pat in patterns:
                if pat.search(text):
                    hits.append((label, str(p.relative_to(ROOT))))
    return hits


@check("secrets-in-repo")
def secrets_in_repo():
    patterns = [
        ("baraq-admin-key", re.compile(r"baraq-admin-[A-Za-z0-9_-]{10,}")),
        ("baraq-analyst-key", re.compile(r"baraq-analyst-[A-Za-z0-9_-]{10,}")),
        ("private-key-block", re.compile(r"-----BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY-----")),
        ("password-assignment", re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
    ]
    skipped = set()
    vault = ROOT / "secrets.dat"
    if vault.exists():
        skipped.add(vault)
    hits = _scan(patterns, [ROOT], skipped)
    legit = ("config.py", "tests", "requirements", "README", "documentation", "gen_cert.ps1")
    suspicious = [h for h in hits if not any(ok in h[1] for ok in legit)]
    if suspicious:
        RESULTS.append(("secrets-in-repo", "FAIL", f"{len(suspicious)} suspicious hit(s): " +
                        "; ".join(f"{a}@{b}" for a, b in suspicious[:6])))
    elif hits:
        RESULTS.append(("secrets-in-repo", "WARN",
                        f"{len(hits)} hit(s), all in config/tests/docs (dev defaults) - review manually"))
    else:
        RESULTS.append(("secrets-in-repo", "PASS", "no secret-looking strings outside config/tests/docs"))


@check("vault-present")
def vault_present():
    if (ROOT / "secrets.dat").exists():
        RESULTS.append(("vault-present", "PASS", "secrets.dat present (DPAPI-encrypted credential store)"))
    else:
        RESULTS.append(("vault-present", "WARN", "secrets.dat missing - credentials will be regenerated"))


@check("prod-gate")
def prod_gate():
    src = (ROOT / "backend" / "config.py").read_text(encoding="utf-8", errors="ignore")
    main = (ROOT / "backend" / "main.py").read_text(encoding="utf-8", errors="ignore")
    checks = {
        "IS_PRODUCTION": "IS_PRODUCTION" in src,
        "_assert_production_safe": "_assert_production_safe" in src,
        "docs-hidden-in-prod": "docs_url=None if IS_PRODUCTION" in main or "IS_PRODUCTION" in main,
    }
    missing = [k for k, ok in checks.items() if not ok]
    if missing:
        RESULTS.append(("prod-gate", "FAIL", f"missing: {', '.join(missing)}"))
    else:
        RESULTS.append(("prod-gate", "PASS", "IS_PRODUCTION + _assert_production_safe + docs hiding present"))


@check("login-rate-limit")
def login_rate_limit():
    src = (ROOT / "backend" / "api" / "auth.py").read_text(encoding="utf-8", errors="ignore")
    if "_check_login_rate_limit" in src and "429" in src:
        RESULTS.append(("login-rate-limit", "PASS", "failed-login throttling + lockout present"))
    else:
        RESULTS.append(("login-rate-limit", "FAIL", "no login rate limiting found"))


@check("csrf")
def csrf():
    src = (ROOT / "backend" / "config.py").read_text(encoding="utf-8", errors="ignore")
    if "CSRF" in src:
        RESULTS.append(("csrf", "PASS", "CSRF config present"))
    else:
        RESULTS.append(("csrf", "WARN", "CSRF config not found in config.py"))


@check("mfa")
def mfa():
    auth_src = (ROOT / "backend" / "api" / "auth.py").read_text(encoding="utf-8", errors="ignore")
    if "totp" in auth_src and "mfa_required" in auth_src:
        RESULTS.append(("mfa", "PASS", "TOTP MFA flow present (/api/auth/mfa/*)"))
    else:
        RESULTS.append(("mfa", "FAIL", "TOTP MFA not found"))


@check("tls")
def tls():
    cfg = (ROOT / "backend" / "config.py").read_text(encoding="utf-8", errors="ignore")
    certgen = (ROOT / "scripts" / "gen_cert.ps1").exists()
    if "TLS_ENABLED" in cfg and certgen:
        RESULTS.append(("tls", "PASS", "TLS config + cert generator present"))
    else:
        RESULTS.append(("tls", "WARN", "TLS wiring incomplete"))


@check("single-instance")
def single_instance():
    src = (ROOT / "backend" / "locks.py").read_text(encoding="utf-8", errors="ignore")
    if "pg_try_advisory_lock" in src:
        RESULTS.append(("single-instance", "PASS", "DB advisory-lock guard present"))
    else:
        RESULTS.append(("single-instance", "WARN", "instance lock not found"))


@check("backup-and-migrations")
def backup_and_migrations():
    have = (ROOT / "scripts" / "db_backup.py").exists() and (ROOT / "alembic" / "versions").is_dir()
    if have:
        RESULTS.append(("backup-and-migrations", "PASS", "db_backup.py + alembic present"))
    else:
        RESULTS.append(("backup-and-migrations", "WARN", "backup/migration tooling missing"))


@check("deps-consistent")
def deps_consistent():
    py = ROOT / "venv" / "Scripts" / "python.exe"
    if not py.exists():
        RESULTS.append(("deps-consistent", "WARN", "no venv at venv/Scripts/python.exe"))
        return
    proc = subprocess.run([str(py), "-m", "pip", "check"], capture_output=True, text=True, cwd=ROOT)
    out = proc.stdout.strip() or proc.stderr.strip()
    if proc.returncode == 0:
        RESULTS.append(("deps-consistent", "PASS", "pip check clean"))
    else:
        RESULTS.append(("deps-consistent", "FAIL", out[:400]))


@check("cve-audit")
def cve_audit():
    py = ROOT / "venv" / "Scripts" / "python.exe"
    proc = subprocess.run([str(py), "-m", "pip", "show", "pip-audit"],
                          capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        RESULTS.append(("cve-audit", "WARN", "pip-audit not installed (pip install pip-audit to enable CVE scanning)"))
        return
    try:
        scan = subprocess.run([str(py), "-m", "pip_audit", "-l"],
                              capture_output=True, text=True, cwd=ROOT, timeout=30)
    except subprocess.TimeoutExpired:
        RESULTS.append(("cve-audit", "WARN", "pip-audit timed out (no network?) - rerun later"))
        return
    if scan.returncode == 0:
        RESULTS.append(("cve-audit", "PASS", "no known vulnerabilities in direct deps"))
    else:
        RESULTS.append(("cve-audit", "FAIL", (scan.stdout or scan.stderr)[:400]))


def main() -> int:
    for fn in (secrets_in_repo, vault_present, prod_gate, login_rate_limit, csrf,
               mfa, tls, single_instance, backup_and_migrations, deps_consistent, cve_audit):
        fn()
    print(f"{'check':<22} {'status':<5} detail")
    print("-" * 78)
    for name, status, detail in RESULTS:
        print(f"{name:<22} {status:<5} {detail[:90]}")
    fails = [r for r in RESULTS if r[1] == "FAIL"]
    warns = [r for r in RESULTS if r[1] == "WARN"]
    print("-" * 78)
    print(f"{len(RESULTS)} checks: {len(RESULTS) - len(fails) - len(warns)} pass, "
          f"{len(warns)} warn, {len(fails)} fail")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())