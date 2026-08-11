"""Database backup / restore for BARAQ (PostgreSQL).

Usage::

    venv\\Scripts\\python scripts\\db_backup.py backup  [--dir DIR] [--keep N] [--encrypt]
    venv\\Scripts\\python scripts\\db_backup.py list    [--dir DIR]
    venv\\Scripts\\python scripts\\db_backup.py verify  <archive> [--dir DIR]
    venv\\Scripts\\python scripts\\db_backup.py restore <archive> [--yes] [--target DBURL]

Behaviour:
  * ``backup`` dumps the database configured in ``BARAQ_DATABASE_URL``
    with ``pg_dump`` (custom format, consistent snapshot). Every archive
    gets a SHA-256 manifest sidecar and the newest ``--keep`` archives are
    retained.
  * ``--encrypt`` wraps the archive with AES-256-GCM under the DPAPI vault
    master key (``backend.crypto``) so backups at rest stay confidential.
  * ``restore`` refuses to run unless ``--yes`` is passed (it replaces the
    contents of the target database) and validates archives with
    ``pg_restore --list`` first.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

#: Directories probed for embedded/portable PostgreSQL binaries (besides
#: ``BARAQ_PG_BIN`` and PATH). ``<project>/pg/bin`` is the portable bundle
#: produced by ``scripts/download_postgres.ps1``; ``%LOCALAPPDATA%`` is the
#: default home used by ``scripts/pg_setup.ps1``.
_PG_BIN_HINTS = [
    Path(__file__).resolve().parent.parent / "pg" / "bin",
    Path.home() / "AppData" / "Local" / "BARAQ" / "postgres" / "bin",
]

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "backups"


def dialect_of(url: str) -> str:
    return "postgres"


def find_pg_binary(tool: str) -> str:
    """Locate a PostgreSQL client binary: env hint, PATH, then known dirs."""
    import os

    hint = os.environ.get("BARAQ_PG_BIN", "").strip()
    candidates: list[Path] = []
    if hint:
        hint_dir = Path(hint)
        candidates.append(hint_dir if hint_dir.is_dir() else hint_dir.parent / tool)
        candidates.append(Path(hint) / (tool + ".exe"))
    for base in _PG_BIN_HINTS:
        candidates.append(base / (tool + ".exe"))
    for cand in candidates:
        if Path(cand).is_file():
            return str(Path(cand))
    which = shutil.which(tool)
    if which:
        return which
    raise RuntimeError(
        f"Could not locate {tool}.exe - set BARAQ_PG_BIN to the PostgreSQL "
        "bin directory or add it to PATH."
    )


def archive_base(dialect: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"baraq_{dialect}_{ts}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_path(archive: Path) -> Path:
    return archive.with_suffix(archive.suffix + ".sha256")


def write_manifest(archive: Path) -> None:
    manifest_path(archive).write_text(
        f"{sha256_file(archive)}  {archive.name}\n", encoding="utf-8"
    )


def verify_archive(archive: Path) -> bool:
    if not archive.exists():
        return False
    manifest = manifest_path(archive)
    if not manifest.exists():
        return False
    try:
        expected = manifest.read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        return False
    return sha256_file(archive) == expected


def iter_archives(backup_dir: Path):
    return sorted(
        (p for p in backup_dir.glob("baraq_*") if p.suffix != ".sha256"),
        key=lambda p: (p.stat().st_mtime, p.name),
        reverse=True,
    )


def prune_old(backup_dir: Path, keep: int) -> list[Path]:
    """Delete all but the newest ``keep`` archives (with their manifests)."""
    removed: list[Path] = []
    for archive in iter_archives(backup_dir)[keep:]:
        archive.unlink(missing_ok=True)
        manifest_path(archive).unlink(missing_ok=True)
        removed.append(archive)
    return removed


def pg_url_for_tools(url: str) -> str:
    """Strip SQLAlchemy driver suffixes for the native pg_* client tools."""
    return url.replace("postgresql+psycopg://", "postgresql://").replace(
        "postgresql+psycopg2://", "postgresql://"
    )


def run_or_die(cmd: list[str]) -> None:
    """Run a pg tool; print its stderr verbatim when it fails."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"Command failed ({proc.returncode}): {' '.join(cmd[:2])} ...\n"
            f"{proc.stderr.strip() or proc.stdout.strip() or 'no output'}"
        )


def backup_db(url: str, backup_dir: Path, *, keep: int = 10, encrypt: bool = False) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / (archive_base("postgres") + (".enc" if encrypt else ".dump"))

    pg_dump = find_pg_binary("pg_dump")
    plain = backup_dir / (archive_base("postgres") + ".dump")
    run_or_die(
        [
            pg_dump, "-Fc", "-Z", "9", "--no-owner",
            "--file", str(plain), pg_url_for_tools(url),
        ]
    )
    data = plain.read_bytes()
    plain.unlink(missing_ok=True)

    if encrypt:
        from backend.crypto import encrypt_file_bytes

        archive.write_bytes(encrypt_file_bytes(data))
    else:
        archive.write_bytes(data)
    write_manifest(archive)
    for p in prune_old(backup_dir, keep):
        print(f"  pruned old archive: {p.name}")
    print(f"  backup written: {archive.name} ({archive.stat().st_size:,} bytes)")
    return archive


def restore_db(url: str, archive: Path, *, yes: bool = False) -> None:
    if not verify_archive(archive):
        raise SystemExit(
            f"Archive verification failed: {archive.name} (missing or tampered). Aborting."
        )
    if not yes:
        raise SystemExit(
            "Refusing to restore without --yes. Stop the BARAQ service and "
            "run again with --yes to replace the target database contents."
        )

    if archive.suffix == ".enc":
        from backend.crypto import decrypt_file_bytes

        data = decrypt_file_bytes(archive.read_bytes())
        if data is None:
            raise SystemExit(
                "Could not decrypt archive (wrong vault key or tampered data)."
            )
        body_path = None
        with tempfile.NamedTemporaryFile(suffix=".dump", delete=False) as tf:
            tf.write(data)
            body_path = Path(tf.name)
    else:
        body_path = archive

    try:
        pg_restore = find_pg_binary("pg_restore")
        run_or_die(
            [
                pg_restore, "--clean", "--if-exists", "--no-owner",
                "--dbname", pg_url_for_tools(url), str(body_path),
            ]
        )
    finally:
        if body_path is not archive:
            body_path.unlink(missing_ok=True)
    print(f"  restored {archive.name} into {url}")


def list_backups(backup_dir: Path) -> None:
    raw = iter_archives(backup_dir)
    if not raw:
        print("  (no backups found)")
        return
    for p in raw:
        status = "verified" if verify_archive(p) else "MISMATCH"
        print(f"  {p.name}  {p.stat().st_size:>14,} B  {status}")
    print(f"  {len(raw)} backup(s) in {backup_dir}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BARAQ database backup/restore")
    sub = parser.add_subparsers(dest="command", required=True)

    p_bk = sub.add_parser("backup", help="Create a consistent database archive")
    p_bk.add_argument("--keep", type=int, default=10, help="archives to retain (default 10)")
    p_bk.add_argument("--encrypt", action="store_true", help="AES-GCM encrypt the archive")
    p_bk.add_argument("--dir", default=None, help="backup directory (default ./backups)")

    p_ls = sub.add_parser("list", help="List backups with verification status")
    p_ls.add_argument("--dir", default=None)

    p_vf = sub.add_parser("verify", help="Check an archive's SHA-256 manifest")
    p_vf.add_argument("archive")
    p_vf.add_argument("--dir", default=None)

    p_rs = sub.add_parser("restore", help="Restore an archive into the database")
    p_rs.add_argument("archive")
    p_rs.add_argument("--yes", action="store_true", help="confirm destructive restore")
    p_rs.add_argument("--target", default=None, help="override BARAQ_DATABASE_URL")
    p_rs.add_argument("--dir", default=None)

    args = parser.parse_args(argv)

    from backend.config import DATABASE_URL

    backup_dir = Path(args.dir) if args.dir else DEFAULT_DIR
    url = getattr(args, "target", None) or DATABASE_URL

    if args.command == "backup":
        backup_db(url, backup_dir, keep=args.keep, encrypt=args.encrypt)
    elif args.command == "list":
        list_backups(backup_dir)
    elif args.command == "verify":
        ok = verify_archive(backup_dir / args.archive)
        print(f"  {args.archive}: {'verified' if ok else 'MISMATCH/UNVERIFIED'}")
    elif args.command == "restore":
        restore_db(url, backup_dir / args.archive, yes=args.yes)
    return 0


if __name__ == "__main__":
    sys.exit(main())