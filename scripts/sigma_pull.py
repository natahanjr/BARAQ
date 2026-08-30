# ===========================================================================
#  BARAQ - SigmaHQ rules puller
#
#  Downloads the community Sigma rule repository and extracts the requested
#  platform subdirectories into the local sigma_rules\ directory (default),
#  which the Sigma engine (backend/detection/sigma) loads on every cycle.
#
#  Usage:
#    python scripts\sigma_pull.py                  # windows rules (~2000)
#    python scripts\sigma_pull.py --subdirs windows,linux,cloud
#    python scripts\sigma_pull.py --subdirs all    # everything (~5000)
#    python scripts\sigma_pull.py --out C:\sigma-rules
#
#  Existing files are never overwritten, so local edits survive re-pulls.
#  No git or network tooling required - stdlib only.
# ===========================================================================
from __future__ import annotations

import argparse
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

SIGMA_URL = "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master"
SIGMA_SLUG = "sigma-master"

DEFAULT_SUBDIRS = ("windows",)
ALL_SUBDIRS = (
    "windows",
    "linux",
    "macos",
    "cloud",
    "network",
    "application",
    "web",
    "aws",
    "gcp",
    "azure",
)

RULES_REL = "rules"


def fetch_sigma_archive(url: str = SIGMA_URL) -> bytes:
    print(f"Downloading SigmaHQ rules from {url} ...")
    with urllib.request.urlopen(url, timeout=120) as resp:
        data = resp.read()
    print(f"  downloaded {len(data) / (1024 * 1024):.1f} MB")
    return data


def extract_subdirs(archive: bytes, subdirs: tuple[str, ...], out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    skipped = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        names = tar.getnames()
        root = next((n.split("/", 1)[0] for n in names if n and "/" in n), SIGMA_SLUG)
        wanted_roots = (
            {f"{root}/{RULES_REL}/{s}" for s in subdirs} if subdirs else set()
        )
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.replace("\\", "/")
            if not (name.endswith((".yml", ".yaml"))):
                continue
            if subdirs and not any(name.startswith(r + "/") for r in wanted_roots):
                continue
            rel = name.split("/", 2)[-1]
            target = out_dir / rel
            if target.exists():
                skipped += 1
                continue
            fh = tar.extractfile(member)
            if fh is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(fh.read())
            extracted += 1
    return extracted, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Download SigmaHQ rules for BARAQ")
    parser.add_argument(
        "--subdirs",
        default=",".join(DEFAULT_SUBDIRS),
        help="comma-separated rules subdirectories to pull "
        f"(one of: {', '.join(ALL_SUBDIRS)}; 'all' for everything)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: <repo>/sigma_rules)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be pulled without downloading",
    )
    args = parser.parse_args()

    out_dir = (
        Path(args.out)
        if args.out
        else Path(__file__).resolve().parent.parent / "sigma_rules"
    )

    if args.subdirs.strip().lower() == "all":
        subdirs = ALL_SUBDIRS
    else:
        subdirs = tuple(s.strip() for s in args.subdirs.split(",") if s.strip())
        unknown = [s for s in subdirs if s not in ALL_SUBDIRS]
        if unknown:
            print(f"Unknown subdirectory(ies): {', '.join(unknown)}", file=sys.stderr)
            print(f"Choose from: {', '.join(ALL_SUBDIRS)} or 'all'", file=sys.stderr)
            return 2

    print(f"Target: {out_dir}")
    print(f"Subdirectories: {', '.join(subdirs)}")

    if args.dry_run:
        print(
            "Dry run - nothing downloaded. Enable the Sigma engine by restarting BARAQ."
        )
        return 0

    archive = fetch_sigma_archive()
    extracted, skipped = extract_subdirs(archive, subdirs, out_dir)
    print(
        f"Extracted {extracted} rule file(s) to {out_dir} ({skipped} existing skipped)."
    )
    if extracted:
        sample = sorted(out_dir.rglob("*.yml"))[:3]
        for path in sample:
            print(f"  e.g. {path.relative_to(out_dir)}")
    print("Restart BARAQ - the Sigma engine will load the rules on the next cycle.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
