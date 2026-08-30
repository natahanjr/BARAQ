"""Vendor tool: generate BARAQ commercial license keys.

Usage (vendor only - never ship this tool or the private key):
    python scripts\\license_gen.py --generate-keypair
    python scripts\\license_gen.py --customer "Example University" --edition professional --seats 40 --expires 2027-08-13
    python scripts\\license_gen.py --customer "Lab X" --edition standard --seats 5 --expires 2026-12-31 --features "sigma,tls,reporting"

The private key defaults to licensing\\private_key.pem (gitignored). Set
BARAQ_LICENSE_PRIVATE_KEY to use another key. The matching public key must
be embedded in backend/config.py (LICENSE_PUBLIC_KEY) of the shipped build.
"""

from __future__ import annotations

import argparse
import base64
import sys
import uuid
from datetime import UTC, date, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.licensing import LicenseInfo, sign_license

DEFAULT_PRIVATE_KEY = ROOT / "licensing" / "private_key.pem"


def _load_private_key(path: Path) -> bytes:
    if not path.exists():
        raise SystemExit(
            f"Private key not found at {path}. Generate one first:\n"
            f"  python scripts\\license_gen.py --generate-keypair"
        )
    raw = path.read_text(encoding="utf-8").strip()
    return raw.encode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate BARAQ license keys")
    parser.add_argument("--customer", default="", help="customer/organisation name")
    parser.add_argument(
        "--edition", default="standard", choices=["trial", "standard", "professional"]
    )
    parser.add_argument("--seats", type=int, default=1, help="licensed endpoint seats")
    parser.add_argument(
        "--expires", default="", help="expiry date YYYY-MM-DD (default 1 year)"
    )
    parser.add_argument("--features", default="", help="comma-separated feature flags")
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        help="generate licensing/private_key.pem + public_key.pem",
    )
    parser.add_argument(
        "--private-key",
        default=str(DEFAULT_PRIVATE_KEY),
        help="path to the private key file",
    )
    args = parser.parse_args()

    if args.generate_keypair:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
        out_dir = Path(args.private_key).parent
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "private_key.pem").write_text(enc(key.private_bytes_raw()))
        (out_dir / "public_key.pem").write_text(
            enc(key.public_key().public_bytes_raw())
        )
        print(
            f"private key : {(out_dir / 'private_key.pem')}  (keep secret, never ship)"
        )
        print(f"public key  : {(out_dir / 'public_key.pem')}")
        print("Embed the public key value into backend/config.py LICENSE_PUBLIC_KEY.")
        return

    expires = (
        args.expires or (date.today().replace(year=date.today().year + 1)).isoformat()
    )
    issued = datetime.now(UTC).isoformat()
    info = LicenseInfo(
        license_id=str(uuid.uuid4()),
        customer=args.customer,
        edition=args.edition,
        seats=args.seats,
        issued_at=issued,
        expires_at=expires,
        features=[f.strip() for f in args.features.split(",") if f.strip()],
    )
    key = sign_license(info, _load_private_key(Path(args.private_key)))
    print(f"license_id : {info.license_id}")
    print(f"customer   : {args.customer or '(unnamed)'}")
    print(f"edition    : {args.edition}  seats: {args.seats}")
    print(f"issued     : {issued}")
    print(f"expires    : {expires}")
    print()
    print(key)
    print()
    print("Deliver this key to the customer; they activate it via")
    print("POST /api/system/license/activate (admin).")


if __name__ == "__main__":
    main()
