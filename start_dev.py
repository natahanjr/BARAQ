"""Start BARAQ with all feature flags enabled for development.

Also the container entrypoint (see Dockerfile CMD), so it must honour
BARAQ_TLS: a production deployment that sets BARAQ_TLS=1 passes the
config-level TLS gate, but if this script ignores it the server keeps serving
plaintext HTTP while the configuration (and the Secure cookie flag) claim
encryption. Fail closed instead.
"""
import argparse
import os
from pathlib import Path

os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_ALERTS_V2"] = "1"
os.environ["BARAQ_CORRELATION"] = "1"
os.environ["BARAQ_RISK"] = "1"
os.environ["BARAQ_BEHAVIOR_GROUPS"] = "1"
os.environ.setdefault("BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED", "1")
os.environ.setdefault("BARAQ_V2_ENGINES_ALLOW_PROD", "0")

import uvicorn

_APP_DIR = Path(__file__).resolve().parent


def _truthy(name: str) -> bool:
    return os.environ.get(name, "0").strip().lower() in ("1", "true", "yes", "on")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start BARAQ backend")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1, use 0.0.0.0 for LAN)")
    parser.add_argument("--port", type=int, default=8001, help="Bind port (default: 8001)")
    parser.add_argument("--ssl-certfile", default="", help="TLS certificate (PEM)")
    parser.add_argument("--ssl-keyfile", default="", help="TLS private key (PEM)")
    args = parser.parse_args()

    scheme = "http"
    ssl_kwargs = {}
    cert = args.ssl_certfile or os.environ.get("BARAQ_TLS_CERT", "").strip()
    key = args.ssl_keyfile or os.environ.get("BARAQ_TLS_KEY", "").strip()
    if cert:
        cert = str((_APP_DIR / cert).resolve()) if not Path(cert).is_absolute() else cert
    if key:
        key = str((_APP_DIR / key).resolve()) if not Path(key).is_absolute() else key

    if _truthy("BARAQ_TLS"):
        if not cert or not key:
            raise SystemExit(
                "BARAQ_TLS=1 but no certificate configured. Set BARAQ_TLS_CERT and "
                "BARAQ_TLS_KEY (or pass --ssl-certfile/--ssl-keyfile). Refusing to "
                "start: the config claims TLS, serving plaintext would silently "
                "downgrade every session."
            )
        for path, label in ((cert, "certificate"), (key, "private key")):
            if not Path(path).is_file():
                raise SystemExit(f"BARAQ_TLS=1 but the {label} does not exist: {path}")
        scheme = "https"
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}

    print(f"BARAQ backend starting on {scheme}://{args.host}:{args.port}")
    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        **ssl_kwargs,
    )
