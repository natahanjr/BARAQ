"""Start BARAQ with all feature flags enabled for development."""
import argparse
import os

os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_ALERTS_V2"] = "1"
os.environ["BARAQ_CORRELATION"] = "1"
os.environ["BARAQ_RISK"] = "1"
os.environ["BARAQ_BEHAVIOR_GROUPS"] = "1"
os.environ["BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED"] = "1"
os.environ["BARAQ_V2_ENGINES_ALLOW_PROD"] = "1"

import uvicorn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start BARAQ backend")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1, use 0.0.0.0 for LAN)")
    parser.add_argument("--port", type=int, default=8001, help="Bind port (default: 8001)")
    args = parser.parse_args()

    print(f"BARAQ backend starting on {args.host}:{args.port}")
    uvicorn.run("backend.main:app", host=args.host, port=args.port, reload=False)
