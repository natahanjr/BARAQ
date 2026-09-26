"""Local webhook sink used to prove the BARAQ alert-delivery path.

Stands in for Slack / Teams / PagerDuty during testing: accepts the POST,
prints it, and records it to a file so delivery can be asserted rather than
eyeballed. Test-only helper - never point production at this.

    venv\\Scripts\\python scripts\\webhook_sink.py --port 8899 --out sink.jsonl
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    out_path: Path | None = None

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:
            payload = {"_raw": raw.decode("utf-8", "replace")}
        record = {
            "path": self.path,
            "received_at": self.log_date_time_string(),
            "content_type": self.headers.get("Content-Type", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "payload": payload,
        }
        line = json.dumps(record, default=str)
        print("WEBHOOK RECEIVED:", line[:400], flush=True)
        if type(self).out_path:
            with type(self).out_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"sink"}')

    def log_message(self, fmt: str, *args) -> None:  # quieter output
        pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    Handler.out_path = Path(args.out) if args.out else None
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"webhook sink listening on http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
