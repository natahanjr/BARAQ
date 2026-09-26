"""Prove the two paging channels BARAQ supports: email (SMTP) and Telegram.

Runs offline against local stubs so the delivery mechanism is verified without
real credentials:

* email  - a minimal in-process SMTP sink (no aiosmtpd/smtpd dependency) that
  accepts the message and records it.
* Telegram - the outbound HTTPS call is captured (the real api.telegram.org URL
  is unreachable in a test), so the request the bot would send is asserted.

Test-only helper. Real deployments just set the credentials in the environment.
"""
from __future__ import annotations

import json
import socket
import socketserver
import sys
import threading
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

RECEIVED: list[dict] = []


class _SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP to accept one message: EHLO/MAIL/RCPT/DATA/QUIT."""

    def handle(self) -> None:  # noqa: C901 - protocol, linear by nature
        self.wfile.write(b"220 localhost BARAQ test sink\r\n")
        sender = ""
        rcpts: list[str] = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode("utf-8", "replace").strip()
            upper = cmd.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self.wfile.write(b"250-localhost\r\n250 SIZE 10485760\r\n")
            elif upper.startswith("MAIL FROM"):
                sender = cmd.split(":", 1)[1].strip()
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("RCPT TO"):
                rcpts.append(cmd.split(":", 1)[1].strip())
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                buf = b""
                while True:
                    chunk = self.rfile.readline()
                    if not chunk or chunk.strip() == b".":
                        break
                    buf += chunk
                RECEIVED.append(
                    {
                        "from": sender,
                        "to": rcpts,
                        "raw": buf.decode("utf-8", "replace"),
                    }
                )
                self.wfile.write(b"250 OK: queued\r\n")
            elif upper.startswith("QUIT"):
                self.wfile.write(b"221 Bye\r\n")
                return
            elif upper.startswith("RSET"):
                sender, rcpts = "", []
                self.wfile.write(b"250 OK\r\n")
            else:
                self.wfile.write(b"250 OK\r\n")


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    # --- email: point BARAQ at the local sink BEFORE importing config ---
    server = _SMTPServer(("127.0.0.1", 0), _SMTPHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    import os

    os.environ["BARAQ_SMTP_HOST"] = "127.0.0.1"
    os.environ["BARAQ_SMTP_PORT"] = str(port)
    os.environ["BARAQ_SMTP_TO"] = "soc-team@example.com"
    os.environ["BARAQ_SMTP_FROM"] = "baraq-soc@example.com"
    os.environ["BARAQ_SMTP_STARTTLS"] = "0"  # the sink speaks plaintext
    os.environ["BARAQ_SMTP_USERNAME"] = ""
    os.environ["BARAQ_TELEGRAM_BOT_TOKEN"] = "test-token-not-real"
    os.environ["BARAQ_TELEGRAM_CHAT_ID"] = "-1001234567890"

    import backend.notify as notify

    notify.SMTP_HOST = "127.0.0.1"
    notify.SMTP_PORT = port
    notify.SMTP_TO = "soc-team@example.com"
    notify.SMTP_STARTTLS = False
    notify.SMTP_USERNAME = ""
    notify.TELEGRAM_BOT_TOKEN = "test-token-not-real"
    notify.TELEGRAM_CHAT_ID = "-1001234567890"

    # --- telegram: capture the HTTPS call instead of dialling the internet ---
    telegram_calls: list[dict] = []
    real_urlopen = notify.urllib.request.urlopen

    def fake_urlopen(req, *a, **kw):
        url = getattr(req, "full_url", str(req))
        if "api.telegram.org" in url:
            body = json.loads(req.data.decode()) if getattr(req, "data", None) else {}
            telegram_calls.append({"url": url, "body": body})
            return _FakeResponse()
        return real_urlopen(req, *a, **kw)

    notify.urllib.request.urlopen = fake_urlopen

    alert = {
        "id": 4242,
        "alert_id": 4242,
        "name": "Brute Force Attack",
        "severity": "critical",
        "mitre_id": "T1110",
        "mitre_tactic": "Credential Access",
        "risk_score": 92.0,
        "host": "HR-LAPTOP-01",
        "evidence": "12 failed logons for account 'administrator' from 192.168.99.77",
    }

    print("--- email (SMTP) ---")
    notify._send_email(alert)
    print("--- telegram ---")
    notify._send_telegram(alert)

    ok = True
    if not RECEIVED:
        print("FAIL: SMTP sink received nothing")
        ok = False
    else:
        msg = BytesParser(policy=default_policy).parsebytes(
            RECEIVED[0]["raw"].encode()
        )
        print(f"PASS: email delivered to {msg['to']}")
        print(f"      subject: {msg['subject']}")
        body = msg.get_body(preferencelist=("plain",)).get_content()
        assert "Brute Force Attack" in body, "alert name missing from email body"
        assert "192.168.99.77" in body, "evidence missing from email body"
        print("      body contains the alert name and the source IP")

    if not telegram_calls:
        print("FAIL: telegram send produced no request")
        ok = False
    else:
        call = telegram_calls[0]
        text = call["body"].get("text", "")
        assert call["body"].get("chat_id") == "-1001234567890"
        assert "CRITICAL" in text and "Brute Force Attack" in text
        # The real send is UTF-8 JSON; this only guards the console print,
        # which would choke on the siren emoji under cp1252.
        first_line = text.splitlines()[0].encode("ascii", "replace").decode()
        print(f"PASS: telegram request built for chat {call['body']['chat_id']}")
        print(f"      message: {first_line}")
    return 0 if ok else 1


class _FakeResponse:
    def read(self, *_a, **_k):
        return b'{"ok":true}'

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


if __name__ == "__main__":
    raise SystemExit(main())
