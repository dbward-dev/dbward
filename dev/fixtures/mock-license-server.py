#!/usr/bin/env python3
"""Mock license validation server for E2E testing.

Environment variables:
  MOCK_LICENSE_STATUS: active|expired|revoked|suspended|unknown (default: active)
  MOCK_GRACE_DAYS: grace period to return (default: 7)
  MOCK_CONTROL_PORT: port for runtime status changes (default: 8444)

Control API (POST /set-status):
  curl -X POST http://localhost:8444/set-status -d '{"status":"revoked"}'
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone, timedelta
import json
import os
import sys
import threading

CURRENT_STATUS = os.environ.get("MOCK_LICENSE_STATUS", "active")
GRACE_DAYS = int(os.environ.get("MOCK_GRACE_DAYS", "7"))
CONTROL_PORT = int(os.environ.get("MOCK_CONTROL_PORT", "8444"))
LOCK = threading.Lock()


def get_status():
    with LOCK:
        return CURRENT_STATUS


def set_status(s):
    global CURRENT_STATUS
    with LOCK:
        CURRENT_STATUS = s


class LicenseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/v1/validate":
            self.send_response(404)
            self.end_headers()
            return

        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"missing bearer token"}')
            return

        status = get_status()
        now = datetime.now(timezone.utc)

        if status == "active":
            validated_until = (now + timedelta(hours=24)).isoformat()
            body = {
                "status": "active",
                "plan": "pro",
                "validated_until": validated_until,
                "grace_days": GRACE_DAYS,
                "expires_at": (now + timedelta(days=365)).isoformat(),
            }
            self.send_response(200)
        elif status == "expired":
            body = {"status": "expired"}
            self.send_response(200)
        elif status == "suspended":
            body = {"status": "suspended"}
            self.send_response(403)
        elif status == "revoked":
            body = {"status": "revoked"}
            self.send_response(403)
        elif status == "unknown":
            self.send_response(404)
            self.end_headers()
            return
        else:
            body = {"status": status}
            self.send_response(200)

        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format, *args):
        print(f"[license-mock] {args[0]}", flush=True)


class ControlHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/set-status":
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length).decode())
            new_status = data.get("status", "active")
            set_status(new_status)
            print(f"[license-mock] Status changed to: {new_status}", flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": new_status}).encode())
        elif self.path == "/get-status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": get_status()}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == "/get-status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": get_status()}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def run_control_server():
    server = HTTPServer(("0.0.0.0", CONTROL_PORT), ControlHandler)
    server.serve_forever()


if __name__ == "__main__":
    print(f"[license-mock] Starting on :8443 (status={CURRENT_STATUS}, grace_days={GRACE_DAYS})", flush=True)
    print(f"[license-mock] Control API on :{CONTROL_PORT}", flush=True)

    control_thread = threading.Thread(target=run_control_server, daemon=True)
    control_thread.start()

    HTTPServer(("0.0.0.0", 8443), LicenseHandler).serve_forever()
