#!/usr/bin/env python3
"""Simple webhook receiver that prints payloads to stdout."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, sys

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        event = self.headers.get('X-Dbward-Event', 'unknown')
        sig = self.headers.get('X-Dbward-Signature', '')
        print(f"\n{'='*60}", flush=True)
        print(f"EVENT: {event}", flush=True)
        if sig:
            print(f"SIGNATURE: {sig}", flush=True)
        try:
            print(json.dumps(json.loads(body), indent=2), flush=True)
        except:
            print(body, flush=True)
        print(f"{'='*60}", flush=True)
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args):
        pass  # suppress access logs

print("Webhook receiver listening on :9999", flush=True)
HTTPServer(('0.0.0.0', 9999), Handler).serve_forever()
