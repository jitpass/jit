#!/usr/bin/env python3
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
"""A stand-in for oauth2.googleapis.com/token, so the spike can watch what
gcloud writes on a SUCCESSFUL refresh without a real Google account.

gcloud is pointed at it with `auth/token_host` (creds.py honors the property
when it is explicitly set). Every grant is answered with a fresh fake access
token; with ROTATE=1 the response also carries a new refresh_token, the case
RFC 9700 4.14.2 warns about (lose the rotated one and the grant may be
revoked). Each request is appended to LOG as one JSON line.

  PORT=8765 LOG=requests.jsonl ROTATE=0 TTL=3600 python3 fake_token_server.py
"""
import json
import os
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8765"))
LOG = os.environ.get("LOG", "requests.jsonl")
ROTATE = os.environ.get("ROTATE", "0") == "1"
TTL = int(os.environ.get("TTL", "3600"))
counter = 0


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global counter
        counter += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        form = urllib.parse.parse_qs(body)
        grant = form.get("grant_type", ["?"])[0]
        rt = form.get("refresh_token", [""])[0]
        with open(LOG, "a") as f:
            f.write(json.dumps({"n": counter, "t": time.time(), "path": self.path,
                                "grant": grant, "refresh_token": rt}) + "\n")
        resp = {
            "access_token": f"ya29.FAKE-ACCESS-{counter}",
            "expires_in": TTL,
            "token_type": "Bearer",
            "scope": form.get("scope", ["https://www.googleapis.com/auth/cloud-platform"])[0],
        }
        if ROTATE:
            resp["refresh_token"] = f"1//FAKE-ROTATED-{counter}"
        out = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"fake token server on 127.0.0.1:{PORT} rotate={ROTATE}", file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
