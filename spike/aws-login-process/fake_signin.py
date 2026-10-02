#!/usr/bin/env python3
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
"""A stand-in for the AWS Sign-In service's CreateOAuth2Token (POST /v1/token,
rest-json), the call botocore's LoginCredentialFetcher makes to refresh an
`aws login` session. Rotates the refresh token on every call, as AWS does,
and logs each request (with whether it carried a DPoP header) to LOG."""
import json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(os.environ.get("PORT", "8790")); LOG = os.environ.get("LOG", "req.jsonl"); n = 0
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        global n; n += 1
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        ti = body.get("tokenInput", body)  # the model's payload member: the body IS the TokenInput
        with open(LOG, "a") as f:
            f.write(json.dumps({"n": n, "path": self.path, "grant": ti.get("grantType"),
                                "refreshToken": ti.get("refreshToken"), "dpop": bool(self.headers.get("DPoP"))}) + "\n")
        out = json.dumps({"accessToken": {"accessKeyId": f"ASIALOGIN{n:08d}", "secretAccessKey": f"s{n}",
                          "sessionToken": f"t{n}"}, "refreshToken": f"rt-rotated-{n}", "expiresIn": 900}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
